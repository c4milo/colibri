//! The client's part of `udp_run.zig`: the hq-interop client, its one key update, and the second
//! connection of a resumption (RFC 9846 §2.2). A client holds one connection at a time.
//!
//! With `resumption` the first connection fetches the first path and keeps the ticket its server
//! issues. Once it closes, a second connection presents the ticket and fetches the rest. chapulin
//! fails the second handshake closed when the server declines the ticket, so a second connection
//! that finishes resumed the first one's session.
const std = @import("std");
const assert = std.debug.assert;
const quic = @import("quic");
const constants = @import("../../constants.zig");
const chapulin_quic = @import("../chapulin_quic.zig");
const hq_client = @import("../hq/hq_client.zig");
const udp_arguments = @import("udp_arguments.zig");
const udp_identity = @import("udp_identity.zig");
const udp_run = @import("udp_run.zig");

const Connection = udp_run.Connection;
const Parameters = quic.transport_parameters.Parameters;
const StreamProvider = quic.stream.stream_provider.StreamProvider;

var client: hq_client.Client = undefined;
/// Whether the one key update has started.
var keys_updated: bool = false;
/// The ticket the first connection's server issued, and the instant it arrived.
var ticket: chapulin_quic.Ticket = .{};
var ticket_received_ns: ?u64 = null;
/// Whether the connection in use presented the ticket.
var resuming: bool = false;
/// What the first connection fetched, once the second has started.
var fetched_before: usize = 0;
var received_before: u64 = 0;

/// Starts the first connection, which fetches every path, or with `resumption` the first alone.
pub fn connect(connection: *Connection, asked: udp_arguments.Client, now_ns: u64) void {
    const paths = if (asked.resumption) asked.paths[0..1] else asked.paths;
    start(connection, asked, paths, &ticket, null, now_ns);
}

fn start(
    connection: *Connection,
    asked: udp_arguments.Client,
    paths: []const []const u8,
    ticket_store: ?*chapulin_quic.Ticket,
    resumption: ?chapulin_quic.Resumption,
    now_ns: u64,
) void {
    const options = udp_identity.client_options(asked, &connection.receive, ticket_store, resumption) catch |failure|
        udp_run.fail("cannot read the trust anchor: {t}", .{failure});
    connection.peer.init(options, udp_identity.client_ids(), parameters(), now_ns, asked.address) catch |failure|
        udp_run.fail("the client did not start: {t}", .{failure});
    connection.outbound = udp_run.outbound_to(asked.address);
    connection.spare_ids_issued = false;
    client.init(asked.downloads, paths);
    connection.live = true;
}

/// Notes the instant a ticket arrived, which its age on the second connection counts from
/// (RFC 9846 §4.2.11). chapulin hands it over inside a receive.
pub fn on_received(now_ns: u64) void {
    if (ticket.held and ticket_received_ns == null) ticket_received_ns = now_ns;
}

/// Starts the client's one key update once RFC 9001 §6.1 permits it: the handshake confirmed, and
/// a packet of the current key phase acknowledged. Until then each turn asks again.
pub fn update_keys_once(connection: *Connection, now_ns: u64) void {
    if (keys_updated) return;
    const suite = connection.peer.session.suite();
    quic.connection_key_update.initiate(&connection.peer.connection, suite, now_ns) catch |failure| switch (failure) {
        error.HandshakeNotConfirmed, error.PhaseNotAcknowledged, error.PhaseNotSettled => return,
        else => udp_run.fail("the key update failed: {t}", .{failure}),
    };
    keys_updated = true;
}

/// Reads and requests on the connection's streams. hq-interop ends the connection with NO_ERROR
/// once every file has arrived.
pub fn step(connection: *Connection) void {
    client.step(&connection.peer.connection) catch |failure| udp_run.fail("the client's streams failed: {t}", .{failure});
    if (client.is_done()) connection.peer.close();
}

pub fn provider() StreamProvider {
    return client.provider();
}

/// Whether the run is over: the connection's close has gone out (RFC 9000 §10.2 lets a client
/// stop there) and no second connection is owed. The first connection of a resumption that
/// fetched its path starts the second instead.
pub fn finished(connection: *Connection, asked: udp_arguments.Client, now_ns: u64) bool {
    if (connection.peer.connection.termination.state == .active) return false;
    if (!asked.resumption or resuming or !client.is_done()) return true;
    resume_session(connection, asked, now_ns);
    return false;
}

/// Starts the second connection, presenting the first one's ticket.
fn resume_session(connection: *Connection, asked: udp_arguments.Client, now_ns: u64) void {
    if (ticket.too_long) udp_run.fail("the server's ticket is longer than {d} octets", .{ticket.identity.len});
    if (!ticket.held) udp_run.fail("the server issued no ticket", .{});
    fetched_before = client.finished_count;
    received_before = client.received_len;
    resuming = true;
    const age = obfuscated_age(ticket_received_ns.?, now_ns, ticket.age_add);
    // The second connection keeps no ticket: the one it presents stays where chapulin reads it.
    start(connection, asked, asked.paths[1..], null, .{ .ticket = &ticket, .obfuscated_age = age }, now_ns);
}

/// RFC 9846 §4.2.11: the age of a ticket received at `received_ns`, in milliseconds, "added to
/// the ticket_age_add value that was included with the ticket ... modulo 2^32".
fn obfuscated_age(received_ns: u64, now_ns: u64, age_add: u32) u32 {
    assert(now_ns >= received_ns);
    const age_ms = (now_ns - received_ns) / constants.nanoseconds_per_millisecond;
    return @truncate(age_ms +% age_add);
}

pub fn report(connection: *Connection, asked: udp_arguments.Client) void {
    std.debug.print("quic-udp: fetched {d} of {d} files, {d} octets, alpn={s}\n", .{
        fetched_before + client.finished_count,
        asked.paths.len,
        received_before + client.received_len,
        connection.peer.session.provider().negotiated_alpn() orelse "none",
    });
    // A connection that ended before every file arrived, by a timeout or the server's close, is a
    // failed run.
    if (!client.is_done()) udp_run.fail("the connection ended with files missing", .{});
    if (resuming) std.debug.print("quic-udp: the second connection resumed the first one's session\n", .{});
}

/// What the client grants: its receive pool, for the answers on the streams it opens.
fn parameters() Parameters {
    var held = Parameters.initial();
    held.initial_max_data = quic.constants.receive_pool_len_default;
    held.initial_max_stream_data_bidi_local = quic.constants.receive_pool_len_default;
    held.max_idle_timeout_ms = constants.quic_idle_timeout_ms;
    return held;
}

const testing = std.testing;

test "RFC 9846 §4.2.11: the obfuscated age is the age in milliseconds plus age_add, modulo 2^32" {
    const received_ns: u64 = 5 * constants.nanoseconds_per_second;
    const now_ns = received_ns + 1_500 * constants.nanoseconds_per_millisecond + 999_999;
    try testing.expectEqual(1_500 + 7, obfuscated_age(received_ns, now_ns, 7));
    try testing.expectEqual(1_499, obfuscated_age(received_ns, now_ns, std.math.maxInt(u32)));
    try testing.expectEqual(7, obfuscated_age(received_ns, received_ns, 7));
}
