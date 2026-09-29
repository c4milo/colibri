//! The client's part of `udp_run.zig`: the hq-interop or h3 client, its one key update, and the
//! second connection of a resumption (RFC 9846 §2.2). A client holds one connection at a time.
//!
//! With `resumption` the first connection fetches the first path and keeps the ticket its server
//! issues. Once it closes, a second connection presents the ticket and fetches the rest. chapulin
//! fails the second handshake closed when the server declines the ticket, so a second connection
//! that finishes resumed the first one's session.
const std = @import("std");
const assert = std.debug.assert;
const tls = @import("tls");
const quic = @import("quic");
const constants = @import("../../constants.zig");
const hq_client = @import("../hq/hq_client.zig");
const h3_client = @import("../h3/h3_client.zig");
const h3 = @import("h3");
const udp_arguments = @import("udp_arguments.zig");
const udp_identity = @import("udp_identity.zig");
const udp_run = @import("udp_run.zig");

const Connection = udp_run.Connection;
const Parameters = quic.transport_parameters.Parameters;
const StreamProvider = quic.stream.stream_provider.StreamProvider;

var client: hq_client.Client align(@alignOf(hq_client.Client)) = undefined;
var h3_side: h3_client.Client align(@alignOf(h3_client.Client)) = undefined;
/// Whether the run fetches over h3, which the `h3` option asks for.
var over_h3: bool = false;
/// Whether the one key update has started.
var keys_updated: bool = false;
/// The ticket the first connection's server issued, and the instant it arrived.
var ticket: ?tls.Ticket align(@alignOf(?tls.Ticket)) = null;
var ticket_received_ns: ?u64 = null;
/// Whether the connection in use presented the ticket.
var resuming: bool = false;
/// What the first connection fetched, once the second has started.
var fetched_before: usize = 0;
var received_before: u64 = 0;

/// Starts the first connection, which fetches every path, or with `resumption` the first alone.
pub fn connect(connection: *Connection, asked: udp_arguments.Client, now_ns: u64) void {
    const paths = if (asked.resumption) asked.paths[0..1] else asked.paths;
    start(connection, asked, paths, null, now_ns);
}

fn start(
    connection: *Connection,
    asked: udp_arguments.Client,
    paths: []const []const u8,
    resumption: ?tls.Resumption,
    now_ns: u64,
) void {
    const how = udp_identity.client_start(asked, resumption);
    connection.peer.init(how, udp_identity.keylog(), udp_identity.client_ids(), parameters(), now_ns, asked.address, true, asked.qlogdir) catch |failure|
        udp_run.fail("the client did not start: {t}", .{failure});
    connection.outbound = udp_run.outbound_to(asked.address);
    connection.spare_ids_issued = false;
    over_h3 = asked.h3;
    if (over_h3) {
        h3_side.init(asked.downloads, paths, asked.hostname, udp_identity.grease(), connection.peer.connection.qlog.log);
    } else {
        client.init(asked.downloads, paths);
    }
    connection.live = true;
}

/// Takes the first ticket the server sent, which chapulin keeps in the session until it is taken,
/// and notes the instant it arrived: its age on the second connection counts from there (RFC 9846
/// §4.3.11.1).
pub fn on_received(connection: *Connection, now_ns: u64) void {
    if (ticket != null or resuming) return;
    ticket = connection.peer.session.client.take_ticket() orelse return;
    ticket_received_ns = now_ns;
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

/// Reads and requests on the connection's streams, and ends the connection once every file has
/// arrived: hq-interop with NO_ERROR, and h3 with H3_NO_ERROR (RFC 9114 §5.2).
pub fn step(connection: *Connection, now_ns: u64) void {
    const held = &connection.peer.connection;
    if (over_h3) {
        h3_side.step(held, now_ns) catch |failure| udp_run.fail("the h3 client failed: {t}", .{failure});
        if (h3_side.is_done()) connection.peer.close(h3.constants.error_no_error);
        return;
    }
    client.step(held) catch |failure| udp_run.fail("the client's streams failed: {t}", .{failure});
    if (client.is_done()) connection.peer.close(0);
}

pub fn provider() StreamProvider {
    return if (over_h3) h3_side.provider() else client.provider();
}

/// Whether every path the connection in use fetches has arrived.
fn is_done() bool {
    return if (over_h3) h3_side.is_done() else client.is_done();
}

fn finished_count() usize {
    return if (over_h3) h3_side.finished_count else client.finished_count;
}

fn received_len() u64 {
    return if (over_h3) h3_side.received_len else client.received_len;
}

/// Whether the run is over: the connection's close has gone out (RFC 9000 §10.2 lets a client
/// stop there) and no second connection is owed. The first connection of a resumption that
/// fetched its path starts the second instead.
pub fn finished(connection: *Connection, asked: udp_arguments.Client, now_ns: u64) bool {
    if (connection.peer.connection.termination.state == .active) return false;
    if (!asked.resumption or resuming or !is_done()) return true;
    resume_session(connection, asked, now_ns);
    return false;
}

/// Starts the second connection, presenting the first one's ticket. chapulin drops a ticket whose
/// identity is longer than it keeps, so a server that sent one sent none this client holds.
fn resume_session(connection: *Connection, asked: udp_arguments.Client, now_ns: u64) void {
    const kept = if (ticket) |*held| held else udp_run.fail("the server issued no ticket this client keeps", .{});
    fetched_before = finished_count();
    received_before = received_len();
    resuming = true;
    const age = age_ms(ticket_received_ns.?, now_ns);
    // The first connection has ended, and the second has an original destination ID of its own.
    connection.peer.qlog.close();
    start(connection, asked, asked.paths[1..], .{ .ticket = kept, .age_ms = age }, now_ns);
}

/// RFC 9846 §4.3.11.1: a ticket's age is the time since it was received, in milliseconds, which
/// chapulin adds `ticket_age_add` to.
fn age_ms(received_ns: u64, now_ns: u64) u64 {
    assert(now_ns >= received_ns);
    return (now_ns - received_ns) / constants.nanoseconds_per_millisecond;
}

pub fn report(connection: *Connection, asked: udp_arguments.Client) void {
    std.debug.print("quic-udp: fetched {d} of {d} files, {d} octets, alpn={s} suite=0x{x:0>4} version=0x{x:0>8}\n", .{
        fetched_before + finished_count(),
        asked.paths.len,
        received_before + received_len(),
        connection.peer.session.provider().negotiated_alpn() orelse "none",
        suite_ran(connection),
        // RFC 9369 §4.1: the negotiated version, which the connection's packets carried.
        @intFromEnum(connection.peer.connection.versions.negotiated),
    });
    // A connection that ended before every file arrived, by a timeout or the server's close, is a
    // failed run.
    if (!is_done()) udp_run.fail("the connection ended with files missing", .{});
    if (resuming) std.debug.print("quic-udp: the second connection resumed the first one's session\n", .{});
}

/// The suite the connection ran, as an RFC 9846 Appendix B.4 codepoint. A client of an object
/// without AES-GCM offers ChaCha20 alone and records no suite (chapulin's `suite`), so none
/// recorded means that one.
fn suite_ran(connection: *Connection) u16 {
    const recorded = connection.peer.session.client.session.suite() orelse return udp_identity.chacha20;
    return @intFromEnum(recorded);
}

/// What the client grants: its receive pool, for the answers on the streams it opens, and h3's
/// unidirectional streams (RFC 9114 §6.2), which an hq-interop server never opens.
fn parameters() Parameters {
    var held = Parameters.initial();
    held.initial_max_data = quic.constants.receive_pool_len_default;
    held.initial_max_stream_data_bidi_local = quic.constants.receive_pool_len_default;
    held.initial_max_stream_data_uni = constants.h3_stream_window;
    held.initial_max_streams_uni = h3.constants.uni_streams_max;
    held.max_idle_timeout_ms = constants.quic_idle_timeout_ms;
    return held;
}

const testing = std.testing;

test "RFC 9846 §4.3.11.1: a ticket's age is the whole milliseconds since it arrived" {
    const received_ns: u64 = 5 * constants.nanoseconds_per_second;
    const now_ns = received_ns + 1_500 * constants.nanoseconds_per_millisecond + 999_999;
    try testing.expectEqual(1_500, age_ms(received_ns, now_ns));
    try testing.expectEqual(0, age_ms(received_ns, received_ns));
}
