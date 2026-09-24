//! The loop of design §9's UDP QUIC endpoints (design §8 step 9e, piece 11): one Rotor socket, a
//! table of connections, and the hq-interop server or client on top.
//!
//! Each turn waits in Rotor's `tick` until a datagram arrives or a connection's next deadline
//! passes, then reads the instant that tick read (decision 63). It hands each datagram to the
//! connection its Destination Connection ID names (RFC 9000 §5.2), in Rotor's own buffer, which
//! the suite opens in place. Then every live connection fires its deadlines, lets hq-interop read
//! and answer, and sends what colibri owes. A sent datagram's octets belong to Rotor until its
//! send's event (Rotor's rule 3), so each is built in a slot of its own, and a datagram Rotor has
//! no room for is one lost on the way, which RFC 9002 recovers.
//!
//! A server holds as many connections as its `connections=<n>` option asks, up to
//! `quic_connections_max`, so a client that opens many at once is served, and one whose close was
//! lost does not turn the next client away while it waits out its idle timeout. A client holds
//! one.
const std = @import("std");
const quic = @import("quic");
const constants = @import("../../constants.zig");
const udp = @import("../../udp.zig");
const check_file = @import("../../tls/check_file.zig");
const chapulin_quic_c = @import("../chapulin_quic_c.zig");
const udp_peer = @import("udp_peer.zig");
const udp_arguments = @import("udp_arguments.zig");
const udp_identity = @import("udp_identity.zig");
const hq_server = @import("../hq/hq_server.zig");
const hq_client = @import("../hq/hq_client.zig");

const Parameters = quic.transport_parameters.Parameters;
const StreamProvider = quic.stream.stream_provider.StreamProvider;

/// One connection, and what the endpoint keeps beside it.
const Connection = struct {
    live: bool,
    peer: udp_peer.Peer,
    /// A server's hq-interop state for this connection.
    server: hq_server.Server,
    /// chapulin's buffer for this connection's handshake messages.
    receive: [constants.tls_receive_len]u8,
    /// Where this connection's datagrams go, which is where its client sent from.
    outbound: udp.Outbound,
    /// Whether the spare connection IDs have been issued (`issue_spare_ids`).
    spare_ids_issued: bool,
};

var memory: udp.Memory = undefined;
var socket: udp.Endpoint = undefined;
/// Sized for the most a server may hold, because `src/` has no heap (CLAUDE.md non-negotiable 4).
/// `table` is the part in use.
var connections: [constants.quic_connections_max]Connection = undefined;
var client: hq_client.Client = undefined;
var arguments: udp_arguments.Arguments = undefined;
var slots: [constants.udp_send_slots][constants.quic_datagram_len_max]u8 = undefined;
var slot_busy: [constants.udp_send_slots]bool = @splat(false);
/// Where each slot's datagram goes, which its send reads until its event (Rotor's rule 3).
var slot_outbound: [constants.udp_send_slots]udp.Outbound = undefined;
var events: [constants.udp_operations_max]udp.Event = undefined;
/// Whether a connection ended on a connection error, which fails the run.
var connection_failed: bool = false;
/// Files the server answered, over every connection it has ended.
var served: u64 = 0;

/// The address a client binds: any address of its server's family, with a port the kernel picks.
fn any_address(family: udp.Address.Family) udp.Address {
    return switch (family) {
        .ipv4 => udp.Address.ipv4(@splat(0), 0),
        .ipv6 => udp.Address.ipv6(@splat(0), 0, 0),
    };
}

pub fn main(init: std.process.Init.Minimal) !void {
    if (!chapulin_quic_c.available) {
        std.debug.print("quic-udp: built without chapulin; pass -Dchapulin-quic=<checkout>\n", .{});
        std.process.exit(check_file.exit_usage);
    }
    arguments = udp_arguments.parse(init);
    try udp_identity.seed();
    for (&connections) |*connection| connection.live = false;
    const bind = switch (arguments) {
        .server => |asked| asked.address,
        .client => |asked| any_address(asked.address.family),
    };
    try socket.open(&memory, bind);
    // Decision 63: this first tick reads the clock whose instant every turn then passes on.
    _ = try socket.tick(&events, 0);
    switch (arguments) {
        // A script starts its client once this line is out.
        .server => std.debug.print("quic-udp: listening on port {d}\n", .{(try socket.local_address()).port}),
        .client => connect(),
    }
    run();
    if (connection_failed) fail("a connection ended on a connection error", .{});
    // Rotor makes a send's system call on a later tick, so the client's CONNECTION_CLOSE leaves
    // only once the loop has had every send's final event, which closing the socket waits for.
    socket.close() catch |failure| fail("the socket did not close: {t}", .{failure});
    report();
}

fn connect() void {
    const asked = arguments.client;
    const connection = &connections[0];
    const options = udp_identity.client_options(asked, &connection.receive) catch |failure|
        fail("cannot read the trust anchor: {t}", .{failure});
    connection.peer.init(options, udp_identity.client_ids(), client_parameters(), socket.now_ns(), asked.address) catch |failure|
        fail("the client did not start: {t}", .{failure});
    connection.outbound = outbound_to(asked.address);
    connection.spare_ids_issued = false;
    client.init(asked.downloads, asked.paths);
    connection.live = true;
}

/// Turns until the run is over, or the ticks run out.
fn run() void {
    for (0..constants.quic_run_ticks_max) |_| {
        const ready = socket.tick(&events, wait_ns()) catch |failure| fail("the tick failed: {t}", .{failure});
        const now_ns = socket.now_ns();
        for (ready) |event| on_event(event, now_ns);
        for (table()) |*connection| {
            if (connection.live) turn(connection, now_ns);
        }
        if (finished()) return;
    }
    fail("ran out of ticks", .{});
}

/// One connection's part of a turn: its deadlines, its streams, and what it owes.
fn turn(connection: *Connection, now_ns: u64) void {
    connection.peer.on_instant(now_ns) catch |failure| fail("a deadline failed: {t}", .{failure});
    if (arguments == .client and arguments.client.key_update) update_keys_once(connection, now_ns);
    step_application(connection);
    flush(connection, now_ns);
    // A client's stack derives its last secrets while it writes its Finished, inside `send`.
    udp_identity.write_keylog();
}

/// Whether the client's one key update has started.
var keys_updated: bool = false;

/// Starts the client's one key update once RFC 9001 §6.1 permits it: the handshake confirmed, and
/// a packet of the current key phase acknowledged. Until then each turn asks again.
fn update_keys_once(connection: *Connection, now_ns: u64) void {
    if (keys_updated) return;
    const suite = connection.peer.session.suite();
    quic.connection_key_update.initiate(&connection.peer.connection, suite, now_ns) catch |failure| switch (failure) {
        error.HandshakeNotConfirmed, error.PhaseNotAcknowledged, error.PhaseNotSettled => return,
        else => fail("the key update failed: {t}", .{failure}),
    };
    keys_updated = true;
}

/// How long the next tick may wait: until the soonest deadline of a live connection, and never
/// longer than `quic_tick_wait_ns_max`.
fn wait_ns() u64 {
    const now_ns = socket.now_ns();
    var wait = constants.quic_tick_wait_ns_max;
    for (table()) |*connection| {
        if (!connection.live) continue;
        const deadline_ns = connection.peer.deadline_ns() orelse continue;
        wait = @min(wait, deadline_ns -| now_ns);
    }
    return wait;
}

fn on_event(event: udp.Event, now_ns: u64) void {
    if (event.user_data != udp.receive_user_data) {
        // A send's event gives its slot back.
        slot_busy[@intCast(event.user_data)] = false;
        return;
    }
    if (event.flags.buffer) on_datagram(socket.delivery(event), now_ns);
    socket.finish_receive(event);
}

fn on_datagram(delivery: udp.Delivery, now_ns: u64) void {
    if (arguments == .server and answer_version(delivery)) return;
    const connection = connection_for(delivery.bytes) orelse accept(delivery, now_ns) orelse return;
    const ecn = udp_peer.received_ecn(&delivery.from);
    const received = connection.peer.receive(delivery.bytes, ecn, delivery.from.peer, now_ns) catch |failure| {
        close_on(connection, failure);
        udp_identity.write_keylog();
        return;
    };
    // Decision 72: the client's address changed and colibri followed it, so it owes PATH_CHALLENGE
    // frames whose data is drawn here.
    if (received.migrated) quic.connection_migration.challenge(&connection.peer.connection, udp_identity.challenge_data());
    issue_spare_ids(connection);
    // The step may have derived secrets. They go out now, because a server's connections step
    // through their handshakes together and the log holds one step's lines, not a run's.
    udp_identity.write_keylog();
}

/// Issues spare connection IDs once the handshake is confirmed, as many as the peer's
/// active_connection_id_limit allows beside the one in use (RFC 9000 §5.1.1). A peer whose
/// address changes then has one it has not used to send on the new path: §9.3 says an endpoint
/// with none "will not be able to send anything on the new path until the peer provides one",
/// and §9.5 lets it wait for one rather than reuse the old.
fn issue_spare_ids(connection: *Connection) void {
    if (connection.spare_ids_issued) return;
    const held = &connection.peer.connection;
    if (!held.handshake_confirmed) return;
    const peer = held.peer_parameters orelse return;
    connection.spare_ids_issued = true;
    const limit = @min(peer.active_connection_id_limit, quic.constants.connection_ids_max);
    // Bounded by `connection_ids_max`, a named limit.
    for (1..limit) |_| {
        var id: [udp_identity.id_len]u8 = undefined;
        var token: [quic.constants.stateless_reset_token_len]u8 = undefined;
        udp_identity.spare_id(&id, &token);
        _ = quic.connection_id_frames.issue(held, &id, &token) catch return;
    }
}

/// The entries in use: as many as the server's `connections=<n>` option asks, or a client's one.
fn table() []Connection {
    return switch (arguments) {
        .server => |asked| connections[0..asked.connections],
        .client => connections[0..1],
    };
}

/// The live connection a datagram belongs to. RFC 9000 §5.2 matches it by its Destination
/// Connection ID and not by the sender's address: a client that reuses a port for its next
/// connection sends from the address of the last. A client's one connection takes every
/// datagram, because it sends to one server.
fn connection_for(datagram: []const u8) ?*Connection {
    if (arguments == .client) return if (connections[0].live) &connections[0] else null;
    const dcid = udp_peer.destination_of(datagram, udp_identity.id_len) orelse return null;
    for (table()) |*connection| {
        if (connection.live and connection.peer.connection.addressed_by(dcid)) return connection;
    }
    return null;
}

/// A connection error colibri found (RFC 9000 §11): the connection closes with the error's code,
/// so the peer learns why, and the run is marked failed.
fn close_on(connection: *Connection, failure: udp_peer.Error) void {
    std.debug.print("quic-udp: the connection failed: {t}\n", .{failure});
    // RFC 9000 §11: an endpoint with no more specific code sends INTERNAL_ERROR.
    const code = if (quic.connection_frames.member_of(quic.connection_datagram.Error, failure)) |held|
        quic.connection_datagram.connection_error_code(&connection.peer.connection, held)
    else
        quic.error_code.internal_error;
    quic.connection_close.owe(&connection.peer.connection, quic.connection_close.transport(code, null));
    connection_failed = true;
}

/// Starts a connection for a client's first Initial packet (RFC 9000 §7.2) in a free entry, and
/// answers null for any other datagram, or when every entry is taken. A server asked for `retry`
/// first answers with a Retry, and starts a connection only for an Initial that returns its token
/// (RFC 9000 §8.1.2).
fn accept(delivery: udp.Delivery, now_ns: u64) ?*Connection {
    if (arguments != .server) return null;
    const long = udp_peer.first_initial(delivery.bytes, udp_identity.id_len) orelse return null;
    if (!arguments.server.retry) return start(delivery, now_ns, udp_identity.server_ids(long.dcid, long.scid));
    // RFC 9000 §14.1: "A server MUST discard an Initial packet that is carried in a UDP datagram
    // with a payload that is smaller than the smallest allowed maximum datagram size".
    if (delivery.bytes.len < quic.constants.datagram_len_min) return null;
    var address_storage: [udp_peer.token_address_len_max]u8 = undefined;
    const address = udp_peer.token_address(delivery.from.peer, &address_storage);
    switch (quic.connection_retry.verify_token(udp_identity.retry_suite(), address, long.token, long.dcid, now_ns)) {
        .absent => send_retry(delivery, long, address, now_ns),
        // RFC 9000 §8.1.2: the server "can discard such a packet and allow the client to time
        // out". Closing with INVALID_TOKEN would need Initial keys for a connection it refused.
        .invalid => std.debug.print("quic-udp: an Initial returned an invalid Retry token\n", .{}),
        .validated => |ids| return start(delivery, now_ns, udp_identity.server_ids_after_retry(&ids, long.scid)),
    }
    return null;
}

/// Answers a client's first Initial with a Retry (RFC 9000 §17.2.5.1), from a free slot. With no
/// slot free the Initial goes unanswered, and the client sends it again.
fn send_retry(delivery: udp.Delivery, long: quic.packet.header.Long, address: []const u8, now_ns: u64) void {
    const index = free_slot() orelse return;
    var pseudo: [quic.constants.retry_pseudo_packet_len_max]u8 = undefined;
    const answered = quic.connection_retry.answer(udp_identity.retry_suite(), .{
        .client_source = long.scid,
        .original_destination = long.dcid,
        .server_source = udp_identity.retry_id(),
        .address = address,
        .now_ns = now_ns,
    }, &pseudo, &slots[index]);
    switch (answered) {
        .written => |len| send_from(index, slots[index][0..len], outbound_to(delivery.from.peer)),
        .refused => |why| std.debug.print("quic-udp: no Retry: {t}\n", .{why}),
    }
}

fn free_slot() ?usize {
    for (slot_busy, 0..) |busy, index| {
        if (!busy) return index;
    }
    return null;
}

/// A connection in a free entry, for a client whose first Initial the server accepted.
fn start(delivery: udp.Delivery, now_ns: u64, identity: udp_peer.Identity) ?*Connection {
    const connection = free_connection() orelse return null;
    const asked = arguments.server;
    const options = udp_identity.server_options(asked, &connection.receive) catch |failure|
        fail("cannot read the identity: {t}", .{failure});
    connection.peer.init(options, identity, server_parameters(), now_ns, delivery.from.peer) catch |failure|
        fail("the server did not start: {t}", .{failure});
    connection.outbound = outbound_to(delivery.from.peer);
    connection.spare_ids_issued = false;
    connection.server.init(asked.www);
    connection.live = true;
    return connection;
}

/// A free entry, or when every entry is taken the one idle longest. A connection whose peer's
/// close was lost lingers until its idle timeout (RFC 9000 §10.1), and one that has heard nothing
/// for longest is that one: giving it up is what lets the next client in.
fn free_connection() ?*Connection {
    var idlest: ?*Connection = null;
    for (table()) |*connection| {
        if (!connection.live) return connection;
        const since_ns = connection.peer.connection.termination.idle_since_ns;
        if (idlest == null or since_ns < idlest.?.peer.connection.termination.idle_since_ns) idlest = connection;
    }
    const evicted = idlest orelse return null;
    served += evicted.server.served;
    evicted.live = false;
    return evicted;
}

fn step_application(connection: *Connection) void {
    const held = &connection.peer.connection;
    switch (arguments) {
        .server => connection.server.step(held) catch |failure| fail("the server's streams failed: {t}", .{failure}),
        .client => {
            client.step(held) catch |failure| fail("the client's streams failed: {t}", .{failure});
            // hq-interop ends the connection with NO_ERROR once every file has arrived.
            if (client.is_done()) connection.peer.close();
        },
    }
}

/// Sends every datagram `connection` owes now, each from a free slot.
fn flush(connection: *Connection, now_ns: u64) void {
    const provider = stream_provider(connection);
    for (&slots, 0..) |*slot, index| {
        if (slot_busy[index]) continue;
        const outgoing = (connection.peer.send(provider, slot, now_ns) catch |failure|
            fail("the send failed: {t}", .{failure})) orelse return;
        send_from(index, outgoing.octets, addressed(connection.outbound, outgoing));
    }
}

/// `to`, sent to the address colibri named (decision 72) and asking rotor to set the codepoint it
/// named (decision 68). A datagram left Not-ECT asks for nothing, and the socket sends it
/// unmarked.
fn addressed(to: udp.Outbound, outgoing: udp_peer.Outgoing) udp.Outbound {
    var held = to;
    held.peer = outgoing.to;
    held.ecn = outgoing.ecn;
    held.flags.ecn = outgoing.ecn != .not_ect;
    return held;
}

/// Hands one slot's datagram to Rotor, bound for `to`.
fn send_from(index: usize, datagram: []const u8, to: udp.Outbound) void {
    slot_outbound[index] = to;
    if (socket.send(index, datagram, &slot_outbound[index])) slot_busy[index] = true;
}

/// Answers a datagram asking for a version this server does not speak (RFC 9000 §6.1), and
/// answers true when it did. The QUIC Interop Runner's simulator sends one to learn the server
/// is listening.
fn answer_version(delivery: udp.Delivery) bool {
    for (&slots, 0..) |*slot, index| {
        if (slot_busy[index]) continue;
        const answer = udp_peer.version_negotiation(delivery.bytes, slot) orelse return false;
        send_from(index, answer, outbound_to(delivery.from.peer));
        return true;
    }
    return false;
}

fn stream_provider(connection: *Connection) StreamProvider {
    return switch (arguments) {
        .server => connection.server.provider(),
        .client => client.provider(),
    };
}

/// Whether the run is over. A client is done once its close has gone out (RFC 9000 §10.2 lets it
/// stop there). A server frees each connection that ends, and with `once`, or after a connection
/// error, stops at the first.
fn finished() bool {
    switch (arguments) {
        .client => return connections[0].peer.connection.termination.state != .active,
        .server => |asked| {
            var ended = false;
            for (table()) |*connection| {
                if (!connection.live or !connection.peer.is_closed()) continue;
                connection.live = false;
                served += connection.server.served;
                ended = true;
            }
            if (!ended) return false;
            return asked.once or connection_failed;
        },
    }
}

fn outbound_to(address: udp.Address) udp.Outbound {
    return .{ .peer = address, .local = undefined, .segment_bytes = 0, .ecn = .not_ect, .flags = .{ .peer = true } };
}

fn report() void {
    switch (arguments) {
        .server => std.debug.print("quic-udp: served {d} files\n", .{served}),
        .client => {
            std.debug.print("quic-udp: fetched {d} of {d} files, {d} octets, alpn={s}\n", .{
                client.finished_count,
                client.paths.len,
                client.received_len,
                connections[0].peer.session.provider().negotiated_alpn() orelse "none",
            });
            // A connection that ended before every file arrived, by a timeout or the server's
            // close, is a failed run.
            if (!client.is_done()) fail("the connection ended with files missing", .{});
        },
    }
}

/// What the server grants (RFC 9000 §18.2): a request line per stream, `hq_requests_max`
/// streams at once, and a connection window as large as its receive pool (decision 61).
fn server_parameters() Parameters {
    var held = Parameters.initial();
    held.initial_max_data = quic.constants.receive_pool_len_default;
    held.initial_max_stream_data_bidi_remote = constants.hq_request_len_max;
    held.initial_max_streams_bidi = constants.hq_requests_max;
    held.max_idle_timeout_ms = constants.quic_idle_timeout_ms;
    return held;
}

/// What the client grants: its receive pool, for the answers on the streams it opens.
fn client_parameters() Parameters {
    var held = Parameters.initial();
    held.initial_max_data = quic.constants.receive_pool_len_default;
    held.initial_max_stream_data_bidi_local = quic.constants.receive_pool_len_default;
    held.max_idle_timeout_ms = constants.quic_idle_timeout_ms;
    return held;
}

pub fn fail(comptime format: []const u8, values: anytype) noreturn {
    std.debug.print("quic-udp: " ++ format ++ "\n", values);
    std.process.exit(check_file.exit_failed);
}
