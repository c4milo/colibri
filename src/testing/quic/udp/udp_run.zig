//! The loop of design §9's UDP QUIC endpoints (design §8 step 9e, piece 11): one Rotor socket,
//! one connection at a time, and the hq-interop server or client on top.
//!
//! Each turn waits in Rotor's `tick` until a datagram arrives or the connection's next deadline
//! passes, then reads the instant that tick read (decision 63). It hands each datagram to colibri
//! in Rotor's own buffer, which the suite opens in place, fires the deadlines, lets hq-interop
//! read and answer, and sends every datagram colibri owes. A sent datagram's octets belong to
//! Rotor until its send's event (Rotor's rule 3), so each is built in a slot of its own, and a
//! datagram Rotor has no room for is one lost on the way, which RFC 9002 recovers.
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

var memory: udp.Memory = undefined;
var socket: udp.Endpoint = undefined;
var peer: udp_peer.Peer = undefined;
/// Whether `peer` holds a connection.
var peer_live: bool = false;
var server: hq_server.Server = undefined;
var client: hq_client.Client = undefined;
var arguments: udp_arguments.Arguments = undefined;
var slots: [constants.udp_send_slots][constants.quic_datagram_len_max]u8 = undefined;
var slot_busy: [constants.udp_send_slots]bool = @splat(false);
/// Where every datagram goes. Each send reads it until its event, so it outlives them all.
var outbound: udp.Outbound = undefined;
var events: [constants.udp_operations_max]udp.Event = undefined;

/// The address a client binds: any, with a port the kernel picks.
const any_address: [udp_arguments.ipv4_octets]u8 = @splat(0);

pub fn main(init: std.process.Init.Minimal) !void {
    if (!chapulin_quic_c.available) {
        std.debug.print("quic-udp: built without chapulin; pass -Dchapulin-quic=<checkout>\n", .{});
        std.process.exit(check_file.exit_usage);
    }
    arguments = udp_arguments.parse(init);
    try udp_identity.seed();
    const bind = switch (arguments) {
        .server => |asked| udp.Address.ipv4(asked.address, asked.port),
        .client => udp.Address.ipv4(any_address, 0),
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
    // Rotor makes a send's system call on a later tick, so the client's CONNECTION_CLOSE leaves
    // only once the loop has had every send's final event, which closing the socket waits for.
    socket.close() catch |failure| fail("the socket did not close: {t}", .{failure});
    report();
    udp_identity.write_keylog();
}

fn connect() void {
    const asked = arguments.client;
    const options = udp_identity.client_options(asked) catch |failure| fail("cannot read the trust anchor: {t}", .{failure});
    peer.init(options, udp_identity.client_ids(), client_parameters(), socket.now_ns()) catch |failure|
        fail("the client did not start: {t}", .{failure});
    outbound = outbound_to(udp.Address.ipv4(asked.address, asked.port));
    client.init(asked.downloads, asked.paths);
    peer_live = true;
}

/// Turns until the run is over, or the ticks run out.
fn run() void {
    for (0..constants.quic_run_ticks_max) |_| {
        const ready = socket.tick(&events, wait_ns()) catch |failure| fail("the tick failed: {t}", .{failure});
        const now_ns = socket.now_ns();
        for (ready) |event| on_event(event, now_ns);
        if (!peer_live) continue;
        peer.on_instant(now_ns) catch |failure| fail("a deadline failed: {t}", .{failure});
        step_application();
        flush(now_ns);
        if (finished()) return;
    }
    fail("ran out of ticks", .{});
}

/// How long the next tick may wait: until the connection's next deadline, and never longer than
/// `quic_tick_wait_ns_max`.
fn wait_ns() u64 {
    if (!peer_live) return constants.quic_tick_wait_ns_max;
    const deadline_ns = peer.deadline_ns() orelse return constants.quic_tick_wait_ns_max;
    const now_ns = socket.now_ns();
    if (deadline_ns <= now_ns) return 0;
    return @min(deadline_ns - now_ns, constants.quic_tick_wait_ns_max);
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
    if (!peer_live) {
        if (arguments != .server) return;
        if (!accept(delivery, now_ns)) return;
    }
    _ = peer.receive(delivery.bytes, now_ns) catch |failure| fail("the connection failed: {t}", .{failure});
}

/// Starts a connection for a client's first Initial packet (RFC 9000 §7.2), and answers false for
/// any other datagram, which no connection this endpoint holds can read.
fn accept(delivery: udp.Delivery, now_ns: u64) bool {
    const long = udp_peer.first_initial(delivery.bytes, udp_identity.id_len) orelse return false;
    const asked = arguments.server;
    const options = udp_identity.server_options(asked) catch |failure| fail("cannot read the identity: {t}", .{failure});
    peer.init(options, udp_identity.server_ids(long.dcid, long.scid), server_parameters(), now_ns) catch |failure|
        fail("the server did not start: {t}", .{failure});
    outbound = outbound_to(delivery.from.peer);
    server.init(asked.www);
    peer_live = true;
    return true;
}

fn step_application() void {
    switch (arguments) {
        .server => server.step(&peer.connection) catch |failure| fail("the server's streams failed: {t}", .{failure}),
        .client => {
            client.step(&peer.connection) catch |failure| fail("the client's streams failed: {t}", .{failure});
            // hq-interop ends the connection with NO_ERROR once every file has arrived.
            if (client.is_done()) peer.close();
        },
    }
}

/// Sends every datagram colibri owes now, each from a free slot.
fn flush(now_ns: u64) void {
    const provider = stream_provider();
    for (&slots, 0..) |*slot, index| {
        if (slot_busy[index]) continue;
        const datagram = (peer.send(provider, slot, now_ns) catch |failure| fail("the send failed: {t}", .{failure})) orelse return;
        if (socket.send(index, datagram, &outbound)) slot_busy[index] = true;
    }
}

fn stream_provider() StreamProvider {
    return switch (arguments) {
        .server => server.provider(),
        .client => client.provider(),
    };
}

/// Whether the run is over. A client is done once its close has gone out (RFC 9000 §10.2 lets it
/// stop there). A server frees its connection when it ends, and with `once` stops.
fn finished() bool {
    switch (arguments) {
        .client => return peer.connection.termination.state != .active,
        .server => |asked| {
            if (!peer.is_closed()) return false;
            peer_live = false;
            return asked.once;
        },
    }
}

fn outbound_to(address: udp.Address) udp.Outbound {
    return .{ .peer = address, .local = undefined, .segment_bytes = 0, .ecn = .not_ect, .flags = .{ .peer = true } };
}

fn report() void {
    switch (arguments) {
        .server => std.debug.print("quic-udp: served {d} files\n", .{server.served}),
        .client => {
            std.debug.print("quic-udp: fetched {d} of {d} files, {d} octets, alpn={s}\n", .{
                client.finished_count,
                client.paths.len,
                client.received_len,
                peer.session.provider().negotiated_alpn() orelse "none",
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
