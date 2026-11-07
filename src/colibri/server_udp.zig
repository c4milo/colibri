//! The UDP socket of a `colibri.Server` (design §8 step 37c): h3 over QUIC on the UDP port of the
//! same number as the TCP listener's, on the same Rotor loop. The socket itself is
//! `datagram_socket.zig`'s, which a `colibri.Client` shares. This file opens it on the listener's
//! port, and passes each datagram it reads to the engine.
const std = @import("std");
const assert = std.debug.assert;
const rotor = @import("rotor");
const server = @import("server");
const constants = @import("constants.zig");
const datagram_socket = @import("datagram_socket.zig");

/// Opens the UDP socket on the listener's address and port.
pub fn open(state: anytype) (datagram_socket.BindError || error{HostInvalid})!void {
    const address = try @import("server_loop.zig").address_of(state.config.host, state.bound_port);
    assert(address.port == state.bound_port);
    try state.udp.bind(&address);
}

/// Opens the UDP socket when the server serves h3: `quic_slots` and an identity. RFC 9114 §3.1:
/// h3 runs over QUIC, which needs TLS (RFC 9001 §4). A TCP connection over TLS then advertises h3
/// on the same port (RFC 7838 §3), unless the program named another alternative.
pub fn open_when_served(state: anytype, quic_slots: bool) !void {
    assert(!state.udp.open);
    if (!quic_slots or state.config.identity == null) return;
    try open(state);
    if (state.engine_config.h3_alternative == null) state.engine_config.h3_alternative = .{ .port = state.bound_port };
}

/// Hands an event of the UDP socket to it. A server that is shutting down starts no receive.
pub fn on_event(run: anytype, event: rotor.Event, now_ns: u64) void {
    const state = run.server;
    state.udp.on_event(&state.loop, event, !state.shut_down, run, take, now_ns);
}

/// Passes a datagram to the engine, then routes every event it reports until it reports none.
/// `server_udp_test.zig` calls it through `datagram_socket.take_delivery`.
pub fn take(run: anytype, received: datagram_socket.Received, now_ns: u64) void {
    const state = run.server;
    state.now_ns = now_ns;
    var rest: server.Input = .{ .datagram = .{ .bytes = received.bytes, .ecn = received.ecn, .from = received.from } };
    for (0..constants.limits.events_per_step_max) |_| {
        const reported = state.engine.receive(rest, now_ns).event orelse return;
        rest = .none;
        @import("server_pump.zig").route(run, reported);
    }
}
