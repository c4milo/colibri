//! The UDP socket of a `colibri.Server` (design §8 step 37c): h3 over QUIC on the UDP port of the
//! same number as the TCP listener's. The socket itself is `datagram_socket.zig`'s, which a
//! `colibri.Client` shares. This file decides whether the server serves h3, and passes each
//! datagram the host read to the engine.
const std = @import("std");
const assert = std.debug.assert;
const server = @import("server");
const constants = @import("constants.zig");
const datagram_socket = @import("datagram_socket.zig");
const host = @import("host.zig");

/// Whether the server serves h3: `quic_slots` and an identity. RFC 9114 §3.1: h3 runs over QUIC,
/// which needs TLS (RFC 9001 §4).
pub fn served(state: anytype, quic_slots: bool) bool {
    return quic_slots and state.config.identity != null;
}

/// Records that the host opened the UDP socket on the listener's port. A TCP connection over TLS
/// then advertises h3 on the same port (RFC 7838 §3), unless the program named another
/// alternative.
pub fn opened(state: anytype, port: u16) void {
    assert(!state.udp.served);
    state.udp.served = true;
    if (state.engine_config.h3_alternative == null) state.engine_config.h3_alternative = .{ .port = port };
}

/// Hands a completion of the UDP socket to it.
pub fn complete(run: anytype, slot: u32, completion: *const host.Completion, now_ns: u64) void {
    run.server.udp.complete(slot, completion, run, take, now_ns);
}

/// Passes a datagram to the engine, then routes every event it reports until it reports none.
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
