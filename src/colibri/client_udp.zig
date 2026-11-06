//! The UDP socket of a `colibri.Client` (design §8 step 42): h3 over QUIC, on `datagram_socket.zig`'s
//! socket, which a `colibri.Server` shares. Every QUIC connection of the pool sends from the one
//! socket, which `init` opened on a port the system chose. This file starts the QUIC connection the
//! pool asks for, and passes each datagram the socket reads to the pool.
const std = @import("std");
const assert = std.debug.assert;
const rotor = @import("rotor");
const client = @import("client");
const constants = @import("constants.zig");
const datagram_socket = @import("datagram_socket.zig");
const client_loop = @import("client_loop.zig");

comptime {
    // A server's datagrams and a client's carry one address type and one codepoint type, so one
    // socket serves both (decisions 68 and 72).
    assert(@FieldType(client.Datagram, "from") == datagram_socket.PeerAddress);
    assert(@FieldType(client.Datagram, "ecn") == datagram_socket.ReceivedEcn);
}

/// Starts the QUIC connection the pool's `open` asked for. The pool draws the connection's IDs
/// (RFC 9000 §7.2) and h3's grease value (RFC 9114 §7.2.4.1) from the client's source (decision
/// 120). A start the TLS stack refuses is the pool's to report: it ends the attempt, and TCP opens.
pub fn start(state: anytype, now_ns: u64) void {
    // A client with no QUIC holds no receive pool, and its pool asks for no QUIC connection.
    if (comptime @TypeOf(state.receive_pool) == void) {
        unreachable;
    } else {
        assert(state.udp.open);
        state.pool.start_quic(state.config.random.?, client_loop.unix_seconds(state, now_ns), now_ns, null) catch {};
    }
}

/// Hands an event of the UDP socket to it. The receive goes on until the run's end cancels it: a
/// pool that has closed drops each datagram it is given.
pub fn on_event(run: anytype, event: rotor.Event, now_ns: u64) void {
    const state = run.client;
    state.udp.on_event(&state.loop, event, true, run, take, now_ns);
}

/// Passes a datagram to the pool, then does what each event it reports asks, until it reports none.
/// The pool takes a datagram whole, and may first report an event it owes, with the datagram
/// left. The turn's drain reads the events the pool reports after it.
fn take(run: anytype, received: datagram_socket.Received, now_ns: u64) void {
    var input: client.Input = .{ .datagram = .{ .bytes = received.bytes, .ecn = received.ecn, .from = received.from } };
    for (0..constants.limits.events_per_step_max) |_| {
        const result = run.client.pool.receive(input, now_ns);
        if (result.consumed > 0) input = .none;
        client_loop.handle(run, result.event orelse return, now_ns);
    }
}
