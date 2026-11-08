//! The driver of a `colibri.Client` (design §8 step 42, decision 159). It does no I/O, reads no
//! clock and imports no Rotor: the host does each operation and calls `turn` and `complete`
//! (`rotor_host.zig` for `.private`). Each turn:
//! 1. passes a `shutdown` to the pool once;
//! 2. fires the pool's deadlines, and reads the pool's events;
//! 3. steps each TCP socket a completion named (`client_tcp.zig`);
//! 4. writes what each socket needs next, cancels each connect past its deadline, and writes the
//!    datagrams the pool owes.
//!
//! The pool's events go to the program's handler: `on_finished` for each exchange that ends, and
//! `on_connected`, when the handler declares it, for the connection that takes the exchanges.
//!
//! A client's `SocketId`s are its TCP sockets from 0, then its UDP socket of each family. Its
//! operation table holds each TCP socket's slots, then the UDP socket's.
const std = @import("std");
const assert = std.debug.assert;
const client = @import("client");
const host = @import("host.zig");
const operation_table = @import("operation_table.zig");
const datagram_socket = @import("datagram_socket.zig");
const socket_module = @import("socket.zig");
const client_tcp = @import("client_tcp.zig");

/// The slots of the operation table of a client with `tcp_connections` sockets, and a UDP socket
/// when `quic` is set.
pub fn slot_count(tcp_connections: usize, quic: bool) u32 {
    return datagram_slot(tcp_connections) + if (quic) datagram_socket.slots else 0;
}

/// The first slot of the UDP socket, after every TCP socket's.
pub fn datagram_slot(tcp_connections: usize) u32 {
    return @intCast(tcp_connections * socket_module.slots_per_socket);
}

/// The id of the UDP socket of `family`: IPv4's after every TCP socket's, then IPv6's. The client
/// sends from the one of its destination's family (decision 156 ruling 13).
pub fn datagram_id(tcp_connections: usize, family: Family) host.SocketId {
    return @enumFromInt(tcp_connections + @intFromEnum(family));
}

/// The two families of a UDP socket.
pub const Family = enum(u1) { ipv4, ipv6 };

/// The octets of an IPv4 address (RFC 791 §3.1).
const ipv4_len = @sizeOf(u32);

/// The family of `address`: 4 octets are IPv4, and 16 are IPv6.
pub fn family_of(address: client.Address) Family {
    return if (address.len == ipv4_len) .ipv4 else .ipv6;
}

/// The size of the host's table of sockets: the TCP sockets, and a UDP socket for each family.
pub fn sockets_max(tcp_connections: usize) u16 {
    return @intCast(tcp_connections + @typeInfo(Family).@"enum".fields.len);
}

/// The operations a client holds in flight at most: for each TCP socket a receive, a send and a
/// close, or its connect alone, and the UDP socket's receive and sends.
pub fn operations_max(tcp_connections: usize, quic: bool) u32 {
    return @intCast(tcp_connections * socket_module.operations_per_socket + if (quic) datagram_socket.operations else 0);
}

/// Runs the client `state` names on the calling thread until its pool reports `closed`, every
/// socket has closed, and each operation had its final completion (`Client.run`). The UDP socket
/// closes last.
pub fn run_loop(state: anytype) !void {
    // The pool reports `closed` once, so a second run would wait for it without end.
    assert(!state.ran);
    state.ran = true;
    defer state.host.close_open();
    const now_ns = try state.host.begin();
    defer state.host.end();
    start(state, now_ns);
    try state.host.run(state, @This(), state);
}

/// Starts a run at `now_ns`, the instant `unix_seconds` counts from, with the UDP socket's receive
/// owed.
pub fn start(state: anytype, now_ns: u64) void {
    assert(!state.started);
    reset(state, now_ns);
    state.started = true;
    if (state.udp.served) state.udp.start(state.udp.socket, datagram_slot(state.sockets.len), state.datagram_segments);
}

/// Empties what a run holds: no socket, pending step or operation.
pub fn reset(state: anytype, now_ns: u64) void {
    for (&state.sockets) |*socket| socket.live = false;
    state.connections = @splat(client_tcp.Connection.empty);
    state.pending = .initEmpty();
    state.touched = .initEmpty();
    state.operations = .empty;
    // A request made before `run` waits for the first drain, which the first turn makes at once.
    state.undrained = true;
    state.shut_down = false;
    state.closed = false;
    state.started_ns = now_ns;
}

/// The seconds since 1970 at `now_ns`: the program's instant at the start of `run`, and the time
/// the run has lasted since. chapulin judges a chain's dates at it (RFC 5280 §4.1.2.5).
pub fn unix_seconds(state: anytype, now_ns: u64) u64 {
    return state.unix_seconds + (now_ns -| state.started_ns) / client.constants.nanoseconds_per_second;
}

/// One turn at `now_ns`. See the header. A hosted client's first turn is the instant that
/// `unix_seconds` counts from, because its `init` takes no instant.
pub fn turn(run: anytype, now_ns: u64, operations: []host.Operation) host.Turn {
    const state = run;
    host.enter(&state.in_turn, "turn()");
    defer state.in_turn = false;
    if (!state.started) start(state, now_ns);
    var out: operation_table.Outbox = .{ .operations = operations };
    pass_shutdown(state);
    const due = if (state.pool.deadline_ns()) |at_ns| at_ns <= now_ns else false;
    if (due) state.pool.on_instant(now_ns);
    drain(run, now_ns);
    client_tcp.serve(run, now_ns);
    client_tcp.arm(state, &out, now_ns);
    client_tcp.cancel_late(state, &out, now_ns);
    if (state.udp.served) state.udp.write(&out, &state.operations, !state.closed, &state.pool, now_ns);
    return .{ .operations = out.len, .wait = wait(state, out.full) };
}

/// When the host calls `turn` next: at once while work is left, at the soonest of the pool's
/// deadline and each connect's, or when a completion arrives.
pub fn wait(state: anytype, full: bool) host.Wait {
    if (full or state.undrained or state.pending.count() > 0) return .now;
    const pool_ns = state.pool.deadline_ns();
    const connect_ns = client_tcp.next_deadline(state);
    if (pool_ns == null and connect_ns == null) return .none;
    return .{ .at_ns = @min(pool_ns orelse std.math.maxInt(u64), connect_ns orelse std.math.maxInt(u64)) };
}

/// Takes one completion at `now_ns`. A completion with an id that the client does not hold is a
/// halt (decision 159, rule 6).
pub fn complete(run: anytype, completion: *const host.Completion, now_ns: u64) void {
    const state = run;
    host.enter(&state.in_turn, "complete()");
    defer state.in_turn = false;
    const slot = state.operations.held(completion.id);
    if (completion.final()) state.operations.finish(slot);
    if (state.udp.served and state.udp.owns(slot)) return @import("client_udp.zig").complete(run, slot, completion, now_ns);
    const index = slot / socket_module.slots_per_socket;
    const kind: socket_module.Kind = @enumFromInt(slot % socket_module.slots_per_socket);
    client_tcp.complete(run, index, kind, completion.result, now_ns);
}

/// Passes a `shutdown` to the pool once. A connection the shutdown ends owes its last octets, such
/// as h2's GOAWAY (RFC 9113 §6.8). The turn steps each running socket, because of a bug of the
/// pool: after `shutdown`, an idle h2 connection never sends its GOAWAY. Its last `send_stream`
/// wrote nothing and set `send_blocked`, and `shutdown` does not clear it, so the pool reports no
/// `send` event. The fix belongs in `src/client/pool/`, which design §8 step 39 changes.
pub fn pass_shutdown(state: anytype) void {
    if (!state.stopping.load(.acquire) or state.shut_down) return;
    state.shut_down = true;
    state.pool.shutdown();
    state.undrained = true;
    for (state.connections, 0..) |connection, slot| {
        if (connection.started) state.pending.set(slot);
    }
}

/// Reads the pool's events until it reports none, and does what each asks. The reads are bounded
/// by `receive_events_without_input_max` of the pool's counts, and one more read that reports no
/// event. A handler that calls `request` starts a new count, so a drain that reaches the bound
/// leaves the rest for the next turn, which then waits for nothing.
pub fn drain(run: anytype, now_ns: u64) void {
    const state = run;
    const Pool = @TypeOf(state.pool);
    const reads_max = Pool.receive_events_without_input_max(state.pool.counts) + 1;
    for (0..reads_max) |_| {
        const received = state.pool.receive(.none, now_ns);
        assert(received.consumed == 0);
        const reported = received.event orelse {
            state.undrained = false;
            return;
        };
        handle(run, reported, now_ns);
    }
    state.undrained = true;
}

/// Does what one of the pool's events asks.
pub fn handle(run: anytype, reported: client.Event, now_ns: u64) void {
    const state = run;
    switch (reported) {
        .open => |asked| switch (asked.transport) {
            .tcp => client_tcp.open(state, asked),
            .quic => @import("client_udp.zig").start(state, now_ns),
        },
        .send => |connection| client_tcp.owed(state, connection),
        .close => |connection| client_tcp.close(state, connection),
        .connected => |connected| state.handler.on_connected(state, connected),
        // The client offers no ticket, so it keeps none it is given.
        .ticket => |connection| if (state.pool.take_ticket(connection)) |ticket| {
            var held = ticket;
            held.wipe();
        },
        // `Client.request` takes no streamed exchange, so no exchange has pieces.
        .headers, .body, .body_taken => unreachable,
        .finished => |ended| state.handler.on_finished(state, ended),
        // The next turn cancels the UDP socket's receive.
        .closed => state.closed = true,
    }
}

/// Whether the run may end: the pool reported `closed`, every TCP socket is free, and each
/// operation had its final completion (decision 159, rule 1).
pub fn finished(state: anytype) bool {
    if (!state.closed) return false;
    for (&state.sockets) |*socket| {
        if (socket.live) return false;
    }
    return state.operations.count == 0;
}

const testing = std.testing;

/// The fields `unix_seconds` reads, with nothing else of a client. Test-only.
const Clock = struct {
    unix_seconds: u64,
    started_ns: u64,
};

test "design §8 step 42: a chain is judged at the program's instant plus the run's time since" {
    const second_ns = client.constants.nanoseconds_per_second;
    const clock: Clock = .{ .unix_seconds = 1_000, .started_ns = 5 * second_ns };
    try testing.expectEqual(1_000, unix_seconds(&clock, 5 * second_ns));
    // Two and a half seconds of the run count as two whole seconds.
    try testing.expectEqual(1_002, unix_seconds(&clock, 7 * second_ns + second_ns / 2));
}
