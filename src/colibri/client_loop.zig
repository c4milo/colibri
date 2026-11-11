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
    return datagram_slot(tcp_connections) + if (quic) Datagrams.slots else 0;
}

/// The first slot of the UDP sockets, after every TCP socket's.
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

/// A client's UDP socket of each family, IPv4's at index 0 and IPv6's at index 1
/// (`datagram_socket.zig`).
pub const Datagrams = datagram_socket.DatagramSockets(@typeInfo(Family).@"enum".fields.len);

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
    return @intCast(tcp_connections * socket_module.client_operations_per_socket + if (quic) Datagrams.operations else 0);
}

/// Runs the client `state` names on the calling thread until its pool reports `closed`, every
/// socket has closed, and each operation had its final completion (`Client.run`). The UDP socket
/// closes last.
pub fn run_loop(state: anytype) !void {
    // The pool reports `closed` once, so a second run would wait for it without end.
    assert(!state.ran);
    state.ran = true;
    defer state.host.close_open();
    // A `fetch` may have made the loop and started the run already.
    try begin(state);
    defer end(state);
    try state.host.run(state, @This(), state);
}

/// Makes the loop of a `.private` client on the calling thread, and starts the run at the loop's
/// first instant, unless a `fetch` did already (`client_fetch.zig`).
pub fn begin(state: anytype) !void {
    if (state.begun) return;
    const now_ns = try state.host.begin();
    state.begun = true;
    start(state, now_ns);
}

/// Frees the loop that `begin` made, after the run's last operation or a failure of the loop.
pub fn end(state: anytype) void {
    assert(state.begun);
    state.host.end();
    state.begun = false;
}

/// Stops a run that a `fetch` began and no `run` ended (`Client.deinit` of `.private`). It calls
/// `shutdown`, and runs the loop until each exchange has finished and each connection has closed
/// (decision 156 ruling 10). A loop that fails ends at once: `end` cancels what is in flight.
pub fn stop(state: anytype) void {
    if (!state.begun) return;
    state.shutdown();
    state.host.run(state, @This(), state) catch {};
    end(state);
}

/// Starts a run at `now_ns`, the instant `unix_seconds` counts from, with the receive of each UDP
/// socket owed.
pub fn start(state: anytype, now_ns: u64) void {
    assert(!state.started);
    state.started = true;
    state.started_ns = now_ns;
    if (state.udp.served) state.udp.start(datagram_slot(state.sockets.len), state.datagram_segments);
}

/// Empties what a run holds, at `init`: no socket, pending step or operation, and a pool that has
/// not closed. So `stopped()` holds only after the run that follows.
pub fn reset(state: anytype) void {
    for (&state.sockets) |*socket| socket.live = false;
    state.connections = @splat(client_tcp.Connection.empty);
    state.pending = .initEmpty();
    state.touched = .initEmpty();
    state.operations = .empty;
    // Each turn reads the pool's events first, so a request made before the first turn leaves
    // in it.
    state.undrained = false;
    state.shut_down = false;
    state.closed = false;
    state.started = false;
    state.started_ns = 0;
}

/// The seconds since 1970 at `now_ns`: the program's instant at the start of the run, and the
/// time the run has lasted since. A `.private` run starts at the loop's first instant, and a
/// `.hosted` one at `init`. chapulin judges a chain's dates at it (RFC 5280 §4.1.2.5).
pub fn unix_seconds(state: anytype, now_ns: u64) u64 {
    return state.unix_seconds + (now_ns -| state.started_ns) / client.constants.nanoseconds_per_second;
}

/// One turn at `now_ns`. See the header. The run started before it: at the loop's first instant
/// on `.private`, and at `init` on `.hosted`. An instant before the last call's is a halt
/// (decision 159, rule 6).
pub fn turn(run: anytype, now_ns: u64, operations: []host.Operation) host.Turn {
    const state = run;
    host.enter(&state.in_turn, "turn()");
    defer state.in_turn = false;
    assert(state.started);
    host.record_instant(&state.latest_ns, now_ns);
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
/// halt, and so is an instant before the last call's (decision 159, rule 6).
pub fn complete(run: anytype, completion: *const host.Completion, now_ns: u64) void {
    const state = run;
    host.enter(&state.in_turn, "complete()");
    defer state.in_turn = false;
    host.record_instant(&state.latest_ns, now_ns);
    const slot = state.operations.held(completion.id);
    if (!completion.more) state.operations.finish(slot);
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
            .quic => open_quic(run, asked, now_ns),
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
        .finished => |ended| finish(state, ended),
        // The next turn cancels the UDP socket's receive.
        .closed => state.closed = true,
    }
}

/// Hands an exchange that ended to the handler, unless it is the one a `fetch` runs, which
/// `fetch` returns (decision 156 ruling 12).
fn finish(state: anytype, ended: client.Finished) void {
    const fetching = state.fetching orelse return state.handler.on_finished(state, ended);
    if (fetching != ended.id) return state.handler.on_finished(state, ended);
    state.fetching = null;
    state.fetched = true;
}

/// Starts the QUIC connection that `asked` opens, from the UDP socket of its address's family.
/// With no socket of that family, the attempt ends as a refused open does, and the pool opens TCP
/// (decision 156 ruling 13). A destination can name a family with no socket after
/// `set_destination`, or when the host did not open one.
fn open_quic(run: anytype, asked: client.Open, now_ns: u64) void {
    const state = run;
    if (!state.udp.sends_to(&asked.to)) return state.pool.transport_closed(asked.connection);
    @import("client_udp.zig").start(state, now_ns);
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

/// The fields `wait` reads, with nothing else of a client: a pool and a connect with no
/// deadline. Test-only.
const Waiting = struct {
    const Pool = struct {
        fn deadline_ns(_: *const Pool) ?u64 {
            return null;
        }
    };
    const Connection = struct {
        connecting: bool = false,
        connect_owed: bool = false,
        connect_canceled: bool = false,
        connect_deadline_ns: ?u64 = null,
    };
    undrained: bool = false,
    pending: std.bit_set.IntegerBitSet(1) = .initEmpty(),
    pool: Pool = .{},
    connections: [1]Connection = .{.{}},
};

test "decision 159: a socket that a turn left to step makes the host turn again at once" {
    var state: Waiting = .{};
    try testing.expectEqual(host.Wait.none, wait(&state, false));
    // A step that ran out of its bound leaves the socket pending (`client_tcp.zig`).
    state.pending.set(0);
    try testing.expectEqual(host.Wait.now, wait(&state, false));
}

test "design §8 step 42: a chain is judged at the program's instant plus the run's time since" {
    const second_ns = client.constants.nanoseconds_per_second;
    const clock: Clock = .{ .unix_seconds = 1_000, .started_ns = 5 * second_ns };
    try testing.expectEqual(1_000, unix_seconds(&clock, 5 * second_ns));
    // Two and a half seconds of the run count as two whole seconds.
    try testing.expectEqual(1_002, unix_seconds(&clock, 7 * second_ns + second_ns / 2));
}
