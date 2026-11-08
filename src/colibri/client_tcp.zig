//! The TCP sockets of a `colibri.Client` (design §8 step 42): one for each TCP slot of the pool,
//! opened and closed when the pool asks. Each is `socket.zig`'s, which a server's accepted sockets
//! are too, and its `Connection` holds what only a client needs: the connection's handle, the
//! address its connect names, the connect's deadline, and an open that waits for the slot's last
//! close. The host opens each socket at its connect (decision 159).
//!
//! The pool's events name a TCP connection by its handle, whose slot is the socket's index. A slot
//! holds one socket at a time: an open the pool asks for while the slot's last socket still
//! closes waits for that close's final completion, so the host never holds two sockets for one
//! slot.
const std = @import("std");
const assert = std.debug.assert;
const client = @import("client");
const constants = @import("constants.zig");
const host = @import("host.zig");
const operation_table = @import("operation_table.zig");
const socket_module = @import("socket.zig");
const client_loop = @import("client_loop.zig");

/// What the client holds for the socket of one TCP slot, beside the socket.
pub const Connection = struct {
    /// The connection the slot's socket carries, which the pool's calls and events name.
    handle: client.ConnectionHandle,
    /// The peer the connect names.
    address: client.Address,
    /// The connect is owed or in flight. The socket receives and sends nothing until its
    /// completion.
    connecting: bool,
    /// The next turn writes the connect.
    connect_owed: bool,
    /// The instant the connect ends at, and whether its cancel was written. Null for no limit.
    connect_deadline_ns: ?u64,
    connect_canceled: bool,
    /// The pool's connection runs on the socket: `start_tcp` took it. The flag stays set after the
    /// pool's `close` and after a failure, and the pool changes nothing more for the connection.
    /// After `close` its handle names none, and a second `transport_closed` changes nothing.
    started: bool,
    /// An open the pool asked for while the slot's last socket was still closing.
    waiting: ?client.Open,

    pub const empty: Connection = .{
        .handle = .{ .slot = 0, .generation = 0 },
        .address = .{},
        .connecting = false,
        .connect_owed = false,
        .connect_deadline_ns = null,
        .connect_canceled = false,
        .started = false,
        .waiting = null,
    };
};

/// Takes the socket the pool's `open` event asks for, or holds the open until the slot's last
/// socket has closed.
pub fn open(state: anytype, asked: client.Open) void {
    const slot: usize = asked.connection.slot;
    assert(slot < state.sockets.len and asked.transport == .tcp);
    const connection = &state.connections[slot];
    if (state.sockets[slot].live) {
        assert(connection.waiting == null);
        connection.waiting = asked;
        return;
    }
    take(state, slot, asked);
}

/// Takes the socket of `slot` for `asked`. The next turn writes its connect.
fn take(state: anytype, slot: usize, asked: client.Open) void {
    // A slot holds one socket at a time: `open` holds an open until the last socket has closed.
    assert(!state.sockets[slot].live);
    state.connections[slot] = .{
        .handle = asked.connection,
        .address = asked.to,
        .connecting = true,
        .connect_owed = true,
        .connect_deadline_ns = null,
        .connect_canceled = false,
        .started = false,
        .waiting = null,
    };
    state.sockets[slot].open();
    state.touched.set(slot);
}

/// The instant a connect written at `now_ns` ends at: `connect_ns` later, at once for 0, and never
/// for null.
pub fn connect_deadline(now_ns: u64, connect_ns: ?u64) ?u64 {
    return now_ns +| (connect_ns orelse return null);
}

/// The pool is done with a connection: its socket sends what it owes and closes. The pool reads
/// nothing more of it, and the slot's next socket starts with no input (`Socket.open`), so the next
/// connection gets none of its octets. An open still waiting for the slot's last close is the one
/// the pool gave up, and never starts. A socket whose connect is in flight closes at once (`arm`),
/// and one whose connect is not written yet frees its slot with no operation.
pub fn close(state: anytype, handle: client.ConnectionHandle) void {
    if (handle.slot >= state.sockets.len) return;
    const slot: usize = handle.slot;
    const connection = &state.connections[slot];
    if (connection.waiting) |asked| {
        if (std.meta.eql(asked.connection, handle)) {
            connection.waiting = null;
            return;
        }
    }
    const socket = &state.sockets[slot];
    if (!socket.live or !std.meta.eql(connection.handle, handle)) return;
    socket.closing = true;
    if (connection.connect_owed) {
        // The host holds no socket for the slot yet, so nothing is closed.
        connection.connect_owed = false;
        connection.connecting = false;
        socket.close_submitted = true;
        socket.closed = true;
    }
    state.pending.set(slot);
}

/// Marks the socket of a TCP connection that owes octets, so the turn steps it. A step of a slot
/// whose connection owes nothing writes nothing, so the handle's generation is not checked.
pub fn owed(state: anytype, handle: client.ConnectionHandle) void {
    if (handle.slot < state.sockets.len) state.pending.set(handle.slot);
}

/// Hands a completion to the socket of `slot`.
pub fn complete(run: anytype, slot: usize, kind: socket_module.Kind, result: host.Completion.Result, now_ns: u64) void {
    const state = run;
    const socket = &state.sockets[slot];
    assert(socket.live);
    switch (kind) {
        .connect => on_connected(state, slot, result, now_ns),
        .receive => socket.on_received(result),
        .send => socket.on_sent(result),
        .close => socket.closed = true,
    }
    // The peer closed first, or a call failed: the pool ends the connection. The pool changes
    // nothing for a handle it already ended, so each later completion of the socket may call again.
    if (socket.failed) state.pool.transport_closed(state.connections[slot].handle);
    state.pending.set(slot);
}

/// Starts the pool's connection on a socket whose connect succeeded. A connect that failed ends
/// the attempt, whether the peer refused it or its deadline passed. A start the TLS stack refuses
/// ends it too. The pool owes no `close` for a connection that never started, so the socket closes
/// here.
fn on_connected(state: anytype, slot: usize, result: host.Completion.Result, now_ns: u64) void {
    const connection = &state.connections[slot];
    const socket = &state.sockets[slot];
    assert(connection.connecting and !connection.connect_owed);
    connection.connecting = false;
    // The pool asked for the close while the connect ran, and `arm` writes it or did. The connect
    // ended canceled, or it succeeded first: either way the connection never starts.
    if (socket.closing) return;
    if (result != .connected) {
        socket.failed = true;
        state.pool.transport_closed(connection.handle);
        return;
    }
    state.pool.start_tcp(connection.handle, state.random, client_loop.unix_seconds(state, now_ns), null) catch {
        socket.failed = true;
        return;
    };
    connection.started = true;
}

/// Steps every socket a completion named, until none is named.
pub fn serve(run: anytype, now_ns: u64) void {
    const state = run;
    for (0..state.sockets.len * constants.limits.events_per_step_max) |_| {
        const slot = state.pending.toggleFirstSet() orelse return;
        serve_slot(run, slot, now_ns);
    }
}

/// Steps the socket of `slot`. A socket the host has finished with frees the slot, and the open
/// that waited for it starts. A connect the close cancelled still owes its final completion
/// (decision 159, rule 2).
fn serve_slot(run: anytype, slot: usize, now_ns: u64) void {
    const state = run;
    const socket = &state.sockets[slot];
    const connection = &state.connections[slot];
    if (!socket.live) return;
    if (socket.finished() and !connection.connecting) {
        socket.live = false;
        const asked = connection.waiting orelse return;
        connection.waiting = null;
        return take(state, slot, asked);
    }
    state.touched.set(slot);
    if (socket.stopped() or !connection.started) return;
    step(run, slot, now_ns);
}

/// Passes the socket's unread octets to the pool and writes what its connection owes into the
/// socket's room, until neither moves.
fn step(run: anytype, slot: usize, now_ns: u64) void {
    const state = run;
    const socket = &state.sockets[slot];
    const connection = &state.connections[slot];
    // Bounded: a pass in which nothing moves ends the loop.
    for (0..constants.limits.events_per_step_max) |_| {
        const unread = socket.unread();
        const input: client.Input = if (unread.len == 0) .none else .{ .stream = .{ .connection = connection.handle, .bytes = unread } };
        const received = state.pool.receive(input, now_ns);
        socket.consume(received.consumed);
        if (received.event) |reported| client_loop.handle(run, reported, now_ns);
        if (socket.stopped()) return;
        const written = write(state, slot, now_ns);
        if (received.consumed == 0 and received.event == null and written == 0) return;
    } else state.pending.set(slot);
}

/// Writes what the slot's connection owes into its socket's room.
fn write(state: anytype, slot: usize, now_ns: u64) usize {
    const socket = &state.sockets[slot];
    const room = socket.room();
    if (room.len == 0) return 0;
    const written = state.pool.send_stream(state.connections[slot].handle, room, now_ns);
    socket.wrote(written);
    return written;
}

/// Writes what each socket this turn changed needs next. A socket that connects receives and
/// sends nothing. Once the pool closed its connection, the socket's close goes at once: the host's
/// close cancels the connect in flight, which could otherwise wait for the system's own limit. A
/// socket whose operation found no room stays changed for the next turn.
pub fn arm(state: anytype, out: *operation_table.Outbox, now_ns: u64) void {
    var left: @TypeOf(state.touched) = .initEmpty();
    for (0..state.sockets.len) |_| {
        const slot = state.touched.toggleFirstSet() orelse break;
        const socket = &state.sockets[slot];
        const connection = &state.connections[slot];
        if (!socket.live) continue;
        if (connection.connect_owed) {
            if (!write_connect(state, out, slot, now_ns)) left.set(slot);
            continue;
        }
        // A connecting socket wrote nothing, so `Socket.arm` writes its close alone.
        assert(!connection.connecting or socket.output_len == 0);
        if (connection.connecting and !socket.closing) continue;
        if (!socket.arm(out, &state.operations, slot)) left.set(slot);
    }
    state.touched.setUnion(left);
}

/// Writes the connect of `slot`, whose deadline starts at `now_ns` (decision 153 ruling 9).
fn write_connect(state: anytype, out: *operation_table.Outbox, slot: usize, now_ns: u64) bool {
    if (!out.room()) return false;
    const connection = &state.connections[slot];
    const id = state.operations.issue(socket_module.slot_of(slot, .connect));
    out.put(.{ .id = id, .kind = .{ .connect = .{ .socket = @enumFromInt(slot), .address = connection.address } } });
    connection.connect_owed = false;
    connection.connect_deadline_ns = connect_deadline(now_ns, state.pool_config.timeouts.connect_ns);
    return true;
}

/// Cancels each connect whose deadline passed at `now_ns`. Its completion then ends the attempt
/// as a refused one (`on_connected`).
pub fn cancel_late(state: anytype, out: *operation_table.Outbox, now_ns: u64) void {
    for (&state.connections, 0..) |*connection, slot| {
        if (!connection.connecting or connection.connect_owed or connection.connect_canceled) continue;
        const at_ns = connection.connect_deadline_ns orelse continue;
        if (at_ns > now_ns) continue;
        if (!out.room()) return;
        const target = state.operations.id(socket_module.slot_of(slot, .connect));
        out.put(.{ .id = target, .kind = .{ .cancel = .{ .target = target } } });
        connection.connect_canceled = true;
    }
}

/// The soonest instant a connect in flight ends at, or null for none.
pub fn next_deadline(state: anytype) ?u64 {
    var soonest: ?u64 = null;
    for (&state.connections) |*connection| {
        if (!connection.connecting or connection.connect_owed or connection.connect_canceled) continue;
        const at_ns = connection.connect_deadline_ns orelse continue;
        soonest = @min(soonest orelse at_ns, at_ns);
    }
    return soonest;
}

comptime {
    // Decision 124: the socket holds what the pool needs of a TCP connection's input and output.
    assert(constants.limits.socket_input_len >= client.constants.limits.stream_input_len_min);
    assert(constants.limits.socket_output_len >= client.constants.limits.stream_output_len_min);
}

test "decision 153 ruling 9: a connect ends at the pool's limit, never for null, and at once for 0" {
    const now_ns: u64 = 5;
    try std.testing.expectEqual(now_ns + 10_000_000_000, connect_deadline(now_ns, client.constants.policy.connect_timeout_ns).?);
    try std.testing.expectEqual(null, connect_deadline(now_ns, null));
    try std.testing.expectEqual(now_ns, connect_deadline(now_ns, 0).?);
    // The largest limit saturates, so the connect never ends by its deadline.
    try std.testing.expectEqual(std.math.maxInt(u64), connect_deadline(now_ns, std.math.maxInt(u64)).?);
}
