//! The TCP sockets of a `colibri.Client` (design §8 step 42): one for each TCP slot of the pool,
//! opened and closed when the pool asks. Each is `socket.zig`'s, which a server's accepted sockets
//! are too, and its `Connection` holds what only a client needs: the connection's handle, the
//! address its connect reads, and an open that waits for the slot's last close.
//!
//! The pool's events name a TCP connection by its handle, whose slot is the socket's index. A slot
//! holds one socket at a time: an open the pool asks for while the slot's last socket still
//! closes waits for that close's final event, so the loop never holds two sockets for one slot.
const std = @import("std");
const assert = std.debug.assert;
const rotor = @import("rotor");
const client = @import("client");
const constants = @import("constants.zig");
const socket_module = @import("socket.zig");
const datagram_socket = @import("datagram_socket.zig");
const client_loop = @import("client_loop.zig");

const Kind = socket_module.Kind;
const kind_bits = socket_module.kind_bits;

/// What the client holds for the socket of one TCP slot, beside the socket.
pub const Connection = struct {
    /// The connection the slot's socket carries, which the pool's calls and events name.
    handle: client.ConnectionHandle,
    /// The peer, which the connect in flight reads until its event (Rotor's rule 3).
    address: rotor.Address,
    /// The connect is in flight. The socket receives and sends nothing until its event.
    connecting: bool,
    /// The pool's connection runs on the socket: `start_tcp` took it, and the pool has not asked
    /// for the close nor heard that the transport closed.
    started: bool,
    /// An open the pool asked for while the slot's last socket was still closing.
    waiting: ?client.Open,

    pub const empty: Connection = .{
        .handle = .{ .slot = 0, .generation = 0 },
        .address = undefined,
        .connecting = false,
        .started = false,
        .waiting = null,
    };
};

/// Opens the socket the pool's `open` event asks for, or holds the open until the slot's last
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
    connect(state, slot, asked);
}

/// Opens a socket with Nagle's algorithm off (TCP_NODELAY), so a small request leaves at once, and
/// submits its connect. A socket the system refuses ends the attempt: the pool hears
/// `transport_closed` in place of the start.
fn connect(state: anytype, slot: usize, asked: client.Open) void {
    const connection = &state.connections[slot];
    // A slot holds one socket at a time: `open` holds an open until the last socket has closed.
    assert(!state.sockets[slot].live);
    connection.* = .{
        .handle = asked.connection,
        .address = datagram_socket.udp_address(asked.to),
        .connecting = false,
        .started = false,
        .waiting = null,
    };
    const descriptor = rotor.sync.open_socket(connection.address.family) catch {
        state.pool.transport_closed(asked.connection);
        return;
    };
    // A socket that refuses the option is used as it is.
    rotor.sync.set_no_delay(descriptor, true) catch {};
    state.sockets[slot].open(descriptor);
    connection.connecting = true;
    var operation = rotor.Operation.connect(socket_module.user_data(slot, .connect), descriptor, &connection.address);
    // Rotor cancels a connect whose deadline passes first, and `on_connected` ends the attempt.
    operation.timeout_ns = connect_timeout_ns(state.pool_config.timeouts.connect_ns);
    const taken = state.loop.submit(&.{operation}, &.{});
    assert(taken == 1);
}

/// The deadline Rotor gives a connect: `connect_ns`, or 0, Rotor's none, for no limit. A limit of 0
/// ends the connect at once, so it becomes Rotor's least deadline. Rotor halts on a deadline past
/// `timeout_ns_max`, one day, so a longer limit becomes that day. The system ends a connect far
/// sooner, at about 75 s on macOS and 127 s on Linux, so the change is not visible.
fn connect_timeout_ns(connect_ns: ?u64) u64 {
    const limit_ns = connect_ns orelse return 0;
    return std.math.clamp(limit_ns, 1, rotor.constants.timeout_ns_max);
}

/// The pool is done with a connection: its socket sends what it owes and closes. The pool reads
/// nothing more of it, and the slot's next socket starts with no input (`Socket.open`), so the next
/// connection gets none of its octets. An open still waiting for the slot's last close is the one
/// the pool gave up, and never starts. A socket whose connect is in flight closes at once (`arm`).
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
    connection.started = false;
    socket.closing = true;
    state.pending.set(slot);
}

/// Marks the socket of a TCP connection that owes octets, so the turn steps it. A step of a slot
/// whose connection owes nothing writes nothing, so the handle's generation is not checked.
pub fn owed(state: anytype, handle: client.ConnectionHandle) void {
    if (handle.slot < state.sockets.len) state.pending.set(handle.slot);
}

/// Hands an event to the socket its user data names.
pub fn on_event(run: anytype, event: rotor.Event, now_ns: u64) void {
    const state = run.client;
    const slot: usize = @intCast(event.user_data >> kind_bits);
    const kind: Kind = @enumFromInt(@as(u8, @truncate(event.user_data)));
    const socket = &state.sockets[slot];
    assert(socket.live);
    switch (kind) {
        .connect => on_connected(state, slot, event, now_ns),
        .receive => socket.on_received(event),
        .send => socket.on_sent(event),
        .close => socket.closed = true,
    }
    // The peer closed first, or a call failed: the pool ends the connection.
    if (socket.failed) transport_closed(state, slot);
    state.pending.set(slot);
}

/// Starts the pool's connection on a socket whose connect succeeded. A connect that failed ends
/// the attempt, whether the peer refused it or its deadline passed (Rotor's `timeout`), and so does
/// a start the TLS stack refuses: the pool owes no `close` for a
/// connection that never started, so the socket closes here.
fn on_connected(state: anytype, slot: usize, event: rotor.Event, now_ns: u64) void {
    const connection = &state.connections[slot];
    const socket = &state.sockets[slot];
    assert(connection.connecting);
    connection.connecting = false;
    // The pool asked for the close while the connect ran, and `arm` submits it or did. The connect
    // ended with `canceled`, or it succeeded first: either way the connection never starts.
    if (socket.closing) return;
    _ = event.outcome() catch {
        socket.failed = true;
        state.pool.transport_closed(connection.handle);
        return;
    };
    state.pool.start_tcp(connection.handle, state.config.random.?, client_loop.unix_seconds(state, now_ns), null) catch {
        socket.failed = true;
        return;
    };
    connection.started = true;
}

/// Tells the pool once that the transport of a running connection closed.
fn transport_closed(state: anytype, slot: usize) void {
    const connection = &state.connections[slot];
    if (!connection.started) return;
    connection.started = false;
    state.pool.transport_closed(connection.handle);
}

/// Steps every socket an event named, until none is named.
pub fn serve(run: anytype, now_ns: u64) void {
    const state = run.client;
    for (0..state.sockets.len * constants.limits.events_per_step_max) |_| {
        const slot = state.pending.toggleFirstSet() orelse return;
        serve_slot(run, slot, now_ns);
    }
}

/// Steps the socket of `slot`. A socket Rotor has finished with frees the slot, and the open that
/// waited for it starts. A connect the close cancelled still owes its final event (Rotor's rule 1).
fn serve_slot(run: anytype, slot: usize, now_ns: u64) void {
    const state = run.client;
    const socket = &state.sockets[slot];
    const connection = &state.connections[slot];
    if (!socket.live) return;
    if (socket.finished() and !connection.connecting) {
        socket.live = false;
        const asked = connection.waiting orelse return;
        connection.waiting = null;
        return connect(state, slot, asked);
    }
    state.touched.set(slot);
    if (socket.stopped() or !connection.started) return;
    step(run, slot, now_ns);
}

/// Passes the socket's unread octets to the pool and writes what its connection owes into the
/// socket's room, until neither moves.
fn step(run: anytype, slot: usize, now_ns: u64) void {
    const state = run.client;
    const socket = &state.sockets[slot];
    const connection = &state.connections[slot];
    // Bounded: a pass in which nothing moves ends the loop.
    for (0..constants.limits.events_per_step_max) |_| {
        const unread = socket.unread();
        const input: client.Input = if (unread.len == 0) .none else .{ .stream = .{ .connection = connection.handle, .bytes = unread } };
        const received = state.pool.receive(input, now_ns);
        socket.consume(received.consumed);
        if (received.event) |reported| client_loop.handle(run, reported, now_ns);
        if (!connection.started or socket.stopped()) return;
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

/// Submits what each socket this turn changed needs next. A socket that connects receives and
/// sends nothing. Once the pool closed its connection, the socket's close goes at once: Rotor's
/// close cancels the connect in flight, which could otherwise wait for the system's own limit.
pub fn arm(state: anytype) void {
    for (0..state.sockets.len) |_| {
        const slot = state.touched.toggleFirstSet() orelse return;
        const socket = &state.sockets[slot];
        const connecting = state.connections[slot].connecting;
        // A connecting socket wrote nothing, so `Socket.arm` submits its close alone.
        assert(!connecting or socket.output_len == 0);
        if (socket.live and (!connecting or socket.closing)) socket.arm(&state.loop, slot);
    }
}

comptime {
    // Decision 124: the socket holds what the pool needs of a TCP connection's input and output.
    assert(constants.limits.socket_input_len >= client.constants.limits.stream_input_len_min);
    assert(constants.limits.socket_output_len >= client.constants.limits.stream_output_len_min);
}

test "decision 153 ruling 9: a connect's deadline is the pool's limit, none for null, and at once for 0" {
    try std.testing.expectEqual(10_000_000_000, connect_timeout_ns(client.constants.policy.connect_timeout_ns));
    // Rotor reads a deadline of 0 as none.
    try std.testing.expectEqual(0, connect_timeout_ns(null));
    try std.testing.expectEqual(1, connect_timeout_ns(0));
    // Rotor halts on a deadline past one day, so a longer limit becomes one day.
    try std.testing.expectEqual(rotor.constants.timeout_ns_max, connect_timeout_ns(2 * rotor.constants.timeout_ns_max));
    try std.testing.expectEqual(rotor.constants.timeout_ns_max, connect_timeout_ns(std.math.maxInt(u64)));
}
