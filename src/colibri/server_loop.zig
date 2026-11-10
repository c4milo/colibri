//! The driver of a `colibri.Server` (decision 159): it keeps one accept in flight while a socket
//! is free, hands each completion to the socket it names, steps every socket a completion named
//! (`server_pump.zig`), and writes the operations that each socket needs next. It does no I/O,
//! reads no clock and imports no Rotor. The host does each operation and calls `turn` and
//! `complete` (`rotor_host.zig` for `.private`). Moved from the test-only server's
//! `server_worker.zig` for design §8 step 37b.
//!
//! A server's `SocketId`s are its TCP sockets from 0, then the listener, then the UDP socket. Its
//! operation table holds each TCP socket's slots, the accept's, and the UDP socket's.
const std = @import("std");
const assert = std.debug.assert;
const server = @import("server");
const constants = @import("constants.zig");
const host = @import("host.zig");
const operation_table = @import("operation_table.zig");
const socket_module = @import("socket.zig");
const pump = @import("server_pump.zig");
const server_udp = @import("server_udp.zig");
const datagram_socket = @import("datagram_socket.zig");

/// A server's one UDP socket (`datagram_socket.zig`).
pub const Datagrams = datagram_socket.DatagramSockets(1);

/// The slots of the operation table of a server with `tcp_connections` sockets.
pub fn slot_count(tcp_connections: usize) u32 {
    return accept_slot(tcp_connections) + 1 + Datagrams.slots;
}

/// The slot of the one accept, after every socket's.
pub fn accept_slot(tcp_connections: usize) u32 {
    return @intCast(tcp_connections * socket_module.slots_per_socket);
}

/// The id of the listener, after every TCP socket's.
pub fn listener_id(tcp_connections: usize) host.SocketId {
    return @enumFromInt(tcp_connections);
}

/// The id of the UDP socket, after the listener's.
pub fn datagram_id(tcp_connections: usize) host.SocketId {
    return @enumFromInt(tcp_connections + 1);
}

/// The size of the host's table of sockets: the TCP sockets, then the listener and the UDP
/// socket.
pub fn sockets_max(tcp_connections: usize) u16 {
    return @intFromEnum(datagram_id(tcp_connections)) + 1;
}

/// The operations a server holds in flight at most: an accept, for each socket a receive, a send,
/// a close and the shutdown of its write side, and the UDP socket's receive and sends.
pub fn operations_max(tcp_connections: usize) u32 {
    return @intCast(tcp_connections * socket_module.operations_per_socket + 1 + Datagrams.operations);
}

/// Starts a run at `now`: no socket, entry or pending step, the engine started, and the UDP
/// socket's receive owed. The engine's deadlines count on `now.monotonic_ns`, and the tickets it
/// issues carry the Unix seconds of `now.unix_seconds`, where 0 issues none.
pub fn start(state: anytype, now: server.Timestamp) !void {
    reset(state, now.monotonic_ns);
    try state.engine.init(&state.engine_config, state.random, now);
    const tcp_connections = state.sockets.len;
    if (state.udp.served) state.udp.start(accept_slot(tcp_connections) + 1, state.datagram_segments);
}

/// Empties what a run holds: no socket, entry, pending step or operation, and `now_ns` as the last
/// instant.
pub fn reset(state: anytype, now_ns: u64) void {
    for (&state.sockets) |*socket| socket.live = false;
    for (&state.entries) |*entry| entry.* = .{ .handle = pump.no_connection, .attached = false, .closing = false, .send_owed = false };
    state.entry_of = @splat(null);
    state.pending = .initEmpty();
    state.touched = .initEmpty();
    state.operations = .empty;
    state.accepting = false;
    state.accept_canceled = false;
    state.undrained = false;
    state.shut_down = false;
    state.over = false;
    state.now_ns = now_ns;
}

/// One turn at `now_ns`, in decision 159's order: a `shutdown` passed to the engine, the engine's
/// deadlines and events, a step of each socket a completion named, and then the operations each
/// one needs, which it writes into `operations`.
pub fn turn(run: anytype, now_ns: u64, operations: []host.Operation) host.Turn {
    const state = run;
    host.enter(&state.in_turn, "turn()");
    defer state.in_turn = false;
    var out: operation_table.Outbox = .{ .operations = operations };
    if (state.stopping.load(.acquire) and !state.shut_down) shut_down(state, now_ns);
    const due = if (state.engine.deadline_ns()) |at_ns| at_ns <= now_ns else false;
    // With no deadline due the engine has nothing to fire, so the call is skipped.
    if (due or state.undrained) {
        state.now_ns = now_ns;
        state.engine.on_instant(now_ns);
        pump.drain(run);
    }
    serve(run, now_ns);
    write_accept(state, &out);
    arm(state, &out);
    if (state.udp.served) state.udp.write(&out, &state.operations, !state.shut_down, &state.engine, now_ns);
    return .{ .operations = out.len, .wait = wait(state, out.full) };
}

/// When the host calls `turn` next: at once while work is left, at the engine's next deadline, or
/// when a completion arrives. An idle server never makes the host spin.
pub fn wait(state: anytype, full: bool) host.Wait {
    if (full or state.undrained or state.pending.count() > 0) return .now;
    const at_ns = state.engine.deadline_ns() orelse return .none;
    return .{ .at_ns = at_ns };
}

/// Stops taking connections, and asks the engine to end each one it holds: its `closed` follows
/// once every connection has ended, and the run then ends.
fn shut_down(state: anytype, now_ns: u64) void {
    state.shut_down = true;
    state.engine.shutdown(now_ns);
    // The engine reports what the shutdown ends, and `closed` once it holds no connection. With
    // no socket to step, only a drain reads them, so this turn drains.
    state.undrained = true;
}

/// Takes one completion at `now_ns`. A completion with an id that the server does not hold is a
/// halt (decision 159, rule 6).
pub fn complete(run: anytype, completion: *const host.Completion, now_ns: u64) void {
    const state = run;
    host.enter(&state.in_turn, "complete()");
    defer state.in_turn = false;
    const slot = state.operations.held(completion.id);
    if (!completion.more) state.operations.finish(slot);
    const tcp_connections = state.sockets.len;
    if (slot == accept_slot(tcp_connections)) return on_accept(run, completion.result, now_ns);
    if (state.udp.served and state.udp.owns(slot)) return server_udp.complete(run, slot, completion, now_ns);
    const index = slot / socket_module.slots_per_socket;
    const kind: socket_module.Kind = @enumFromInt(slot % socket_module.slots_per_socket);
    const socket = &state.sockets[index];
    assert(socket.live);
    switch (kind) {
        .receive => socket.on_received(completion.result),
        .send => socket.on_sent(completion.result),
        .close => socket.closed = true,
        .shutdown => socket.on_shut_down(completion.result),
        // A server's sockets come from its listener, so it connects none.
        .connect => unreachable,
    }
    // The peer closed first, or the socket failed: the engine ends the connection.
    if (socket.failed) pump.peer_closed(run, index, now_ns);
    state.pending.set(index);
}

/// Keeps one accept in flight while a socket is free and the server runs, and cancels it once the
/// server shuts down. Every socket taken leaves new connections in the kernel's backlog until one
/// frees.
fn write_accept(state: anytype, out: *operation_table.Outbox) void {
    const slot = accept_slot(state.sockets.len);
    if (state.accepting) {
        if (!state.shut_down or state.accept_canceled or !out.room()) return;
        const target = state.operations.id(slot);
        out.put(.{ .id = target, .kind = .{ .cancel = .{ .target = target } } });
        state.accept_canceled = true;
        return;
    }
    // A hosted server whose host opened no listener serves h3 alone.
    if (state.shut_down or !state.listening) return;
    const into = free_socket(state) orelse return;
    if (!out.room()) return;
    out.put(.{ .id = state.operations.issue(slot), .kind = .{ .accept = .{
        .listener = listener_id(state.sockets.len),
        .into = @enumFromInt(into),
    } } });
    state.accepting = true;
    state.accept_into = @intCast(into);
}

/// Takes the socket an accept delivered into the free entry it named, and starts its connection.
fn on_accept(run: anytype, result: host.Completion.Result, now_ns: u64) void {
    const state = run;
    state.accepting = false;
    if (result != .accepted) return;
    const index: usize = state.accept_into;
    const socket = &state.sockets[index];
    // `write_accept` named a free socket, and only an accept takes one.
    assert(!socket.live);
    socket.open();
    // A server that is shutting down takes no connection.
    if (state.shut_down or !pump.accept(run, index, state.engine_config.tls != null, now_ns)) socket.failed = true;
    state.pending.set(index);
}

/// The index of an entry that can hold a socket.
fn free_socket(state: anytype) ?usize {
    for (&state.sockets, 0..) |*socket, index| {
        if (!socket.live) return index;
    }
    return null;
}

/// Steps every entry a socket or the engine named, until none is named.
fn serve(run: anytype, now_ns: u64) void {
    const state = run;
    for (0..state.sockets.len * constants.limits.events_per_step_max) |_| {
        const index = state.pending.toggleFirstSet() orelse return;
        serve_entry(run, index, now_ns);
    }
}

/// Steps the socket at `index`: its unread octets go in, and what its connection owes is appended
/// to its output. A socket the host has finished with, whose connection has ended, frees its entry.
fn serve_entry(run: anytype, index: usize, now_ns: u64) void {
    const state = run;
    const socket = &state.sockets[index];
    if (!socket.live) return;
    if (socket.finished() and !state.entries[index].attached) {
        socket.live = false;
        return;
    }
    state.touched.set(index);
    if (socket.stopped()) return;
    const room = socket.room();
    if (room.len > 0) {
        const stepped = pump.step(run, index, socket.unread(), room, now_ns);
        socket.wrote(stepped.written);
        socket.consume(stepped.consumed);
    }
    // The engine closed the connection: the socket closes once its octets are out.
    if (state.entries[index].closing) socket.closing = true;
    // The engine closes in stages: the socket's write side closes once its octets are out.
    if (state.entries[index].half_closing) socket.half_closing = true;
}

/// Writes what each socket this turn changed needs next. A socket whose operation found no room
/// stays changed for the next turn.
fn arm(state: anytype, out: *operation_table.Outbox) void {
    var left: @TypeOf(state.touched) = .initEmpty();
    for (0..state.sockets.len) |_| {
        const index = state.touched.toggleFirstSet() orelse break;
        const socket = &state.sockets[index];
        if (!socket.live) continue;
        if (!socket.arm(out, &state.operations, index)) left.set(index);
    }
    state.touched.setUnion(left);
}

/// Whether the run may end: the engine reported `closed`, every socket is free, and each operation
/// had its final completion (decision 159, rule 1).
pub fn finished(state: anytype) bool {
    if (!state.over) return false;
    for (&state.sockets) |*socket| {
        if (socket.live) return false;
    }
    return state.operations.count == 0;
}
