//! The socket side of a `colibri.Server`, on Rotor's own loop (decision 150 ruling 6): it binds the
//! listener, keeps one accept in flight while a socket is free, hands each event to the socket it
//! names, and steps every socket an event named (`server_pump.zig`). Moved from the test-only
//! server's `server_worker.zig` for design §8 step 37b. One loop runs on the thread that calls
//! `run` (ruling 7).
const std = @import("std");
const assert = std.debug.assert;
const rotor = @import("rotor");
const constants = @import("constants.zig");
const socket_module = @import("socket.zig");
const pump = @import("server_pump.zig");
const server_udp = @import("server_udp.zig");

const Kind = socket_module.Kind;
const kind_bits = socket_module.kind_bits;

/// The user data of the one accept the server keeps in flight. No socket's user data reaches it.
pub const accept_user_data: u64 = std.math.maxInt(u64);

pub const BindError = rotor.sync.ListenError || rotor.sync.AddressError || error{
    /// `host` is not an IPv4 or IPv6 literal.
    HostInvalid,
};

/// The Rotor address of `host` and `port`.
pub fn address_of(host: []const u8, port: u16) error{HostInvalid}!rotor.Address {
    const parsed = std.Io.net.IpAddress.parse(host, port) catch return error.HostInvalid;
    return switch (parsed) {
        .ip4 => |ip4| rotor.Address.ipv4(ip4.bytes, ip4.port),
        .ip6 => |ip6| rotor.Address.ipv6(ip6.bytes, ip6.port, 0),
    };
}

/// Binds the listener on the configured host and port, and keeps the port the system chose for
/// port 0. SO_REUSEPORT lets a program run more servers on one port (ruling 7).
pub fn bind(state: anytype) BindError!void {
    const address = try address_of(state.config.host, state.config.port);
    state.listener = try rotor.sync.listen(&address, .{ .backlog = constants.limits.listen_backlog, .reuse_port = true });
    errdefer rotor.sync.close_now(state.listener);
    const local = try rotor.sync.local_address(state.listener);
    assert(local.port != 0);
    state.bound_port = local.port;
}

/// Empties what a run holds: no socket, entry or pending step, and the loop's instant as the last.
pub fn reset(state: anytype) void {
    for (&state.sockets) |*socket| socket.live = false;
    for (&state.entries) |*entry| entry.* = .{ .handle = pump.no_connection, .attached = false, .closing = false, .send_owed = false };
    state.entry_of = @splat(null);
    state.pending = .initEmpty();
    state.touched = .initEmpty();
    state.accepting = false;
    state.undrained = false;
    state.shut_down = false;
    state.over = false;
    state.now_ns = state.loop.now_ns();
}

/// One turn of the loop: an accept when a socket is free, one tick, what its events ask for, and
/// then the operations each socket it changed needs next.
pub fn turn(run: anytype) !void {
    const state = run.server;
    if (state.stopping.load(.acquire) and !state.shut_down) shut_down(state);
    arm_accept(state);
    const deadline_ns = state.endpoint.deadline_ns();
    const count = try state.loop.tick(&state.events, wait_ns(state, deadline_ns, state.loop.now_ns()));
    const now_ns = state.loop.now_ns();
    for (state.events[0..count]) |event| on_event(run, event, now_ns);
    const due = if (deadline_ns) |at_ns| at_ns <= now_ns else false;
    // With no deadline due the endpoint has nothing to fire, so the call is skipped.
    if (due or state.undrained) {
        state.now_ns = now_ns;
        state.endpoint.on_instant(now_ns);
        pump.drain(run);
    }
    serve(run, now_ns);
    arm(state);
    if (state.udp_open) server_udp.flush(state, now_ns);
}

/// Stops taking connections, and asks the endpoint to end each one it holds: its `closed` follows
/// once every connection has ended, and `run` then returns.
fn shut_down(state: anytype) void {
    state.shut_down = true;
    if (state.udp_open) server_udp.stop(state);
    state.endpoint.shutdown(state.loop.now_ns());
    // The endpoint reports what the shutdown ends, and `closed` once it holds no connection. With
    // no socket to step, only a drain reads them, so this turn drains.
    state.undrained = true;
}

/// How long the tick after `now_ns` may wait: until `deadline_ns`, the soonest deadline of a
/// connection, and never longer than Rotor's longest wait. No time while work is left, and a
/// bounded wait while `shutdown` is asked from another thread.
fn wait_ns(state: anytype, deadline_ns: ?u64, now_ns: u64) u64 {
    if (state.undrained or state.pending.count() > 0) return 0;
    const at_ns = deadline_ns orelse return constants.limits.stop_wait_ns_max;
    return @min(constants.limits.stop_wait_ns_max, at_ns -| now_ns);
}

fn on_event(run: anytype, event: rotor.Event, now_ns: u64) void {
    const state = run.server;
    if (event.user_data == accept_user_data) return on_accept(run, event, now_ns);
    if (server_udp.owns(event.user_data)) return server_udp.on_event(run, event, now_ns);
    const index: usize = @intCast(event.user_data >> kind_bits);
    const kind: Kind = @enumFromInt(@as(u8, @truncate(event.user_data)));
    const socket = &state.sockets[index];
    assert(socket.live);
    switch (kind) {
        .receive => socket.on_received(event),
        .send => socket.on_sent(event),
        .close => socket.closed = true,
    }
    // The peer closed first, or the socket failed: the endpoint ends the connection.
    if (socket.failed) pump.peer_closed(run, index, now_ns);
    state.pending.set(index);
}

/// Keeps one accept in flight while a socket is free and the server runs. Every socket taken
/// leaves new connections in the kernel's backlog until one frees.
fn arm_accept(state: anytype) void {
    if (state.accepting or state.shut_down or free_socket(state) == null) return;
    const taken = state.loop.submit(&.{rotor.Operation.accept(accept_user_data, state.listener, false)}, &.{});
    assert(taken == 1);
    state.accepting = true;
}

/// Takes the socket an accept delivered into a free entry, and starts its connection.
fn on_accept(run: anytype, event: rotor.Event, now_ns: u64) void {
    const state = run.server;
    state.accepting = false;
    const descriptor: rotor.Descriptor = @intCast(event.outcome() catch return);
    // `arm_accept` waits for a free socket.
    const index = free_socket(state).?;
    const socket = &state.sockets[index];
    socket.open(descriptor);
    // TCP_NODELAY: a small response leaves at once (design §8 step 13f). A socket that refuses the
    // option is served as it is.
    rotor.sync.set_no_delay(descriptor, true) catch {};
    // A server that is shutting down takes no connection.
    if (state.shut_down or !pump.accept(run, index, state.endpoint_config.tls != null, now_ns)) socket.failed = true;
    state.pending.set(index);
}

/// The index of an entry that can hold a socket.
fn free_socket(state: anytype) ?usize {
    for (&state.sockets, 0..) |*socket, index| {
        if (!socket.live) return index;
    }
    return null;
}

/// Steps every entry a socket or the endpoint named, until none is named.
fn serve(run: anytype, now_ns: u64) void {
    const state = run.server;
    for (0..state.sockets.len * constants.limits.events_per_step_max) |_| {
        const index = state.pending.toggleFirstSet() orelse return;
        serve_entry(run, index, now_ns);
    }
}

/// Steps the socket at `index`: its unread octets go in, and what its connection owes is appended
/// to its output. A socket Rotor has finished with, whose connection has ended, frees its entry.
fn serve_entry(run: anytype, index: usize, now_ns: u64) void {
    const state = run.server;
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
    // The endpoint closed the connection: the socket closes once its octets are out.
    if (state.entries[index].closing) socket.closing = true;
}

/// Submits what each socket this turn changed needs next.
fn arm(state: anytype) void {
    for (0..state.sockets.len) |_| {
        const index = state.touched.toggleFirstSet() orelse return;
        const socket = &state.sockets[index];
        if (socket.live) socket.arm(&state.loop, index);
    }
}

/// Whether the loop may end: the endpoint reported `closed`, and every socket is free.
pub fn finished(state: anytype) bool {
    if (!state.over) return false;
    for (&state.sockets) |*socket| {
        if (socket.live) return false;
    }
    return true;
}
