//! colibri's own host for `.private` (decision 159): with `rotor_host_submit.zig`,
//! `rotor_host_udp.zig`, `rotor_host_end.zig` and `rotor_host_entropy.zig`, the files of `colibri`
//! that import Rotor. It binds, opens and closes the descriptors, runs the loop on the thread that
//! calls `run`, does each operation that the driver writes, and gives back one completion for each
//! Rotor event. The root exports nothing of it.
//!
//! The loop is the host's alone. The low 32 bits of each operation's `user_data` are the driver's
//! `OperationId`, and the high 32 bits are the host's own tag: the kind of the operation, its
//! `SocketId`, and the `Outbound` record of a send. So an event names its socket without a table.
const std = @import("std");
const assert = std.debug.assert;
const rotor = @import("rotor");
const constants = @import("constants.zig");
const host = @import("host.zig");
const errors = @import("errors.zig");
const udp = @import("rotor_host_udp.zig");
const submit_module = @import("rotor_host_submit.zig");
const Family = @import("client_loop.zig").Family;

pub const Kind = std.meta.Tag(host.Operation.Kind);

/// The host's own half of a `user_data`.
const Tag = packed struct(u32) {
    socket: u16,
    outbound: u8,
    kind: u8,
};

/// Where the host's tag starts in a `user_data`: above the driver's id.
const tag_shift = @bitSizeOf(host.OperationId);

/// The `user_data` of an operation: the driver's id, under the host's tag.
pub fn user_data(id: host.OperationId, kind: Kind, socket: host.SocketId, outbound: u8) u64 {
    const tag: Tag = .{ .socket = @intFromEnum(socket), .outbound = outbound, .kind = @intFromEnum(kind) };
    return (@as(u64, @as(u32, @bitCast(tag))) << tag_shift) | @intFromEnum(id);
}

/// The driver's id, the kind and the socket of an event, from its `user_data`.
pub const Tagged = struct { id: host.OperationId, kind: Kind, socket: host.SocketId, outbound: u8 };

pub fn tag_of(event: rotor.Event) Tagged {
    const tag: Tag = @bitCast(@as(u32, @truncate(event.user_data >> tag_shift)));
    return .{
        .id = @enumFromInt(@as(u32, @truncate(event.user_data))),
        .kind = @enumFromInt(tag.kind),
        .socket = @enumFromInt(tag.socket),
        .outbound = tag.outbound,
    };
}

/// Whether a descriptor of the table is open: `closing` is a close that the loop holds, after
/// which the system may give the number to another file.
pub const SocketState = enum { closed, open, closing };

/// The Rotor address of `text`, an IPv4 or IPv6 literal, and `port`.
pub fn address_of(text: []const u8, port: u16) error{HostInvalid}!rotor.Address {
    const parsed = std.Io.net.IpAddress.parse(text, port) catch return error.HostInvalid;
    return switch (parsed) {
        .ip4 => |ip4| rotor.Address.ipv4(ip4.bytes, ip4.port),
        .ip6 => |ip6| rotor.Address.ipv6(ip6.bytes, ip6.port, 0),
    };
}

/// The host of an object with `sockets_max` sockets and `operations_max` operations in flight, and
/// a UDP socket when `datagrams` is set. Its calls are the free functions of this file and of
/// `rotor_host_submit.zig`.
pub fn Host(comptime sockets_max: u16, comptime operations_max: u32, comptime datagrams: bool) type {
    return struct {
        pub const has_datagrams = datagrams;
        pub const loop_options: rotor.Loop.Options = .{ .operations = operations_max };
        /// The operations one turn writes at most: each one that can be in flight, and a cancel
        /// for each socket.
        pub const written_max = operations_max + sockets_max;
        comptime {
            assert(operations_max > 0 and operations_max <= rotor.constants.batch_max);
        }

        loop_memory: [rotor.Loop.memory_bytes(&loop_options)]u8 align(rotor.memory_alignment),
        loop: rotor.Loop,
        events: [operations_max]rotor.Event,
        operations: [written_max]host.Operation,
        descriptors: [sockets_max]rotor.Descriptor,
        states: [sockets_max]SocketState,
        /// The peer that each connect reads until its event (Rotor's rule 3).
        addresses: [sockets_max]rotor.Address,
        /// The operation on each socket that a cancel can name, a connect, an accept or a receive
        /// of datagrams, and its handle.
        cancelable: [sockets_max]host.OperationId,
        handles: [sockets_max]rotor.Handle,
        /// Completions of operations that failed at submit, which a pass gives before its tick.
        refused: [written_max]host.Completion,
        refused_len: u32,
        udp: if (datagrams) udp.Datagrams else void,
        /// The port the listener bound, for `Server.port()`.
        bound_port: u16,

        pub const prepare = host_prepare;
        pub const listen = host_listen;
        pub const bind_datagram = host_bind_datagram;
        pub const bind_datagram_any = host_bind_datagram_any;
        pub const descriptor_of = host_descriptor_of;
        pub const open = host_open;
        pub const opened = host_opened;
        pub const close_open = host_close_open;
        pub const close_ended = host_close_ended;
        pub const begin = host_begin;
        pub const end = @import("rotor_host_end.zig").end;
        pub const run = host_run;
        pub const pass = host_pass;
        pub const submit_turn = host_submit_turn;
        pub const deliver_events = host_deliver_events;
        pub const submit = submit_module.submit;
        pub const refuse = submit_module.refuse;
    };
}

/// Marks every descriptor closed, before `init` opens any.
fn host_prepare(self: anytype) void {
    self.states = @splat(.closed);
    self.cancelable = @splat(@enumFromInt(0));
    self.handles = @splat(rotor.Handle.none);
    self.bound_port = 0;
}

/// Binds the listener `socket` on `text` and `port`, and keeps the port the system chose for port
/// 0. SO_REUSEPORT lets a program run more servers on one port (decision 150 ruling 7).
fn host_listen(self: anytype, socket: host.SocketId, text: []const u8, port: u16) errors.BindError!void {
    const address = try address_of(text, port);
    const listener = try rotor.sync.listen(&address, .{ .backlog = constants.limits.listen_backlog, .reuse_port = true });
    errdefer rotor.sync.close_now(listener);
    const local = try rotor.sync.local_address(listener);
    assert(local.port != 0);
    self.bound_port = local.port;
    self.opened(socket, listener);
}

/// Opens the UDP socket `socket` on `text` and `port`: a server's, on its listener's port.
fn host_bind_datagram(self: anytype, socket: host.SocketId, text: []const u8, port: u16) errors.BindError!void {
    const address = try address_of(text, port);
    assert(address.port == port);
    try open_datagram(self, socket, &address);
}

/// Opens the UDP socket `socket` on every interface of `family`, on a port the system chooses:
/// a client's.
fn host_bind_datagram_any(self: anytype, socket: host.SocketId, family: Family) errors.DatagramBindError!void {
    const address = switch (family) {
        .ipv4 => rotor.Address.ipv4(@splat(0), 0),
        .ipv6 => rotor.Address.ipv6(@splat(0), 0, 0),
    };
    try open_datagram(self, socket, &address);
}

fn open_datagram(self: anytype, socket: host.SocketId, address: *const rotor.Address) errors.DatagramBindError!void {
    const taken = try rotor.sync.open_datagram(address.family, address, udp.socket_options);
    self.opened(socket, taken);
}

/// Records `taken` as the open descriptor of `socket`.
fn host_opened(self: anytype, socket: host.SocketId, taken: rotor.Descriptor) void {
    const index = @intFromEnum(socket);
    assert(self.states[index] == .closed);
    self.descriptors[index] = taken;
    self.states[index] = .open;
}

/// The descriptor of `socket`, which is open.
fn host_descriptor_of(self: anytype, socket: host.SocketId) rotor.Descriptor {
    assert(self.states[@intFromEnum(socket)] == .open);
    return self.descriptors[@intFromEnum(socket)];
}

/// Whether `socket` is open.
fn host_open(self: anytype, socket: host.SocketId) bool {
    return self.states[@intFromEnum(socket)] == .open;
}

/// Closes each descriptor that is open. A descriptor whose close ran is not closed again: the
/// system can give that number to another file of the program.
fn host_close_open(self: anytype) void {
    for (&self.states, &self.descriptors) |*state, held| {
        if (state.* != .open) continue;
        rotor.sync.close_now(held);
        state.* = .closed;
    }
}

/// A close that ended canceled or timed out did not run (Rotor's decision 5, rules 2 and 4), so
/// the descriptor stays open. A close that failed otherwise ran, and the system released the
/// descriptor.
fn host_close_ended(self: anytype, socket: host.SocketId, failure: rotor.Error) void {
    self.states[@intFromEnum(socket)] = switch (failure) {
        error.Canceled, error.Timeout => .open,
        else => .closed,
    };
}

/// Makes the loop on the thread that runs it, gives it the receive buffers, and returns its first
/// instant: the first tick waits for nothing and reads the clock.
fn host_begin(self: anytype) errors.LoopError!u64 {
    const Self = @TypeOf(self.*);
    try self.loop.init(&self.loop_memory, &Self.loop_options);
    errdefer self.end();
    if (Self.has_datagrams) try self.udp.start(&self.loop);
    assert(try self.loop.tick(&self.events, 0) == 0);
    return self.loop.now_ns();
}

/// Runs the driver until `driver.finished(state)`. `run_context` holds the object and the
/// program's handler or router.
fn host_run(self: anytype, run_context: anytype, comptime driver: type, state: anytype) errors.LoopError!void {
    while (!driver.finished(state)) try self.pass(run_context, driver);
}

/// One pass of the loop, in decision 159's order: a turn, a submit of each operation it wrote, a
/// tick that waits as the turn asked, and a completion for each event.
fn host_pass(self: anytype, run_context: anytype, comptime driver: type) errors.LoopError!void {
    const wait_ns = self.submit_turn(run_context, driver, self.loop.now_ns());
    const count = try self.loop.tick(&self.events, wait_ns);
    self.deliver_events(run_context, driver, self.events[0..count], self.loop.now_ns());
}

/// What a pass does before its tick, at `now_ns`: a turn, a submit of each operation it wrote, and
/// the completion of each one that failed at submit. Returns how long the tick waits. It reads no
/// clock, so a test passes its own instant, and no clock decides when a deadline passes.
fn host_submit_turn(self: anytype, run_context: anytype, comptime driver: type, now_ns: u64) u64 {
    const turned = driver.turn(run_context, now_ns, &self.operations);
    self.refused_len = 0;
    for (self.operations[0..turned.operations]) |*operation| self.submit(operation);
    for (self.refused[0..self.refused_len]) |*completion| driver.complete(run_context, completion, now_ns);
    // A completion leaves work for the next turn, which comes before any wait (rule 5).
    return if (self.refused_len > 0) 0 else wait_of(turned.wait, now_ns);
}

/// What a pass does with its tick's `events` at `now_ns`: it gives the driver a completion for
/// each.
fn host_deliver_events(self: anytype, run_context: anytype, comptime driver: type, events: []const rotor.Event, now_ns: u64) void {
    for (events) |event| deliver(self, run_context, driver, event, now_ns);
}

/// How long a tick waits for what the turn asked: no time, until the instant, or the longest
/// wait. The wait stays under `stop_wait_ns_max`, so a `shutdown` from another thread takes effect
/// within it.
pub fn wait_of(wait: host.Wait, now_ns: u64) u64 {
    return switch (wait) {
        .now => 0,
        .at_ns => |at_ns| @min(constants.limits.stop_wait_ns_max, at_ns -| now_ns),
        .none => constants.limits.stop_wait_ns_max,
    };
}

/// Gives the driver the completion of one event. A receive of datagrams gives its buffer back to
/// the loop once the driver has read it.
fn deliver(self: anytype, run_context: anytype, comptime driver: type, event: rotor.Event, now_ns: u64) void {
    // No other loop posts to this one.
    assert(!event.flags.message);
    const tagged = tag_of(event);
    if (tagged.kind == .receive_datagram) {
        if (!@TypeOf(self.*).has_datagrams) unreachable;
        if (self.udp.completion(&self.loop, event, tagged.id)) |completion| driver.complete(run_context, &completion, now_ns);
        return self.udp.give_back(&self.loop, event);
    }
    const completion: host.Completion = .{ .id = tagged.id, .result = result_of(self, tagged, event) };
    driver.complete(run_context, &completion, now_ns);
}

/// The result of the event of one operation that is not a receive of datagrams.
fn result_of(self: anytype, tagged: Tagged, event: rotor.Event) host.Completion.Result {
    if (tagged.kind == .send_datagram) {
        if (!@TypeOf(self.*).has_datagrams) unreachable;
        self.udp.release(tagged.outbound);
    }
    const count = event.outcome() catch |failure| {
        if (tagged.kind == .close) self.close_ended(tagged.socket, failure);
        return udp.result_of_error(failure);
    };
    return switch (tagged.kind) {
        .accept => accepted(self, tagged.socket, @intCast(count)),
        .connect => .connected,
        .receive => .{ .received = count },
        .send => .{ .sent = count },
        .send_datagram => .{ .datagram_sent = count },
        .shutdown_send => .shut_down,
        .close => closed(self, tagged.socket),
        .receive_datagram, .cancel => unreachable,
    };
}

/// Takes the socket an accept delivered into `socket`. TCP_NODELAY: a small response leaves at
/// once (design §8 step 13f). A socket that refuses the option is served as it is.
fn accepted(self: anytype, socket: host.SocketId, taken: rotor.Descriptor) host.Completion.Result {
    rotor.sync.set_no_delay(taken, true) catch {};
    self.opened(socket, taken);
    return .accepted;
}

/// Records that the close of `socket` ran.
fn closed(self: anytype, socket: host.SocketId) host.Completion.Result {
    self.states[@intFromEnum(socket)] = .closed;
    return .closed;
}

const testing = std.testing;

test "design §8 step 42: a tick waits for the turn's instant, and for nothing while work is left" {
    const limit_ns = constants.limits.stop_wait_ns_max;
    try testing.expectEqual(limit_ns, wait_of(.none, 0));
    try testing.expectEqual(limit_ns / 2, wait_of(.{ .at_ns = 3 * limit_ns / 2 }, limit_ns));
    try testing.expectEqual(limit_ns, wait_of(.{ .at_ns = 3 * limit_ns }, 0));
    try testing.expectEqual(0, wait_of(.{ .at_ns = 1 }, 2));
    try testing.expectEqual(0, wait_of(.now, 0));
}

test "decision 159: the host's tag and the driver's id share one user_data" {
    const id: host.OperationId = @enumFromInt(0xab00_0007);
    const data = user_data(id, .send_datagram, @enumFromInt(5), 3);
    try testing.expectEqual(@intFromEnum(id), @as(u32, @truncate(data)));
    const tagged = tag_of(rotor.Event.success(data, 0));
    try testing.expectEqual(id, tagged.id);
    try testing.expectEqual(Kind.send_datagram, tagged.kind);
    try testing.expectEqual(5, @intFromEnum(tagged.socket));
    try testing.expectEqual(3, tagged.outbound);
}
