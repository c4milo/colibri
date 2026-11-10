//! How colibri's own Rotor host does each operation the driver writes (decision 159): it opens
//! a client's socket at its connect, finds each descriptor in its table, and submits the Rotor
//! operation under the `user_data` that names the driver's id and the host's tag
//! (`rotor_host.zig`). The loop holds every operation the driver can have in flight, so it takes
//! each one but a send of datagrams, which it may refuse.
const std = @import("std");
const assert = std.debug.assert;
const rotor = @import("rotor");
const host = @import("host.zig");
const rotor_host = @import("rotor_host.zig");
const udp = @import("rotor_host_udp.zig");

const user_data = rotor_host.user_data;

/// Submits one operation the driver wrote. One that fails before the loop takes it gets its
/// completion from `refuse`, and the pass gives it to the driver before its tick.
pub fn submit(self: anytype, operation: *const host.Operation) void {
    const id = operation.id;
    switch (operation.kind) {
        .connect => |connect| submit_connect(self, id, connect.socket, connect.address),
        .accept => |accept| {
            assert(self.states[@intFromEnum(accept.into)] == .closed);
            const data = user_data(id, .accept, accept.into, 0);
            const taken = rotor.Operation.accept(data, self.descriptor_of(accept.listener));
            submit_one(self, taken, .{ .socket = accept.listener, .id = id });
        },
        .receive => |receive| {
            const data = user_data(id, .receive, receive.socket, 0);
            submit_one(self, rotor.Operation.receive(data, self.descriptor_of(receive.socket), receive.buffer), null);
        },
        .send => |send| {
            const data = user_data(id, .send, send.socket, 0);
            submit_one(self, rotor.Operation.send(data, self.descriptor_of(send.socket), send.bytes), null);
        },
        // RFC 9112 §9.6: the write side closes, and the receive on the socket goes on.
        .shutdown_send => |shutdown| {
            const data = user_data(id, .shutdown_send, shutdown.socket, 0);
            submit_one(self, rotor.Operation.shutdown(data, self.descriptor_of(shutdown.socket), .send), null);
        },
        .close => |close| submit_close(self, id, close.socket),
        .receive_datagram => |receive| submit_receive_datagram(self, id, receive.socket),
        .send_datagram => |send| submit_send_datagram(self, id, send),
        .cancel => |canceled| cancel(self, canceled.target),
    }
}

/// Records a completion of an operation that failed before the loop took it.
pub fn refuse(self: anytype, id: host.OperationId, result: host.Completion.Result) void {
    self.refused[self.refused_len] = .{ .id = id, .result = result };
    self.refused_len += 1;
}

const Cancelable = struct { socket: host.SocketId, id: host.OperationId };

/// Submits one operation, and keeps its handle when a cancel can name it.
fn submit_one(self: anytype, operation: rotor.Operation, cancelable: ?Cancelable) void {
    var handles: [1]rotor.Handle = undefined;
    const taken = self.loop.submit(&.{operation}, &handles);
    assert(taken == 1);
    const named = cancelable orelse return;
    self.cancelable[@intFromEnum(named.socket)] = named.id;
    self.handles[@intFromEnum(named.socket)] = handles[0];
}

/// Opens a TCP socket of the address's family with Nagle's algorithm off (TCP_NODELAY), so a small
/// request leaves at once, and connects it. A socket the system refuses ends the connect at once.
fn submit_connect(self: anytype, id: host.OperationId, socket: host.SocketId, address: anytype) void {
    const index = @intFromEnum(socket);
    assert(self.states[index] == .closed);
    self.addresses[index] = udp.rotor_address(address);
    const taken = rotor.sync.open_socket(self.addresses[index].family) catch |failure| {
        return self.refuse(id, .{ .failed = if (failure == error.AddressFamilyUnsupported) .family_unsupported else .other });
    };
    // A socket that refuses the option is used as it is.
    rotor.sync.set_no_delay(taken, true) catch {};
    self.opened(socket, taken);
    const data = user_data(id, .connect, socket, 0);
    submit_one(self, rotor.Operation.connect(data, taken, &self.addresses[index]), .{ .socket = socket, .id = id });
}

/// Closes `socket`. Rotor's close ends the socket's receive and send first. A connect whose socket
/// the system refused opened nothing, so its close has nothing to close.
fn submit_close(self: anytype, id: host.OperationId, socket: host.SocketId) void {
    if (!self.open(socket)) return self.refuse(id, .closed);
    const closed = self.descriptor_of(socket);
    self.states[@intFromEnum(socket)] = .closing;
    submit_one(self, rotor.Operation.close(user_data(id, .close, socket, 0), closed), null);
}

/// Starts the multishot receive of datagrams into the host's group.
fn submit_receive_datagram(self: anytype, id: host.OperationId, socket: host.SocketId) void {
    if (!@TypeOf(self.*).has_datagrams) unreachable;
    const data = user_data(id, .receive_datagram, socket, 0);
    submit_one(self, self.udp.receive(data, self.descriptor_of(socket)), .{ .socket = socket, .id = id });
}

/// Submits a send of datagrams. A send the loop has no room for fails, and its datagrams are lost
/// on the way, as on a path that drops them (RFC 9002 §6 recovers them).
fn submit_send_datagram(self: anytype, id: host.OperationId, send: anytype) void {
    if (!@TypeOf(self.*).has_datagrams) unreachable;
    const index = self.udp.take_outbound(send) orelse return self.refuse(id, .{ .failed = .other });
    const data = user_data(id, .send_datagram, send.socket, index);
    const operation = self.udp.send(data, self.descriptor_of(send.socket), send.bytes, index);
    if (self.loop.submit(&.{operation}, &.{}) == 1) return;
    self.udp.release(index);
    self.refuse(id, .{ .failed = .other });
}

/// Cancels the operation `target` names. A target that ended names nothing, and a stale handle is
/// legal (Rotor's decision 5, rule 2).
fn cancel(self: anytype, target: host.OperationId) void {
    for (self.cancelable, self.handles) |id, handle| {
        if (!handle.is_none() and id == target) return self.loop.cancel(handle);
    }
}
