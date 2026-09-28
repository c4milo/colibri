//! The TCP connection of the test-only client's origin mode (`origin_loop.zig`): one socket at a
//! time, on the loop the UDP flow runs on, opened and closed when `client.Origin` asks.
//!
//! As in `client_loop.zig`, a receive writes into `received` and its octets are appended to
//! `input` when its event arrives, and at most one receive and one send are in flight. A socket the
//! origin asks to close sends what it owes first. An open the origin asks for while the last socket
//! is still closing waits for that close's event, so the loop never holds two sockets.
const std = @import("std");
const assert = std.debug.assert;
const rotor = @import("rotor");
const constants = @import("../constants.zig");

/// What an operation does. It rides in the operation's user data, above `user_data_base`.
pub const Kind = enum(u8) { connect, receive, send, close };

/// The user data of the socket's operations: just above the index of every UDP send slot, and far
/// below the UDP receive's.
pub const user_data_base: u64 = constants.origin_udp_send_slots;

/// What an event meant, which the loop tells the origin.
pub const Happened = enum {
    /// Nothing the origin needs to hear of.
    none,
    /// The connect succeeded, and the origin starts its connection.
    connected,
    /// The socket failed, or the peer closed it, before the origin asked for the close: the origin
    /// hears `transport_closed`.
    failed,
    /// The socket closed, and the open that waited for it, if any, failed to start.
    open_failed,
};

pub const Socket = struct {
    state: State,
    descriptor: rotor.Descriptor,
    /// The peer, which the connect in flight reads until its event (Rotor's rule 3).
    address: rotor.Address,
    received: [constants.wire_read_len]u8,
    /// Over TLS its octets are records, and `input` and `output` hold them as they cross the
    /// socket, so each holds a whole record.
    input: [constants.wire_read_len]u8,
    input_len: usize,
    output: [constants.write_buffer_len]u8,
    output_len: usize,
    output_sent: usize,
    receiving: bool,
    sending: bool,
    /// The origin asked for the close. The socket closes once its octets are sent, and the origin
    /// hears nothing more of it.
    close_asked: bool,
    /// An open the origin asked for while the last socket was still closing.
    open_pending: ?rotor.Address,

    pub const State = enum { idle, connecting, open, closing };

    pub fn init(socket: *Socket) void {
        socket.state = .idle;
        socket.open_pending = null;
        socket.reset();
    }

    fn reset(socket: *Socket) void {
        socket.input_len = 0;
        socket.output_len = 0;
        socket.output_sent = 0;
        socket.receiving = false;
        socket.sending = false;
        socket.close_asked = false;
    }

    /// Opens a socket to `to` and starts its connect, or waits for the last socket's close. False
    /// when the system gave no socket, which the origin hears as `transport_closed`.
    pub fn open(socket: *Socket, loop: *rotor.Loop, to: rotor.Address) bool {
        assert(socket.open_pending == null);
        if (socket.state != .idle) {
            socket.open_pending = to;
            return true;
        }
        socket.reset();
        socket.address = to;
        socket.descriptor = rotor.sync.open_socket(to.family) catch return false;
        socket.state = .connecting;
        submit(loop, rotor.Operation.connect(user_data(.connect), socket.descriptor, &socket.address));
        return true;
    }

    /// The origin is done with the connection. An open still waiting for the last close is the
    /// one the origin gave up, and it never starts.
    pub fn close(socket: *Socket, loop: *rotor.Loop) void {
        if (socket.open_pending != null) {
            socket.open_pending = null;
            return;
        }
        switch (socket.state) {
            .idle, .closing => {},
            // The connect's event closes the socket.
            .connecting => socket.close_asked = true,
            .open => {
                socket.close_asked = true;
                socket.close_when_sent(loop);
            },
        }
    }

    /// Does what an event of the socket's asks, and says what it meant.
    pub fn on_event(socket: *Socket, loop: *rotor.Loop, event: rotor.Event) Happened {
        const kind: Kind = @enumFromInt(event.user_data - user_data_base);
        return switch (kind) {
            .connect => socket.on_connected(loop, event),
            .receive => socket.on_received(loop, event),
            .send => socket.on_sent(loop, event),
            .close => socket.on_closed(loop),
        };
    }

    fn on_connected(socket: *Socket, loop: *rotor.Loop, event: rotor.Event) Happened {
        assert(socket.state == .connecting);
        if (socket.close_asked) return socket.end(loop);
        _ = event.outcome() catch return socket.end(loop);
        socket.state = .open;
        return .connected;
    }

    /// Appends what a receive read to the input. A receive of no octets is the peer closing its
    /// side.
    fn on_received(socket: *Socket, loop: *rotor.Loop, event: rotor.Event) Happened {
        socket.receiving = false;
        if (socket.state != .open) return .none;
        const read = event.outcome() catch return socket.end(loop);
        if (read == 0) return socket.end(loop);
        assert(read <= socket.input.len - socket.input_len);
        @memcpy(socket.input[socket.input_len..][0..read], socket.received[0..read]);
        socket.input_len += read;
        return .none;
    }

    /// Counts what a send took. Every octet gone and no send in flight, the buffer starts again
    /// at its front, and a socket the origin is done with closes.
    fn on_sent(socket: *Socket, loop: *rotor.Loop, event: rotor.Event) Happened {
        socket.sending = false;
        if (socket.state != .open) return .none;
        const sent = event.outcome() catch return socket.end(loop);
        socket.output_sent += sent;
        assert(socket.output_sent <= socket.output_len);
        if (socket.output_sent == socket.output_len) {
            socket.output_len = 0;
            socket.output_sent = 0;
        }
        if (socket.close_asked) socket.close_when_sent(loop);
        return .none;
    }

    /// The socket closed, so the open that waited for it starts.
    fn on_closed(socket: *Socket, loop: *rotor.Loop) Happened {
        assert(socket.state == .closing);
        socket.state = .idle;
        const pending = socket.open_pending orelse return .none;
        socket.open_pending = null;
        return if (socket.open(loop, pending)) .none else .open_failed;
    }

    /// Closes the socket, and says whether the origin must hear that its transport failed: it
    /// must unless it asked for the close. Rotor's close cancels the receive and the send first.
    fn end(socket: *Socket, loop: *rotor.Loop) Happened {
        assert(socket.state == .connecting or socket.state == .open);
        socket.state = .closing;
        submit(loop, rotor.Operation.close(user_data(.close), socket.descriptor));
        return if (socket.close_asked) .none else .failed;
    }

    fn close_when_sent(socket: *Socket, loop: *rotor.Loop) void {
        assert(socket.close_asked);
        if (socket.output_sent == socket.output_len and !socket.sending) _ = socket.end(loop);
    }

    /// Whether the origin's connection writes into the socket and reads from it: it is open, and
    /// the origin has not closed it.
    pub fn carrying(socket: *const Socket) bool {
        return socket.state == .open and !socket.close_asked;
    }

    /// The octets read and not yet consumed.
    pub fn unread(socket: *Socket) []u8 {
        return socket.input[0..socket.input_len];
    }

    /// Drops the `consumed` octets the origin took, moving what is left to the front.
    pub fn consume(socket: *Socket, consumed: usize) void {
        assert(consumed <= socket.input_len);
        const rest = socket.input_len - consumed;
        std.mem.copyForwards(u8, socket.input[0..rest], socket.input[consumed..socket.input_len]);
        socket.input_len = rest;
    }

    /// Where the origin writes what the socket sends next.
    pub fn room(socket: *Socket) []u8 {
        return socket.output[socket.output_len..];
    }

    pub fn wrote(socket: *Socket, written: usize) void {
        assert(written <= socket.output.len - socket.output_len);
        socket.output_len += written;
    }

    /// Submits a send of what is owed and a receive while there is room for more.
    pub fn arm(socket: *Socket, loop: *rotor.Loop) void {
        if (socket.state != .open) return;
        if (!socket.sending and socket.output_sent < socket.output_len) {
            socket.sending = true;
            const owed = socket.output[socket.output_sent..socket.output_len];
            submit(loop, rotor.Operation.send(user_data(.send), socket.descriptor, owed));
        }
        const free = socket.input.len - socket.input_len;
        if (!socket.receiving and free > 0) {
            socket.receiving = true;
            const into = socket.received[0..@min(free, socket.received.len)];
            submit(loop, rotor.Operation.receive(user_data(.receive), socket.descriptor, into));
        }
    }

    /// Closes the socket at the end of a run, whatever its state.
    pub fn close_now(socket: *Socket, loop: *rotor.Loop) void {
        socket.open_pending = null;
        if (socket.state == .connecting or socket.state == .open) _ = socket.end(loop);
    }
};

/// Whether `user_data` is one of the socket's operations'.
pub fn owns(user_data_value: u64) bool {
    return user_data_value >= user_data_base and user_data_value - user_data_base < @typeInfo(Kind).@"enum".fields.len;
}

fn user_data(kind: Kind) u64 {
    return user_data_base + @intFromEnum(kind);
}

/// Submits one operation. The loop keeps `origin_tcp_operations_max` of its operations for the
/// socket, so it always has room.
fn submit(loop: *rotor.Loop, operation: rotor.Operation) void {
    const taken = loop.submit(&.{operation}, &.{});
    assert(taken == 1);
}

const testing = std.testing;

test "the socket's user data lies between the UDP send slots' and the UDP receive's" {
    try testing.expect(owns(user_data(.connect)) and owns(user_data(.close)));
    try testing.expect(!owns(constants.origin_udp_send_slots - 1));
    try testing.expect(!owns(std.math.maxInt(u64)));
}
