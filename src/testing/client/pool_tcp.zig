//! The TCP connection of one `client.ConnectionPool` of the test-only client: one socket at a time, opened
//! and closed when the pool asks. `client_loop.zig`'s plain modes hold one for each pool of a
//! run, and `pool_loop.zig`'s pool mode one beside its UDP flow, each on its own Rotor loop.
//!
//! A receive writes into `received`, and its octets are appended to `input` when its event
//! arrives, because the pool moves what is left of `input` and Rotor owns a receive's buffer
//! until its final event. At most one receive and one send are in flight. A socket the pool asks
//! to close sends what it owes first, and an open drops what the last socket read. An open the
//! pool asks for while the last socket is still closing waits for that close's event, so the
//! loop never holds two sockets for one pool.
const std = @import("std");
const assert = std.debug.assert;
const rotor = @import("rotor");
const constants = @import("../constants.zig");

/// What an operation does. It rides in the operation's user data, above the socket's `base`.
pub const Kind = enum(u8) { connect, receive, send, close };

const kinds_count: u64 = @typeInfo(Kind).@"enum".fields.len;

/// What an event meant, which the loop tells the pool.
pub const Happened = enum {
    /// Nothing the pool needs to hear of.
    none,
    /// The connect succeeded, and the pool starts its connection.
    connected,
    /// The socket failed, or the peer closed it, before the pool asked for the close: the
    /// pool hears `transport_closed`.
    failed,
    /// The socket closed, and the open that waited for it, if any, failed to start.
    open_failed,
};

pub const Socket = struct {
    /// The user data of the socket's first operation, which `init` takes. Each operation's user
    /// data is `base` plus its `Kind`. The loop that runs the socket chooses `base`, so that no
    /// other operation of the loop carries one of those values.
    base: u64,
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
    /// The pool asked for the close. The socket closes once its octets are sent, and the pool
    /// hears nothing more of it.
    close_asked: bool,
    /// An open the pool asked for while the last socket was still closing.
    open_pending: ?rotor.Address,

    pub const State = enum { idle, connecting, open, closing };

    pub fn init(socket: *Socket, base: u64) void {
        assert(base <= std.math.maxInt(u64) - kinds_count);
        socket.base = base;
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
    /// when the system gave no socket, which the pool hears as `transport_closed`.
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
        submit(loop, rotor.Operation.connect(socket.user_data(.connect), socket.descriptor, &socket.address));
        return true;
    }

    /// The pool is done with the connection. An open still waiting for the last close is the
    /// one the pool gave up, and it never starts.
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
        assert(socket.owns(event.user_data));
        const kind: Kind = @enumFromInt(event.user_data - socket.base);
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
    /// at its front, and a socket the pool is done with closes.
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

    /// Closes the socket, and says whether the pool must hear that its transport failed: it
    /// must unless it asked for the close. Rotor's close cancels the receive and the send first.
    fn end(socket: *Socket, loop: *rotor.Loop) Happened {
        assert(socket.state == .connecting or socket.state == .open);
        socket.state = .closing;
        submit(loop, rotor.Operation.close(socket.user_data(.close), socket.descriptor));
        return if (socket.close_asked) .none else .failed;
    }

    fn close_when_sent(socket: *Socket, loop: *rotor.Loop) void {
        assert(socket.close_asked);
        if (socket.output_sent == socket.output_len and !socket.sending) _ = socket.end(loop);
    }

    /// Whether the pool's connection writes into the socket and reads from it: it is open, and
    /// the pool has not closed it.
    pub fn carrying(socket: *const Socket) bool {
        return socket.state == .open and !socket.close_asked;
    }

    /// The octets read and not yet consumed.
    pub fn unread(socket: *Socket) []u8 {
        return socket.input[0..socket.input_len];
    }

    /// Drops the `consumed` octets the pool took, moving what is left to the front.
    pub fn consume(socket: *Socket, consumed: usize) void {
        assert(consumed <= socket.input_len);
        const rest = socket.input_len - consumed;
        std.mem.copyForwards(u8, socket.input[0..rest], socket.input[consumed..socket.input_len]);
        socket.input_len = rest;
    }

    /// Where the pool writes what the socket sends next.
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
            submit(loop, rotor.Operation.send(socket.user_data(.send), socket.descriptor, owed));
        }
        const free = socket.input.len - socket.input_len;
        if (!socket.receiving and free > 0) {
            socket.receiving = true;
            const into = socket.received[0..@min(free, socket.received.len)];
            submit(loop, rotor.Operation.receive(socket.user_data(.receive), socket.descriptor, into));
        }
    }

    /// Closes the socket at the end of a run, whatever its state.
    pub fn close_now(socket: *Socket, loop: *rotor.Loop) void {
        socket.open_pending = null;
        if (socket.state == .connecting or socket.state == .open) _ = socket.end(loop);
    }

    /// Whether `user_data_value` is one of the socket's operations'.
    pub fn owns(socket: *const Socket, user_data_value: u64) bool {
        return user_data_value >= socket.base and user_data_value - socket.base < kinds_count;
    }

    fn user_data(socket: *const Socket, kind: Kind) u64 {
        return socket.base + @intFromEnum(kind);
    }
};

/// Submits one operation. The loop that runs the socket keeps room for the operations it has in
/// flight at once, so it always has room.
fn submit(loop: *rotor.Loop, operation: rotor.Operation) void {
    const taken = loop.submit(&.{operation}, &.{});
    assert(taken == 1);
}

const testing = std.testing;

test "the socket's user data lies between the UDP send slots' and the UDP receive's" {
    var socket: Socket = undefined;
    socket.init(constants.pool_udp_send_slots);
    try testing.expectEqual(@as(u64, constants.pool_udp_send_slots), socket.user_data(.connect));
    try testing.expect(socket.owns(socket.user_data(.connect)));
    try testing.expect(socket.owns(socket.user_data(.close)));
    try testing.expect(!socket.owns(constants.pool_udp_send_slots - 1));
    try testing.expect(!socket.owns(socket.user_data(.close) + 1));
    try testing.expect(!socket.owns(std.math.maxInt(u64)));
}
