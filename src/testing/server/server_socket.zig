//! One socket of the test-only server (`../server.zig`), with no protocol in it: the octets read
//! but not consumed, the octets its connection produced that the socket has not taken yet, and
//! the Rotor operations in flight. `server_worker.zig` holds a worker's sockets, hands each event
//! to the one it names, and passes the octets between a socket and its connection in the
//! worker's session (`server_session.zig`).
//!
//! A receive writes into `received`, and its octets are appended to `input` when its event
//! arrives. The session consumes `input` from the front, which moves what is left, and Rotor owns
//! a receive's buffer until its final event (its rule 3), so a receive never targets `input`.
//! A send reads `output[output_sent..output_len]`, and the session only appends after that.
//!
//! A socket outlives its connection. The endpoint frees a connection's slot as soon as it has
//! reported its `close`, while the socket still sends the last octets and waits for the final
//! event of each operation, so the socket is free for another connection only after those.
const std = @import("std");
const assert = std.debug.assert;
const rotor = @import("rotor");
const constants = @import("../constants.zig");

/// What an operation a socket has in flight does. It rides in the operation's user data, below
/// the socket's index.
pub const Kind = enum(u8) { receive, send, close };
pub const kind_bits = @bitSizeOf(Kind);

/// The operations a loop holds in flight for each socket: a receive, a send and a close.
pub const operations_per_socket: u32 = @typeInfo(Kind).@"enum".fields.len;

/// The user data of the operation of `kind` the socket at `index` has in flight.
pub fn user_data(index: usize, kind: Kind) u64 {
    return (@as(u64, index) << kind_bits) | @intFromEnum(kind);
}

/// One socket a worker holds. Over TLS, `input` and `output` hold records.
pub const Socket = struct {
    descriptor: rotor.Descriptor,
    /// Where the receive in flight writes (see the header).
    received: [constants.wire_read_len]u8,
    input: [constants.wire_read_len]u8,
    input_len: usize,
    output: [constants.write_buffer_len]u8,
    /// Octets of `output` the connection has produced.
    output_len: usize,
    /// Octets of `output` the socket has taken, which are always the first ones.
    output_sent: usize,
    /// The operations in flight. The socket is free again once it is closed and none is.
    receiving: bool,
    sending: bool,
    close_submitted: bool,
    closed: bool,
    /// Whether this entry holds a socket.
    live: bool,
    /// Whether the endpoint closed the connection, so the octets left are the last the peer gets.
    closing: bool,
    /// Whether the socket closes now, with nothing more sent: the peer left or a call failed.
    failed: bool,

    /// Takes the socket `descriptor` names, with nothing read, written or in flight.
    pub fn open(socket: *Socket, descriptor: rotor.Descriptor) void {
        socket.descriptor = descriptor;
        socket.input_len = 0;
        socket.output_len = 0;
        socket.output_sent = 0;
        socket.receiving = false;
        socket.sending = false;
        socket.close_submitted = false;
        socket.closed = false;
        socket.closing = false;
        socket.failed = false;
        socket.live = true;
    }

    /// Appends what a receive read to the input. A receive of no octets is the peer closing its
    /// side, and a failed one ends the socket the same way: it is `failed` then.
    pub fn on_received(socket: *Socket, event: rotor.Event) void {
        socket.receiving = false;
        const read = event.outcome() catch 0;
        if (read == 0) {
            socket.failed = true;
            return;
        }
        assert(read <= socket.input.len - socket.input_len);
        @memcpy(socket.input[socket.input_len..][0..read], socket.received[0..read]);
        socket.input_len += read;
    }

    /// Counts what a send took. A send that failed leaves the socket `failed`.
    pub fn on_sent(socket: *Socket, event: rotor.Event) void {
        socket.sending = false;
        const sent = event.outcome() catch {
            socket.failed = true;
            return;
        };
        socket.output_sent += sent;
        assert(socket.output_sent <= socket.output_len);
        // Every octet is gone and no send is in flight, so the buffer starts again at its front.
        if (socket.output_sent == socket.output_len) {
            socket.output_len = 0;
            socket.output_sent = 0;
        }
    }

    /// Whether Rotor has closed the socket and delivered the final event of each operation (its
    /// rule 1), so the entry can hold another socket.
    pub fn finished(socket: *const Socket) bool {
        return socket.closed and !socket.receiving and !socket.sending;
    }

    /// Whether the socket carries octets no more: it failed, or its close is on its way.
    pub fn stopped(socket: *const Socket) bool {
        return socket.failed or socket.close_submitted;
    }

    /// The octets read and not yet consumed.
    pub fn unread(socket: *Socket) []u8 {
        return socket.input[0..socket.input_len];
    }

    /// Drops the `consumed` octets the connection took, moving what is left to the front.
    pub fn consume(socket: *Socket, consumed: usize) void {
        assert(consumed <= socket.input_len);
        if (consumed == 0) return;
        std.mem.copyForwards(u8, &socket.input, socket.input[consumed..socket.input_len]);
        socket.input_len -= consumed;
    }

    /// Where the connection writes what the socket sends next.
    pub fn room(socket: *Socket) []u8 {
        return socket.output[socket.output_len..];
    }

    pub fn wrote(socket: *Socket, written: usize) void {
        assert(written <= socket.output.len - socket.output_len);
        socket.output_len += written;
    }

    /// Submits what the socket needs next: its close once it is failed or closing and drained,
    /// otherwise a send of what is owed and a receive while there is room for more. `index` is
    /// where its worker holds it, which each operation's user data names.
    pub fn arm(socket: *Socket, loop: *rotor.Loop, index: usize) void {
        if (socket.close_submitted) return;
        const drained = socket.output_sent == socket.output_len;
        if (socket.failed or (socket.closing and drained)) return socket.submit(loop, index, .close);
        if (!socket.sending and !drained) socket.submit(loop, index, .send);
        const free = socket.input.len - socket.input_len;
        if (!socket.receiving and !socket.closing and free > 0) socket.submit(loop, index, .receive);
    }

    /// Submits one operation. The loop holds one of each kind for every socket, so it always has
    /// room.
    fn submit(socket: *Socket, loop: *rotor.Loop, index: usize, kind: Kind) void {
        const operation = switch (kind) {
            .receive => blk: {
                const free = socket.input.len - socket.input_len;
                socket.receiving = true;
                break :blk rotor.Operation.receive(user_data(index, kind), socket.descriptor, socket.received[0..@min(free, socket.received.len)]);
            },
            .send => blk: {
                socket.sending = true;
                break :blk rotor.Operation.send(user_data(index, kind), socket.descriptor, socket.output[socket.output_sent..socket.output_len]);
            },
            // Rotor's close cancels the socket's receive and send first.
            .close => blk: {
                socket.close_submitted = true;
                break :blk rotor.Operation.close(user_data(index, kind), socket.descriptor);
            },
        };
        const taken = loop.submit(&.{operation}, &.{});
        assert(taken == 1);
    }
};
