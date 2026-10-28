//! One socket of the test-only server (`../server.zig`), with no protocol in it: the octets read
//! but not consumed, the octets its connection produced that the socket has not taken yet, and
//! the Rotor operations in flight. `server_worker.zig` holds a worker's sockets, hands each event
//! to the one it names, and passes the octets between a socket and its connection in the
//! worker's session (`server_session.zig`).
//!
//! A socket has two receive buffers. A receive writes into the one that holds no unread octets,
//! because Rotor owns a receive's buffer until its final event (its rule 3). When its event
//! arrives and nothing was left unread, that buffer becomes the input, and no octet moves. Only
//! octets left unread, such as half a frame, take a copy: the new ones are appended to them. The
//! session consumes the input from the front by moving `input_start`.
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

/// The unread octets a socket holds at most: one receive buffer's.
const input_capacity = constants.wire_read_len;
/// A socket's receive buffers: the input, and the one the receive in flight writes.
const receive_buffers = 2;

/// One socket a worker holds. Over TLS, `input` and `output` hold records.
pub const Socket = struct {
    descriptor: rotor.Descriptor,
    /// The two receive buffers (see the header). `buffers[input_at]` holds the input, and a
    /// receive writes into the other one.
    buffers: [receive_buffers][constants.wire_read_len]u8,
    input_at: u1,
    /// Where the unread octets start in the input, and how many there are.
    input_start: usize,
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
        socket.input_at = 0;
        socket.input_start = 0;
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

    /// Takes what a receive read as input. A receive of no octets is the peer closing its side,
    /// and a failed one ends the socket the same way: it is `failed` then.
    pub fn on_received(socket: *Socket, event: rotor.Event) void {
        socket.receiving = false;
        const read: usize = @intCast(event.outcome() catch 0);
        if (read == 0) {
            socket.failed = true;
            return;
        }
        assert(read <= input_capacity - socket.input_len);
        const arrived = socket.receive_buffer()[0..read];
        // Nothing was left unread, so the buffer the receive wrote is the input now.
        if (socket.input_len == 0) {
            socket.input_at = ~socket.input_at;
            socket.input_start = 0;
            socket.input_len = read;
            return;
        }
        socket.append(arrived);
    }

    /// Appends `arrived` to the unread octets, which first move to the front of the input when
    /// they leave too little room after them.
    fn append(socket: *Socket, arrived: []const u8) void {
        const input = &socket.buffers[socket.input_at];
        if (socket.input_start + socket.input_len + arrived.len > input.len) {
            std.mem.copyForwards(u8, input, input[socket.input_start..][0..socket.input_len]);
            socket.input_start = 0;
        }
        @memcpy(input[socket.input_start + socket.input_len ..][0..arrived.len], arrived);
        socket.input_len += arrived.len;
    }

    /// Where the next receive writes: the buffer that is not the input.
    pub fn receive_buffer(socket: *Socket) *[constants.wire_read_len]u8 {
        return &socket.buffers[~socket.input_at];
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
        return socket.buffers[socket.input_at][socket.input_start..][0..socket.input_len];
    }

    /// Drops the `consumed` octets the connection took. No octet moves.
    pub fn consume(socket: *Socket, consumed: usize) void {
        assert(consumed <= socket.input_len);
        socket.input_start += consumed;
        socket.input_len -= consumed;
        if (socket.input_len == 0) socket.input_start = 0;
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
        const free = input_capacity - socket.input_len;
        if (!socket.receiving and !socket.closing and free > 0) socket.submit(loop, index, .receive);
    }

    /// Submits one operation. The loop holds one of each kind for every socket, so it always has
    /// room.
    fn submit(socket: *Socket, loop: *rotor.Loop, index: usize, kind: Kind) void {
        const operation = switch (kind) {
            .receive => blk: {
                const free = input_capacity - socket.input_len;
                socket.receiving = true;
                break :blk rotor.Operation.receive(user_data(index, kind), socket.descriptor, socket.receive_buffer()[0..free]);
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

const testing = std.testing;

/// The socket the tests drive, outside any stack frame: its buffers are larger than one should
/// hold. Test-only.
var test_socket: Socket align(@alignOf(Socket)) = undefined;

/// Delivers `octets` as the receive in flight read them. Test-only.
fn test_receive(octets: []const u8) void {
    @memcpy(test_socket.receive_buffer()[0..octets.len], octets);
    test_socket.on_received(rotor.Event.success(user_data(0, .receive), @intCast(octets.len)));
}

test "a receive read into the empty side becomes the input, and the next one writes the other side" {
    test_socket.open(0);
    const first = test_socket.receive_buffer();
    test_receive("GET / HTTP/1.1\r\n");
    try testing.expectEqualStrings("GET / HTTP/1.1\r\n", test_socket.unread());
    // The octets stayed where the receive wrote them.
    try testing.expectEqual(@intFromPtr(first), @intFromPtr(test_socket.unread().ptr));
    try testing.expect(test_socket.receive_buffer() != first);
    test_socket.consume(4);
    try testing.expectEqualStrings("/ HTTP/1.1\r\n", test_socket.unread());
    test_socket.consume(test_socket.unread().len);
    try testing.expectEqual(0, test_socket.input_start);
}

test "octets left unread take the next receive after them, moved to the front when they must" {
    test_socket.open(0);
    test_receive("abcdef");
    test_socket.consume(4);
    // "ef" is left unread, so the next receive is appended to it.
    test_receive("gh");
    try testing.expectEqualStrings("efgh", test_socket.unread());
    // A receive that fills what is left of the input moves the unread octets to its front first.
    const fill_len = input_capacity - test_socket.input_len;
    @memset(test_socket.receive_buffer()[0..fill_len], 'z');
    test_socket.on_received(rotor.Event.success(user_data(0, .receive), @intCast(fill_len)));
    try testing.expectEqual(input_capacity, test_socket.unread().len);
    try testing.expectEqualStrings("efghz", test_socket.unread()[0..5]);
    try testing.expectEqual('z', test_socket.unread()[input_capacity - 1]);
}
