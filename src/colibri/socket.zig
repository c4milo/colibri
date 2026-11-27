//! One TCP socket of a `colibri.Server` or a `colibri.Client`, with no protocol and no I/O in
//! it: the bytes read but not consumed, the bytes the next send writes, and the operations in
//! flight. The driver hands each completion to the socket it names, and `server_pump.zig` passes
//! the bytes between a socket and its connection. Moved from the test-only server's
//! `server_socket.zig` for design §8 step 37b. Its host does the I/O (decision 159).
//!
//! A socket has one input buffer (design §8 step 60). A receive writes into the bytes free after
//! the unread ones, and the host owns them until its completion (decision 159, rule 1). The
//! session consumes the input from the front by moving `input_start`, also while a receive is in
//! flight, so what arrives always follows the unread bytes. Bytes left unread, such as half a
//! frame, move to the front only before the next receive is written, when no receive owns the
//! buffer.
//!
//! A socket holds no output (design §8 step 79). Its driver gives it the bytes a send writes,
//! in `outgoing`: a client's from the buffer of `socket_output.zig`, and a server's from what its
//! engine lends with `output_stream` (decision 176). They stay where they are until the send's
//! completion, and `on_sent` gives the driver the count to hand back.
//!
//! A socket outlives its connection. The engine frees a connection's slot once it has reported
//! its `ended`, which waits for the lent send's completion. The socket still waits for the final
//! completion of each other operation, so it is free for another connection only after those.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const host = @import("host.zig");
const operation_table = @import("operation_table.zig");

/// What an operation a socket has in flight does. A client's socket connects (design §8 step 42),
/// and a server's comes from its listener. A server's socket closes its write side for a staged
/// close (decision 160).
pub const Kind = enum(u8) { receive, send, close, shutdown, connect };

/// The slots of the driver's operation table that each socket holds: one for each kind. Socket
/// `index` holds the slots from `index * slots_per_socket` (`operation_table.zig`).
pub const slots_per_socket: u32 = @typeInfo(Kind).@"enum".fields.len;

/// The operations a server's socket holds in flight at once: a receive, a send, a close and the
/// shutdown of its write side. A connect is in flight before the socket receives or sends, alone
/// or with the close that cancels it, so it takes no more room.
pub const operations_per_socket: u32 = slots_per_socket - 1;

/// The operations a client's socket holds in flight at once. A client never closes its write
/// side alone, so it holds no shutdown.
pub const client_operations_per_socket: u32 = operations_per_socket - 1;

comptime {
    // The connect is the one kind that is never in flight beside a receive or a send.
    const fields = @typeInfo(Kind).@"enum".fields;
    assert(std.mem.eql(u8, fields[fields.len - 1].name, "connect"));
}

/// The slot of the operation of `kind` that the socket at `index` holds.
pub fn slot_of(index: usize, kind: Kind) u32 {
    return @intCast(index * slots_per_socket + @intFromEnum(kind));
}

/// The count a completion carries, or null for a failure or a cancel.
pub fn count_of(result: host.Completion.Result) ?u32 {
    return switch (result) {
        .received => |count| count,
        .sent => |count| count,
        else => null,
    };
}

/// The unread bytes a socket holds at most: its input buffer's.
const input_capacity = constants.limits.socket_input_len;

/// One socket a driver holds. Over TLS, `input` and `outgoing` hold records.
pub const Socket = struct {
    /// The input buffer (see the header): the unread bytes, and after them the bytes a receive
    /// writes.
    input: [constants.limits.socket_input_len]u8,
    /// Where the unread bytes start in the input, and how many there are.
    input_start: usize,
    input_len: usize,
    /// The bytes the next send writes, or the send in flight writes, which the driver gave (see
    /// the header). Empty once a send's completion came.
    outgoing: []const u8,
    /// The operations in flight. The socket is free again once it is closed and none is.
    receiving: bool,
    sending: bool,
    close_submitted: bool,
    closed: bool,
    /// Whether this entry holds a socket.
    live: bool,
    /// Whether the engine closed the connection, so the bytes left are the last the peer gets.
    closing: bool,
    /// Whether the engine asked for a half-close: once the bytes left are out, the socket's
    /// write side closes and its receives go on (RFC 9112 §9.6, decision 160).
    half_closing: bool,
    /// Whether the shutdown of the write side was written, and whether it is in flight.
    shutdown_submitted: bool,
    shutting_down: bool,
    /// Whether the socket closes now, with nothing more sent: the peer left or a call failed.
    failed: bool,

    /// Takes a socket with nothing read, written or in flight. The host holds its descriptor.
    pub fn open(socket: *Socket) void {
        socket.input_start = 0;
        socket.input_len = 0;
        socket.outgoing = &.{};
        socket.receiving = false;
        socket.sending = false;
        socket.close_submitted = false;
        socket.closed = false;
        socket.closing = false;
        socket.half_closing = false;
        socket.shutdown_submitted = false;
        socket.shutting_down = false;
        socket.failed = false;
        socket.live = true;
    }

    /// Takes what a receive read as input. A receive of no bytes is the peer closing its side,
    /// and a failed one ends the socket the same way: it is `failed` then.
    pub fn on_received(socket: *Socket, result: host.Completion.Result) void {
        socket.receiving = false;
        const read: usize = count_of(result) orelse 0;
        if (read == 0) {
            socket.failed = true;
            return;
        }
        // The receive wrote right after the unread bytes: a consume moves their start and
        // their count together, so their end stayed where the receive began.
        assert(socket.input_start + socket.input_len + read <= input_capacity);
        socket.input_len += read;
    }

    /// Where the next receive writes: the bytes free after the unread ones, which first move to
    /// the front of the input. No receive is in flight, so no byte the host owns moves.
    pub fn receive_buffer(socket: *Socket) []u8 {
        assert(!socket.receiving);
        if (socket.input_start > 0) {
            @memmove(socket.input[0..socket.input_len], socket.input[socket.input_start..][0..socket.input_len]);
            socket.input_start = 0;
        }
        return socket.input[socket.input_len..];
    }

    /// The bytes the receive in flight writes: those free after the unread ones.
    pub fn receive_target(socket: *Socket) []u8 {
        assert(socket.receiving);
        return socket.input[socket.input_start + socket.input_len ..];
    }

    /// Takes the bytes the next send writes. They stay where they are until its completion. Before
    /// the send starts, a new gift holds the earlier one from the same front, and more.
    pub fn give(socket: *Socket, octets: []const u8) void {
        assert(!socket.sending);
        assert(socket.outgoing.len == 0 or (octets.ptr == socket.outgoing.ptr and octets.len >= socket.outgoing.len));
        socket.outgoing = octets;
    }

    /// Ends the send in flight, and returns the bytes it took: 0 for a send that failed, which
    /// leaves the socket `failed`. The driver hands the count back to whoever gave the bytes.
    pub fn on_sent(socket: *Socket, result: host.Completion.Result) usize {
        assert(socket.sending);
        socket.sending = false;
        const given = socket.outgoing.len;
        socket.outgoing = &.{};
        const sent: usize = count_of(result) orelse {
            socket.failed = true;
            return 0;
        };
        assert(sent <= given);
        return sent;
    }

    /// Drops bytes that the driver gave and no send took, and returns how many it held: the
    /// socket stopped before it wrote their send.
    pub fn drop_unsent(socket: *Socket) usize {
        if (socket.sending) return 0;
        const given = socket.outgoing.len;
        socket.outgoing = &.{};
        return given;
    }

    /// Whether the write side closes now: the engine closes the connection in stages, and the
    /// bytes left are out (RFC 9112 §9.6, decision 160).
    pub fn half_close_due(socket: *const Socket) bool {
        if (!socket.half_closing or socket.shutdown_submitted or socket.stopped()) return false;
        return !socket.sending and socket.outgoing.len == 0;
    }

    /// Takes the end of the shutdown of the write side. One that failed, or that a close ended,
    /// leaves the socket `failed`.
    pub fn on_shut_down(socket: *Socket, result: host.Completion.Result) void {
        assert(socket.shutting_down);
        socket.shutting_down = false;
        if (result != .shut_down) socket.failed = true;
    }

    /// Whether the host has closed the socket and given the final completion of each operation
    /// (decision 159, rule 2), so the entry can hold another socket.
    pub fn finished(socket: *const Socket) bool {
        return socket.closed and !socket.receiving and !socket.sending and !socket.shutting_down;
    }

    /// Whether the socket carries bytes no more: it failed, or its close is on its way.
    pub fn stopped(socket: *const Socket) bool {
        return socket.failed or socket.close_submitted;
    }

    /// The bytes read and not yet consumed.
    pub fn unread(socket: *Socket) []u8 {
        return socket.input[socket.input_start..][0..socket.input_len];
    }

    /// Drops the `consumed` bytes the connection took. No byte moves, so a receive in flight
    /// still writes right after the bytes left.
    pub fn consume(socket: *Socket, consumed: usize) void {
        assert(consumed <= socket.input_len);
        socket.input_start += consumed;
        socket.input_len -= consumed;
    }

    /// Writes what the socket needs next: its close once it is failed or closing and drained, and
    /// no shutdown is in flight, otherwise a send of what is owed, the shutdown of its write side
    /// once a staged close has sent everything, and a receive while there is room for more.
    /// `index` is where its driver holds it, which is its `SocketId`. False when `out` had no room
    /// for an operation the socket needs, so the next turn writes it.
    pub fn arm(socket: *Socket, out: *operation_table.Outbox, table: anytype, index: usize) bool {
        if (socket.close_submitted) return true;
        const drained = socket.outgoing.len == 0;
        if (socket.failed or (socket.closing and drained)) {
            // The close waits for the shutdown's completion. io_uring runs a shutdown on a worker
            // thread, which finds the descriptor only when it starts, so the cancel before Rotor's
            // close does not end it. A close that runs first frees the descriptor's number. The
            // next accept can take that number, and the shutdown then ends the new connection's
            // write side.
            if (socket.shutting_down) return true;
            return socket.write(out, table, index, .close);
        }
        var written = true;
        if (!socket.sending and !drained) written = socket.write(out, table, index, .send);
        // RFC 9112 §9.6: the write side closes once the response is out, and the receives go on.
        if (socket.half_close_due()) written = socket.write(out, table, index, .shutdown) and written;
        const free = input_capacity - socket.input_len;
        if (!socket.receiving and !socket.closing and free > 0) written = socket.write(out, table, index, .receive) and written;
        return written;
    }

    /// Writes one operation, and records it in flight. False when `out` is full.
    fn write(socket: *Socket, out: *operation_table.Outbox, table: anytype, index: usize, kind: Kind) bool {
        if (!out.room()) return false;
        const id = table.issue(slot_of(index, kind));
        const socket_id: host.SocketId = @enumFromInt(index);
        const kind_written: host.Operation.Kind = switch (kind) {
            .receive => blk: {
                const buffer = socket.receive_buffer();
                assert(buffer.len == input_capacity - socket.input_len);
                socket.receiving = true;
                break :blk .{ .receive = .{ .socket = socket_id, .buffer = buffer } };
            },
            .send => blk: {
                socket.sending = true;
                break :blk .{ .send = .{ .socket = socket_id, .bytes = socket.outgoing } };
            },
            .shutdown => blk: {
                socket.shutdown_submitted = true;
                socket.shutting_down = true;
                break :blk .{ .shutdown_send = .{ .socket = socket_id } };
            },
            // The host's close ends the socket's receive and send first (decision 159, rule 1).
            .close => blk: {
                socket.close_submitted = true;
                break :blk .{ .close = .{ .socket = socket_id } };
            },
            // A client writes its connect itself, with the address it holds.
            .connect => unreachable,
        };
        out.put(.{ .id = id, .kind = kind_written });
        return true;
    }
};

const testing = std.testing;

/// The socket the tests drive, outside any stack frame: its buffers are larger than one should
/// hold. Test-only.
threadlocal var test_socket: Socket align(@alignOf(Socket)) = undefined;

/// Delivers `octets` as the receive in flight read them. Test-only.
fn test_receive(octets: []const u8) void {
    @memcpy(test_socket.receive_buffer()[0..octets.len], octets);
    test_socket.on_received(.{ .received = @intCast(octets.len) });
}

test "design §8 step 60: a receive writes after the unread octets, which move only before the next receive" {
    test_socket.open();
    const front = test_socket.receive_buffer().ptr;
    test_receive("GET / HTTP/1.1\r\n");
    try testing.expectEqualStrings("GET / HTTP/1.1\r\n", test_socket.unread());
    // The bytes stayed where the receive wrote them.
    try testing.expectEqual(@intFromPtr(front), @intFromPtr(test_socket.unread().ptr));
    test_socket.consume(4);
    try testing.expectEqualStrings("/ HTTP/1.1\r\n", test_socket.unread());
    try testing.expectEqual(@intFromPtr(front) + 4, @intFromPtr(test_socket.unread().ptr));
    // The next receive's buffer moves the unread bytes to the front, and follows them.
    const next = test_socket.receive_buffer();
    try testing.expectEqual(@intFromPtr(front), @intFromPtr(test_socket.unread().ptr));
    try testing.expectEqual(@intFromPtr(front) + 12, @intFromPtr(next.ptr));
    try testing.expectEqual(input_capacity - 12, next.len);
    try testing.expectEqualStrings("/ HTTP/1.1\r\n", test_socket.unread());
}

test "design §8 step 60: octets consumed while a receive is in flight leave the arrival after the rest" {
    test_socket.open();
    test_receive("abcdef");
    const target = test_socket.receive_buffer();
    test_socket.receiving = true;
    // The session reads while the host owns `target`, and no byte moves.
    test_socket.consume(4);
    // The receive in flight still owns the bytes it was given, right after the unread ones.
    try testing.expectEqual(@intFromPtr(target.ptr), @intFromPtr(test_socket.receive_target().ptr));
    @memcpy(target[0..2], "gh");
    test_socket.on_received(.{ .received = 2 });
    try testing.expectEqualStrings("efgh", test_socket.unread());
    // A receive that fills what is left of the input moves the unread bytes to its front first.
    const fill = test_socket.receive_buffer();
    try testing.expectEqual(input_capacity - 4, fill.len);
    @memset(fill, 'z');
    test_socket.on_received(.{ .received = @intCast(fill.len) });
    try testing.expectEqual(input_capacity, test_socket.unread().len);
    try testing.expectEqualStrings("efghz", test_socket.unread()[0..5]);
    try testing.expectEqual('z', test_socket.unread()[input_capacity - 1]);
}

test {
    _ = @import("socket_send_test.zig");
}

/// The bit of a receive step's kind byte that consumes while the receive is in flight. Test-only.
const consume_in_flight_bit: u8 = 0b10;
/// One step of the fuzz script: a kind byte and two bytes of a count. Test-only.
const step_octets = 3;
const steps_max = 32;
const fuzz_input_len = step_octets * steps_max;

/// The script runs receives and consumes on a socket, and on a model that counts the bytes
/// received and the bytes consumed: the byte at each place of the flow is its place, cut to 8
/// bits. After each step the socket's unread bytes must be the model's. Test-only.
fn fuzz_input(_: void, smith: *std.testing.Smith) anyerror!void {
    var input: [fuzz_input_len]u8 = @splat(0);
    const len = smith.slice(&input);
    test_socket.open();
    var received: usize = 0;
    var consumed: usize = 0;
    var index: usize = 0;
    // Bounded by the input, which holds at most `steps_max` steps.
    while (index + step_octets <= len) : (index += step_octets) {
        const amount: usize = std.mem.readInt(u16, input[index + 1 ..][0 .. step_octets - 1], .little);
        if (input[index] & 1 == 0) {
            try fuzz_receive(input[index] & consume_in_flight_bit != 0, amount, &received, &consumed);
        } else {
            const taken = amount % (test_socket.input_len + 1);
            test_socket.consume(taken);
            consumed += taken;
        }
        const unread = test_socket.unread();
        try testing.expectEqual(received - consumed, unread.len);
        for (unread, 0..) |octet, at| try testing.expectEqual(@as(u8, @truncate(consumed + at)), octet);
    }
}

/// One receive of the fuzz script, of up to `amount` bytes. With `consume_in_flight`, the
/// session consumes some bytes while the receive is in flight (design §8 step 60). Test-only.
fn fuzz_receive(consume_in_flight: bool, amount: usize, received: *usize, consumed: *usize) !void {
    const read = amount % (input_capacity - test_socket.input_len + 1);
    if (read == 0) return;
    const was_empty = test_socket.input_len == 0;
    const target = test_socket.receive_buffer();
    if (consume_in_flight) {
        test_socket.receiving = true;
        const taken = amount % (test_socket.input_len + 1);
        test_socket.consume(taken);
        consumed.* += taken;
    }
    for (target[0..read], 0..) |*octet, at| octet.* = @truncate(received.* + at);
    test_socket.on_received(.{ .received = @intCast(read) });
    received.* += read;
    // Nothing was left unread, so the bytes stay where the receive wrote them.
    if (was_empty) try testing.expectEqual(@intFromPtr(target.ptr), @intFromPtr(test_socket.unread().ptr));
}

test "fuzz: a socket's unread octets are the flow's, whatever the receives and the consumes" {
    try testing.fuzz({}, fuzz_input, .{
        .corpus = &.{
            // Half a message left, the rest appended, then all of it read.
            @import("core").fuzz.input("\x00\x10\x00" ++ "\x01\x0c\x00" ++ "\x00\x08\x00" ++ "\x01\xff\xff"),
            // A receive that fills the input behind bytes left unread, which moves them first.
            @import("core").fuzz.input("\x00\x20\x00" ++ "\x01\x1c\x00" ++ "\x00\xff\xff" ++ "\x01\x03\x00"),
            // A consume while a receive is in flight, then the rest read.
            @import("core").fuzz.input("\x00\x20\x00" ++ "\x02\x10\x00" ++ "\x01\xff\xff"),
        },
    });
    try @import("core").fuzz.sweep(fuzz_input, null);
}

test "the socket property holds over scripts that a counter builds" {
    var input: [fuzz_input_len]u8 = undefined;
    var entry: [@sizeOf(u32) + fuzz_input_len]u8 = undefined;
    for (0..script_count) |script| {
        for (&input, 0..) |*octet, index| octet.* = @truncate((index + 1) *% (script + 1) *% mix >> mix_shift);
        // `Smith` reads a slice's length as 4 bytes, little-endian (`core.fuzz`).
        std.mem.writeInt(u32, entry[0..@sizeOf(u32)], fuzz_input_len, .little);
        @memcpy(entry[@sizeOf(u32)..], &input);
        var smith: std.testing.Smith = .{ .in = &entry };
        try fuzz_input({}, &smith);
    }
}

/// The scripts the counter pass runs, and the constants that spread a counter over the bytes.
/// Test-only.
const script_count = 512;
const mix: usize = 2654435761;
const mix_shift = 7;
