//! One TCP socket of a `colibri.Server` or a `colibri.Client`, with no protocol and no I/O in
//! it: the octets read but not consumed, the octets its connection produced that the socket has
//! not taken yet, and the operations in flight. The driver hands each completion to the socket it
//! names, and `server_pump.zig` passes the octets between a socket and its connection. Moved from
//! the test-only server's `server_socket.zig` for design §8 step 37b. Its host does the I/O
//! (decision 159).
//!
//! A socket has one input buffer (design §8 step 60). A receive writes into the octets free after
//! the unread ones, and the host owns them until its completion (decision 159, rule 1). The
//! session consumes the input from the front by moving `input_start`, also while a receive is in
//! flight, so what arrives always follows the unread octets. Octets left unread, such as half a
//! frame, move to the front only before the next receive is written, when no receive owns the
//! buffer. A send reads `output[output_sent..output_len]`, and the session only appends after
//! that: once the output is full, it waits for the send.
//!
//! A socket outlives its connection. The engine frees a connection's slot as soon as it has
//! reported its `close`, while the socket still sends the last octets and waits for the final
//! completion of each operation, so the socket is free for another connection only after those.
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

/// The unread octets a socket holds at most: its input buffer's.
const input_capacity = constants.limits.socket_input_len;

/// One socket a driver holds. Over TLS, `input` and `output` hold records.
pub const Socket = struct {
    /// The input buffer (see the header): the unread octets, and after them the octets a receive
    /// writes.
    input: [constants.limits.socket_input_len]u8,
    /// Where the unread octets start in the input, and how many there are.
    input_start: usize,
    input_len: usize,
    output: [constants.limits.socket_output_len]u8,
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
    /// Whether the engine closed the connection, so the octets left are the last the peer gets.
    closing: bool,
    /// Whether the engine asked for a half-close: once the octets left are out, the socket's
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
        socket.output_len = 0;
        socket.output_sent = 0;
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

    /// Takes what a receive read as input. A receive of no octets is the peer closing its side,
    /// and a failed one ends the socket the same way: it is `failed` then.
    pub fn on_received(socket: *Socket, result: host.Completion.Result) void {
        socket.receiving = false;
        const read: usize = count_of(result) orelse 0;
        if (read == 0) {
            socket.failed = true;
            return;
        }
        // The receive wrote right after the unread octets: a consume moves their start and
        // their count together, so their end stayed where the receive began.
        assert(socket.input_start + socket.input_len + read <= input_capacity);
        socket.input_len += read;
    }

    /// Where the next receive writes: the octets free after the unread ones, which first move to
    /// the front of the input. No receive is in flight, so no octet the host owns moves.
    pub fn receive_buffer(socket: *Socket) []u8 {
        assert(!socket.receiving);
        if (socket.input_start > 0) {
            @memmove(socket.input[0..socket.input_len], socket.input[socket.input_start..][0..socket.input_len]);
            socket.input_start = 0;
        }
        return socket.input[socket.input_len..];
    }

    /// The octets the receive in flight writes: those free after the unread ones.
    pub fn receive_target(socket: *Socket) []u8 {
        assert(socket.receiving);
        return socket.input[socket.input_start + socket.input_len ..];
    }

    /// Counts what a send took. A send that failed leaves the socket `failed`.
    pub fn on_sent(socket: *Socket, result: host.Completion.Result) void {
        socket.sending = false;
        const sent = count_of(result) orelse {
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

    /// Whether the write side closes now: the engine closes the connection in stages, and the
    /// octets left are out (RFC 9112 §9.6, decision 160).
    pub fn half_close_due(socket: *const Socket) bool {
        if (!socket.half_closing or socket.shutdown_submitted or socket.stopped()) return false;
        return !socket.sending and socket.output_sent == socket.output_len;
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

    /// Whether the socket carries octets no more: it failed, or its close is on its way.
    pub fn stopped(socket: *const Socket) bool {
        return socket.failed or socket.close_submitted;
    }

    /// The octets read and not yet consumed.
    pub fn unread(socket: *Socket) []u8 {
        return socket.input[socket.input_start..][0..socket.input_len];
    }

    /// Drops the `consumed` octets the connection took. No octet moves, so a receive in flight
    /// still writes right after the octets left.
    pub fn consume(socket: *Socket, consumed: usize) void {
        assert(consumed <= socket.input_len);
        socket.input_start += consumed;
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

    /// Writes what the socket needs next: its close once it is failed or closing and drained,
    /// otherwise a send of what is owed, the shutdown of its write side once a staged close has
    /// sent everything, and a receive while there is room for more. `index` is where its driver
    /// holds it, which is its `SocketId`. False when `out` had no room for an operation the socket
    /// needs, so the next turn writes it.
    pub fn arm(socket: *Socket, out: *operation_table.Outbox, table: anytype, index: usize) bool {
        if (socket.close_submitted) return true;
        const drained = socket.output_sent == socket.output_len;
        if (socket.failed or (socket.closing and drained)) return socket.write(out, table, index, .close);
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
                break :blk .{ .send = .{ .socket = socket_id, .bytes = socket.output[socket.output_sent..socket.output_len] } };
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
    // The octets stayed where the receive wrote them.
    try testing.expectEqual(@intFromPtr(front), @intFromPtr(test_socket.unread().ptr));
    test_socket.consume(4);
    try testing.expectEqualStrings("/ HTTP/1.1\r\n", test_socket.unread());
    try testing.expectEqual(@intFromPtr(front) + 4, @intFromPtr(test_socket.unread().ptr));
    // The next receive's buffer moves the unread octets to the front, and follows them.
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
    // The session reads while the host owns `target`, and no octet moves.
    test_socket.consume(4);
    // The receive in flight still owns the octets it was given, right after the unread ones.
    try testing.expectEqual(@intFromPtr(target.ptr), @intFromPtr(test_socket.receive_target().ptr));
    @memcpy(target[0..2], "gh");
    test_socket.on_received(.{ .received = 2 });
    try testing.expectEqualStrings("efgh", test_socket.unread());
    // A receive that fills what is left of the input moves the unread octets to its front first.
    const fill = test_socket.receive_buffer();
    try testing.expectEqual(input_capacity - 4, fill.len);
    @memset(fill, 'z');
    test_socket.on_received(.{ .received = @intCast(fill.len) });
    try testing.expectEqual(input_capacity, test_socket.unread().len);
    try testing.expectEqualStrings("efghz", test_socket.unread()[0..5]);
    try testing.expectEqual('z', test_socket.unread()[input_capacity - 1]);
}

test "decision 159: a socket writes the operations it needs, and none while they are in flight" {
    var table: operation_table.Table(slots_per_socket) = .empty;
    var operations: [operations_per_socket]host.Operation = undefined;
    var out: operation_table.Outbox = .{ .operations = &operations };
    test_socket.open();
    test_socket.wrote(3);
    try testing.expect(test_socket.arm(&out, &table, 0));
    try testing.expectEqual(2, out.len);
    try testing.expectEqual(3, operations[0].kind.send.bytes.len);
    try testing.expectEqual(input_capacity, operations[1].kind.receive.buffer.len);
    try testing.expectEqual(2, table.count);
    // Both are in flight, so a second turn writes nothing.
    try testing.expect(test_socket.arm(&out, &table, 0));
    try testing.expectEqual(2, out.len);
    // A failed socket writes its close alone, and an outbox with no room leaves it owed.
    test_socket.failed = true;
    out = .{ .operations = operations[0..0] };
    try testing.expect(!test_socket.arm(&out, &table, 0));
    try testing.expect(out.full and !test_socket.close_submitted);
    out = .{ .operations = &operations };
    try testing.expect(test_socket.arm(&out, &table, 0));
    try testing.expect(operations[0].kind == .close);
    try testing.expect(test_socket.close_submitted);
}

test "decision 159: a socket whose close completes first is finished only after its receive's final completion" {
    test_socket.open();
    test_socket.receiving = true;
    test_socket.sending = true;
    // Rule 2: the host may give the close's completion before those of the operations it ended.
    test_socket.closed = true;
    try testing.expect(!test_socket.finished());
    test_socket.on_sent(.canceled);
    try testing.expect(!test_socket.finished());
    test_socket.on_received(.canceled);
    try testing.expect(test_socket.finished());
    // The same holds when the send's final completion comes last.
    test_socket.open();
    test_socket.receiving = true;
    test_socket.sending = true;
    test_socket.closed = true;
    test_socket.on_received(.canceled);
    try testing.expect(!test_socket.finished());
    test_socket.on_sent(.canceled);
    try testing.expect(test_socket.finished());
}

test "decision 160: the write side closes once the octets are out, and the socket is finished after it" {
    var table: operation_table.Table(slots_per_socket) = .empty;
    var operations: [operations_per_socket]host.Operation = undefined;
    var out: operation_table.Outbox = .{ .operations = &operations };
    test_socket.open();
    test_socket.half_closing = true;
    test_socket.wrote(3);
    // RFC 9112 §9.6: the response goes out first.
    try testing.expect(!test_socket.half_close_due());
    try testing.expect(test_socket.arm(&out, &table, 0));
    try testing.expectEqual(2, out.len);
    try testing.expect(operations[0].kind == .send and operations[1].kind == .receive);
    test_socket.on_sent(.{ .sent = 3 });
    try testing.expect(test_socket.half_close_due());
    out = .{ .operations = &operations };
    try testing.expect(test_socket.arm(&out, &table, 0));
    // The shutdown is written once, and the receive stays in flight.
    try testing.expectEqual(1, out.len);
    try testing.expectEqual(0, @intFromEnum(operations[0].kind.shutdown_send.socket));
    try testing.expect(test_socket.receiving and !test_socket.half_close_due());
    // The close may complete before the shutdown that it ended.
    test_socket.closed = true;
    try testing.expect(!test_socket.finished());
    test_socket.on_received(.canceled);
    test_socket.on_shut_down(.canceled);
    try testing.expect(test_socket.finished() and test_socket.failed);
    // A socket that failed shuts nothing down.
    test_socket.open();
    test_socket.half_closing = true;
    test_socket.failed = true;
    try testing.expect(!test_socket.half_close_due());
}

/// The bit of a receive step's kind octet that consumes while the receive is in flight. Test-only.
const consume_in_flight_bit: u8 = 0b10;
/// One step of the fuzz script: a kind octet and two octets of a count. Test-only.
const step_octets = 3;
const steps_max = 32;
const fuzz_input_len = step_octets * steps_max;

/// The script runs receives and consumes on a socket, and on a model that counts the octets
/// received and the octets consumed: the octet at each place of the flow is its place, cut to 8
/// bits. After each step the socket's unread octets must be the model's. Test-only.
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

/// One receive of the fuzz script, of up to `amount` octets. With `consume_in_flight`, the
/// session consumes some octets while the receive is in flight (design §8 step 60). Test-only.
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
    // Nothing was left unread, so the octets stay where the receive wrote them.
    if (was_empty) try testing.expectEqual(@intFromPtr(target.ptr), @intFromPtr(test_socket.unread().ptr));
}

test "fuzz: a socket's unread octets are the flow's, whatever the receives and the consumes" {
    try testing.fuzz({}, fuzz_input, .{
        .corpus = &.{
            // Half a message left, the rest appended, then all of it read.
            @import("core").fuzz.input("\x00\x10\x00" ++ "\x01\x0c\x00" ++ "\x00\x08\x00" ++ "\x01\xff\xff"),
            // A receive that fills the input behind octets left unread, which moves them first.
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
        // `Smith` reads a slice's length as 4 octets, little-endian (`core.fuzz`).
        std.mem.writeInt(u32, entry[0..@sizeOf(u32)], fuzz_input_len, .little);
        @memcpy(entry[@sizeOf(u32)..], &input);
        var smith: std.testing.Smith = .{ .in = &entry };
        try fuzz_input({}, &smith);
    }
}

/// The scripts the counter pass runs, and the constants that spread a counter over the octets.
/// Test-only.
const script_count = 512;
const mix: usize = 2654435761;
const mix_shift = 7;
