//! One socket of the test-only server (`../server.zig`), with no protocol in it: the octets read
//! but not consumed, the octets its connection produced that the socket has not taken yet, and
//! the Rotor operations in flight. `server_worker.zig` holds a worker's sockets, hands each event
//! to the one it names, and passes the octets between a socket and its connection in the
//! worker's session (`server_session.zig`).
//!
//! A socket has one input buffer, as `colibri.Server`'s has (design §8 step 60). A receive writes
//! into the octets free after the unread ones, and Rotor owns them until its final event (its rule
//! 3). The session consumes the input from the front by moving `input_start`, also while a receive
//! is in flight, so what arrives always follows the unread octets. Octets left unread, such as half
//! a frame, move to the front only before the next receive is submitted, when no receive owns the
//! buffer. A send reads `output[output_sent..output_len]`, and the session only appends after that.
//!
//! A socket outlives its connection. The engine frees a connection's slot as soon as it has
//! reported its `close`, while the socket still sends the last octets and waits for the final
//! event of each operation, so the socket is free for another connection only after those.
const std = @import("std");
const assert = std.debug.assert;
const rotor = @import("rotor");
const constants = @import("../constants.zig");

/// What an operation a socket has in flight does. It rides in the operation's user data, below
/// the socket's index.
pub const Kind = enum(u8) { receive, send, close, shutdown };
pub const kind_bits = @bitSizeOf(Kind);

/// The operations a loop holds in flight for each socket: a receive, a send, a close and the
/// shutdown of a staged close (decision 160).
pub const operations_per_socket: u32 = @typeInfo(Kind).@"enum".fields.len;

/// The user data of the operation of `kind` the socket at `index` has in flight.
pub fn user_data(index: usize, kind: Kind) u64 {
    return (@as(u64, index) << kind_bits) | @intFromEnum(kind);
}

/// The unread octets a socket holds at most: its input buffer's.
const input_capacity = constants.wire_read_len;

/// One socket a worker holds. Over TLS, `input` and `output` hold records.
pub const Socket = struct {
    descriptor: rotor.Descriptor,
    /// The input buffer (see the header): the unread octets, and after them the octets a receive
    /// writes.
    input: [constants.wire_read_len]u8,
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
    /// Whether the engine closed the connection, so the octets left are the last the peer gets.
    closing: bool,
    /// Whether the engine asked for a half-close: once the octets left are out, the socket's
    /// write side closes and its receives go on (RFC 9112 §9.6, decision 160).
    half_closing: bool,
    /// Whether the shutdown of the write side was submitted, and whether it is in flight.
    shutdown_submitted: bool,
    shutting_down: bool,
    /// Whether the socket closes now, with nothing more sent: the peer left or a call failed.
    failed: bool,

    /// Takes the socket `descriptor` names, with nothing read, written or in flight.
    pub fn open(socket: *Socket, descriptor: rotor.Descriptor) void {
        socket.descriptor = descriptor;
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
    pub fn on_received(socket: *Socket, event: rotor.Event) void {
        socket.receiving = false;
        const read: usize = @intCast(event.outcome() catch 0);
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
    /// the front of the input. No receive is in flight, so no octet Rotor owns moves.
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

    /// Takes the end of the shutdown of the write side. One that failed leaves the socket `failed`.
    pub fn on_shut_down(socket: *Socket, event: rotor.Event) void {
        socket.shutting_down = false;
        _ = event.outcome() catch {
            socket.failed = true;
        };
    }

    /// Whether Rotor has closed the socket and delivered the final event of each operation (its
    /// rule 1), so the entry can hold another socket.
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

    /// Whether the socket ends: it failed, or it is closing and its octets are out.
    fn ending(socket: *const Socket) bool {
        return socket.failed or (socket.closing and socket.output_sent == socket.output_len);
    }

    /// Whether the socket submits its close now: it ends, and no shutdown is in flight. io_uring
    /// runs a shutdown on a worker thread, which finds the descriptor only when it starts, so the
    /// cancel before Rotor's close does not end it. A close that runs first frees the descriptor's
    /// number. The next accept can take that number, and the shutdown then ends the new
    /// connection's write side.
    pub fn close_due(socket: *const Socket) bool {
        return !socket.shutting_down and socket.ending();
    }

    /// Submits what the socket needs next: its close once `close_due` says so, nothing more while
    /// it ends, otherwise a send of what is owed and a receive while there is room for more.
    /// `index` is where its worker holds it, which each operation's user data names. `loop` is the
    /// worker's `*rotor.Loop`, or a test's record of what `arm` submits.
    pub fn arm(socket: *Socket, loop: anytype, index: usize) void {
        if (socket.close_submitted) return;
        const drained = socket.output_sent == socket.output_len;
        if (socket.close_due()) return socket.submit(loop, index, .close);
        if (socket.ending()) return;
        if (!socket.sending and !drained) socket.submit(loop, index, .send);
        // RFC 9112 §9.6: the write side closes once the response is out, and the receives go on.
        if (socket.half_closing and drained and !socket.sending and !socket.shutdown_submitted) socket.submit(loop, index, .shutdown);
        const free = input_capacity - socket.input_len;
        if (!socket.receiving and !socket.closing and free > 0) socket.submit(loop, index, .receive);
    }

    /// Submits one operation. The loop holds one of each kind for every socket, so it always has
    /// room.
    fn submit(socket: *Socket, loop: anytype, index: usize, kind: Kind) void {
        const operation = switch (kind) {
            .receive => blk: {
                const buffer = socket.receive_buffer();
                assert(buffer.len == input_capacity - socket.input_len);
                socket.receiving = true;
                break :blk rotor.Operation.receive(user_data(index, kind), socket.descriptor, buffer);
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
            .shutdown => blk: {
                socket.shutdown_submitted = true;
                socket.shutting_down = true;
                break :blk rotor.Operation.shutdown(user_data(index, kind), socket.descriptor, .send);
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

test "design §8 step 60: a receive writes after the unread octets, which move only before the next receive" {
    test_socket.open(0);
    const front = test_socket.receive_buffer().ptr;
    test_receive("GET / HTTP/1.1\r\n");
    try testing.expectEqualStrings("GET / HTTP/1.1\r\n", test_socket.unread());
    // The octets stayed where the receive wrote them.
    try testing.expectEqual(@intFromPtr(front), @intFromPtr(test_socket.unread().ptr));
    test_socket.consume(4);
    try testing.expectEqual(@intFromPtr(front) + 4, @intFromPtr(test_socket.unread().ptr));
    // The next receive's buffer moves the unread octets to the front, and follows them.
    const next = test_socket.receive_buffer();
    try testing.expectEqual(@intFromPtr(front), @intFromPtr(test_socket.unread().ptr));
    try testing.expectEqual(@intFromPtr(front) + 12, @intFromPtr(next.ptr));
    try testing.expectEqual(input_capacity - 12, next.len);
    try testing.expectEqualStrings("/ HTTP/1.1\r\n", test_socket.unread());
}

/// The most operations one test records. Test-only.
const recorded_max = 8;

/// Stands in for the loop, and records the kind of each operation `arm` submits. Test-only.
const Record = struct {
    kinds: [recorded_max]Kind = undefined,
    len: usize = 0,

    pub fn submit(record: *Record, operations: []const rotor.Operation, handles: anytype) usize {
        _ = handles;
        for (operations) |operation| {
            record.kinds[record.len] = @enumFromInt(@as(u8, @truncate(operation.user_data)));
            record.len += 1;
        }
        return operations.len;
    }

    fn holds(record: *const Record, kind: Kind) bool {
        return std.mem.indexOfScalar(Kind, record.kinds[0..record.len], kind) != null;
    }
};

test "decision 160: a failed socket submits nothing while its shutdown is in flight, then its close" {
    var record: Record = .{};
    test_socket.open(0);
    test_socket.half_closing = true;
    test_socket.arm(&record, 0);
    try testing.expect(record.holds(.shutdown) and record.holds(.receive));
    // The peer closes while the shutdown is in flight, so the socket fails and waits.
    test_socket.on_received(rotor.Event.success(user_data(0, .receive), 0));
    record = .{};
    test_socket.arm(&record, 0);
    try testing.expectEqual(0, record.len);
    // The shutdown's completion lets the close go, and nothing else.
    test_socket.on_shut_down(rotor.Event.success(user_data(0, .shutdown), 0));
    test_socket.arm(&record, 0);
    try testing.expectEqual(1, record.len);
    try testing.expectEqual(Kind.close, record.kinds[0]);
}

test "decision 160: a socket that fails while its shutdown is in flight closes after the shutdown" {
    test_socket.open(0);
    test_socket.half_closing = true;
    test_socket.shutdown_submitted = true;
    test_socket.shutting_down = true;
    // The peer closes while the shutdown is in flight, so the socket fails.
    test_socket.on_received(rotor.Event.success(user_data(0, .receive), 0));
    try testing.expect(test_socket.failed);
    try testing.expect(!test_socket.close_due());
    // The shutdown's completion lets the close go.
    test_socket.on_shut_down(rotor.Event.success(user_data(0, .shutdown), 0));
    try testing.expect(test_socket.close_due());
    // A socket the engine closes waits for its octets as well as for the shutdown.
    test_socket.open(0);
    test_socket.closing = true;
    test_socket.output_len = 3;
    try testing.expect(!test_socket.close_due());
    test_socket.output_sent = 3;
    try testing.expect(test_socket.close_due());
}

test "design §8 step 60: octets consumed while a receive is in flight leave the arrival after the rest" {
    test_socket.open(0);
    test_receive("abcdef");
    const target = test_socket.receive_buffer();
    test_socket.receiving = true;
    // The session reads while Rotor owns `target`, and no octet moves.
    test_socket.consume(4);
    // The receive in flight still owns the octets it was given, right after the unread ones.
    try testing.expectEqual(@intFromPtr(target.ptr), @intFromPtr(test_socket.receive_target().ptr));
    @memcpy(target[0..2], "gh");
    test_socket.on_received(rotor.Event.success(user_data(0, .receive), 2));
    try testing.expectEqualStrings("efgh", test_socket.unread());
    // A receive that fills what is left of the input moves the unread octets to its front first.
    const fill = test_socket.receive_buffer();
    try testing.expectEqual(input_capacity - 4, fill.len);
    @memset(fill, 'z');
    test_socket.on_received(rotor.Event.success(user_data(0, .receive), @intCast(fill.len)));
    try testing.expectEqual(input_capacity, test_socket.unread().len);
    try testing.expectEqualStrings("efghz", test_socket.unread()[0..5]);
    try testing.expectEqual('z', test_socket.unread()[input_capacity - 1]);
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
    test_socket.open(0);
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
    test_socket.on_received(rotor.Event.success(user_data(0, .receive), @intCast(read)));
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
