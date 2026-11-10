//! One TCP socket of a `colibri.Server`, with no protocol in it: the octets read but not
//! consumed, the octets its connection produced that the socket has not taken yet, and the Rotor
//! operations in flight. `server_loop.zig` hands each event to the socket it names, and
//! `server_pump.zig` passes the octets between a socket and its connection. Moved from the
//! test-only server's `server_socket.zig` for design §8 step 37b.
//!
//! A socket has two receive buffers. A receive writes into the one that holds no unread octets,
//! because Rotor owns a receive's buffer until its final event (its rule 3). When its event
//! arrives and nothing was left unread, that buffer becomes the input, and no octet moves. Only
//! octets left unread, such as half a frame, take a copy: the new ones are appended to them. The
//! session consumes the input from the front by moving `input_start`.
//! A send reads `output[output_sent..output_len]`, and the session only appends after that.
//!
//! A socket outlives its connection. The engine frees a connection's slot as soon as it has
//! reported its `close`, while the socket still sends the last octets and waits for the final
//! event of each operation, so the socket is free for another connection only after those.
const std = @import("std");
const assert = std.debug.assert;
const rotor = @import("rotor");
const constants = @import("constants.zig");

/// What an operation a socket has in flight does. It rides in the operation's user data, below
/// the socket's index. A client's socket connects (design §8 step 42), and a server's comes from
/// its listener. A server's socket shuts its write side down for a staged close (decision 160).
pub const Kind = enum(u8) { receive, send, close, shutdown, connect };
pub const kind_bits = @bitSizeOf(Kind);

/// The operations a loop holds in flight for each socket: a receive, a send, a close and a
/// shutdown. A connect is in flight before the socket receives or sends, alone or with the close
/// that cancels it, so it takes no more room.
pub const operations_per_socket: u32 = @typeInfo(Kind).@"enum".fields.len - 1;

comptime {
    // The connect is the one kind that is never in flight beside a receive or a send.
    const fields = @typeInfo(Kind).@"enum".fields;
    assert(std.mem.eql(u8, fields[fields.len - 1].name, "connect"));
}

/// The user data of the operation of `kind` the socket at `index` has in flight.
pub fn user_data(index: usize, kind: Kind) u64 {
    return (@as(u64, index) << kind_bits) | @intFromEnum(kind);
}

/// The user data of the one accept a server keeps in flight (`server_loop.zig`). No socket's user
/// data reaches it, and the UDP socket's are below it.
pub const accept_user_data: u64 = std.math.maxInt(u64);

/// The unread octets a socket holds at most: one receive buffer's.
const input_capacity = constants.limits.socket_input_len;
/// A socket's receive buffers: the input, and the one the receive in flight writes.
const receive_buffers = 2;

/// One socket a worker holds. Over TLS, `input` and `output` hold records.
pub const Socket = struct {
    descriptor: rotor.Descriptor,
    /// The two receive buffers (see the header). `buffers[input_at]` holds the input, and a
    /// receive writes into the other one.
    buffers: [receive_buffers][constants.limits.socket_input_len]u8,
    input_at: u1,
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
    /// Whether the shutdown of the write side was submitted, and whether it is in flight.
    shutdown_submitted: bool,
    shutting_down: bool,
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
    pub fn receive_buffer(socket: *Socket) *[constants.limits.socket_input_len]u8 {
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
        return socket.buffers[socket.input_at][socket.input_start..][0..socket.input_len];
    }

    /// Drops the `consumed` octets the connection took. No octet moves. When none is left, the
    /// next receive's buffer becomes the input, which starts `input_start` again.
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

    /// Submits what the socket needs next: its close once it is failed or closing and drained,
    /// otherwise a send of what is owed and a receive while there is room for more. `index` is
    /// where its worker holds it, which each operation's user data names.
    pub fn arm(socket: *Socket, loop: *rotor.Loop, index: usize) void {
        if (socket.close_submitted) return;
        const drained = socket.output_sent == socket.output_len;
        if (socket.failed or (socket.closing and drained)) return socket.submit(loop, index, .close);
        if (!socket.sending and !drained) socket.submit(loop, index, .send);
        // RFC 9112 §9.6: the write side closes once the response is out, and the receives go on.
        if (socket.half_closing and drained and !socket.sending and !socket.shutdown_submitted) socket.submit(loop, index, .shutdown);
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
            .shutdown => blk: {
                socket.shutdown_submitted = true;
                socket.shutting_down = true;
                break :blk rotor.Operation.shutdown(user_data(index, kind), socket.descriptor, .send);
            },
            // A client submits its connect itself, with the address it holds until the event.
            .connect => unreachable,
        };
        const taken = loop.submit(&.{operation}, &.{});
        assert(taken == 1);
    }
};

/// Ends the run of `loop`, whose TCP sockets are `sockets`, whether it finished or failed. It
/// cancels what is in flight, reads each final event until nothing is in flight, and closes each
/// socket that is still open. A server's run and a client's each end with it.
///
/// On io_uring, a close the loop submitted is in flight, and `cancel_all` can cancel it before it
/// runs. Then the descriptor stays open. kqueue and epoll close at submit. The ticks stop after
/// `rotor.constants.drain_rounds_max`, as Rotor's own `drain` does, and `deinit` then halts.
pub fn end_loop(loop: *rotor.Loop, events: []rotor.Event, sockets: []Socket) void {
    loop.cancel_all();
    for (0..rotor.constants.drain_rounds_max) |_| {
        if (loop.in_flight() == 0) break;
        const count = loop.tick(events, rotor.constants.drain_wait_ns) catch break;
        for (events[0..count]) |event| on_last_event(sockets, event);
    }
    close_left(sockets);
}

/// Reads one event of a run's last ticks. A close that ended canceled or timed out did not run
/// (Rotor's decision 5, rules 2 and 4), so `close_left` closes its socket. A close that failed
/// otherwise ran, and the system released the descriptor, so a second close could close another
/// descriptor with the same number. An accept that succeeded gave a socket no entry holds, so it
/// closes here. Every other event changes nothing. A connect that succeeded leaves its socket
/// live with no close submitted, so `close_left` closes it.
pub fn on_last_event(sockets: []Socket, event: rotor.Event) void {
    if (event.flags.message) return;
    if (event.user_data == accept_user_data) return close_accepted(event);
    // The accept and the UDP socket's operations have user data above every socket's.
    const index = event.user_data >> kind_bits;
    if (index >= sockets.len) return;
    if (@as(u8, @truncate(event.user_data)) != @intFromEnum(Kind.close)) return;
    const socket = &sockets[@intCast(index)];
    assert(socket.live);
    assert(socket.close_submitted);
    _ = event.outcome() catch |failure| switch (failure) {
        error.Canceled, error.Timeout => socket.close_submitted = false,
        else => {},
    };
}

/// Closes the socket an accept delivered after the run ended. An accept that failed or was
/// canceled delivered none.
fn close_accepted(event: rotor.Event) void {
    const descriptor: rotor.Descriptor = @intCast(event.outcome() catch return);
    rotor.sync.close_now(descriptor);
}

/// Closes each socket whose close was never submitted or did not run, once a run ended and the
/// loop holds no operation: a run that failed leaves them open. A socket whose close ran has
/// closed.
pub fn close_left(sockets: []Socket) void {
    for (sockets) |*socket| {
        if (socket.live and !socket.close_submitted) rotor.sync.close_now(socket.descriptor);
        socket.live = false;
    }
}

const testing = std.testing;

/// The socket the tests drive, outside any stack frame: its buffers are larger than one should
/// hold. Test-only.
threadlocal var test_socket: Socket align(@alignOf(Socket)) = undefined;

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
    try testing.expectEqual(0, test_socket.unread().len);
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

/// Opens a socket into `test_socket`, as an accept or a connect does, with its close submitted.
/// Test-only.
fn test_open_closing() !rotor.Descriptor {
    const descriptor = try rotor.sync.open_socket(.ipv4);
    test_socket.open(descriptor);
    test_socket.close_submitted = true;
    return descriptor;
}

test "design §8 step 42: the end of a run closes a socket whose close was canceled" {
    const sockets = (&test_socket)[0..1];
    for ([_]rotor.Code{ .canceled, .timeout }) |code| {
        const descriptor = try test_open_closing();
        on_last_event(sockets, rotor.Event.failure(user_data(0, .close), code));
        close_left(sockets);
        try testing.expect(!test_socket.live);
        // getsockname(2) on a closed descriptor fails with EBADF, which Rotor reports as unexpected.
        try testing.expectError(error.Unexpected, rotor.sync.local_address(descriptor));
    }
}

test "design §8 step 42: the end of a run closes no socket whose close ran" {
    const sockets = (&test_socket)[0..1];
    const descriptor = try test_open_closing();
    defer rotor.sync.close_now(descriptor);
    // A close that ran, and one that ran and failed: the system released the descriptor in each.
    on_last_event(sockets, rotor.Event.success(user_data(0, .close), 0));
    on_last_event(sockets, rotor.Event.failure(user_data(0, .close), .input_output));
    // No other event changes the close: another kind, another socket, the accept, the UDP socket's
    // operations and a message.
    on_last_event(sockets, rotor.Event.failure(user_data(0, .receive), .canceled));
    on_last_event(sockets, rotor.Event.failure(user_data(1, .close), .canceled));
    on_last_event(sockets, rotor.Event.failure(std.math.maxInt(u64), .canceled));
    on_last_event(sockets, rotor.Event.failure(std.math.maxInt(u64) - 1, .canceled));
    on_last_event(sockets, rotor.Event.message(user_data(0, .close), 0));
    try testing.expect(test_socket.close_submitted);
    close_left(sockets);
    // The test's own socket is still open, so no second close reached it.
    _ = try rotor.sync.local_address(descriptor);
}

test "design §8 step 42: the end of a run closes a socket an accept delivered" {
    const sockets = (&test_socket)[0..1];
    test_socket.live = false;
    const descriptor = try rotor.sync.open_socket(.ipv4);
    on_last_event(sockets, rotor.Event.success(accept_user_data, @intCast(descriptor)));
    try testing.expectError(error.Unexpected, rotor.sync.local_address(descriptor));
    // An accept that was canceled delivered no socket, so nothing closes.
    const kept = try rotor.sync.open_socket(.ipv4);
    defer rotor.sync.close_now(kept);
    on_last_event(sockets, rotor.Event.failure(accept_user_data, .canceled));
    _ = try rotor.sync.local_address(kept);
}

test "design §8 step 42: the end of a run closes a socket whose connect succeeded" {
    const sockets = (&test_socket)[0..1];
    const descriptor = try rotor.sync.open_socket(.ipv4);
    test_socket.open(descriptor);
    // The connect ended before `cancel_all` reached it, and no close was submitted.
    on_last_event(sockets, rotor.Event.success(user_data(0, .connect), 0));
    try testing.expect(!test_socket.close_submitted);
    close_left(sockets);
    try testing.expect(!test_socket.live);
    try testing.expectError(error.Unexpected, rotor.sync.local_address(descriptor));
}

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
            const read = amount % (input_capacity - test_socket.input_len + 1);
            if (read == 0) continue;
            const was_empty = test_socket.input_len == 0;
            const target = test_socket.receive_buffer();
            for (target[0..read], 0..) |*octet, at| octet.* = @truncate(received + at);
            test_socket.on_received(rotor.Event.success(user_data(0, .receive), @intCast(read)));
            received += read;
            // Nothing was left unread, so the octets stay where the receive wrote them.
            if (was_empty) try testing.expectEqual(@intFromPtr(target), @intFromPtr(test_socket.unread().ptr));
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

test "fuzz: a socket's unread octets are the flow's, whatever the receives and the consumes" {
    try testing.fuzz({}, fuzz_input, .{
        .corpus = &.{
            // Half a message left, the rest appended, then all of it read.
            @import("core").fuzz.input("\x00\x10\x00" ++ "\x01\x0c\x00" ++ "\x00\x08\x00" ++ "\x01\xff\xff"),
            // A receive that fills the input behind octets left unread, which moves them first.
            @import("core").fuzz.input("\x00\x20\x00" ++ "\x01\x1c\x00" ++ "\x00\xff\xff" ++ "\x01\x03\x00"),
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
