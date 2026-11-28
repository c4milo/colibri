//! The tests of the calls `server_pump.zig` makes on its engine (decision 176, design §8 steps 79
//! and 80): a step passes the engine a socket's unread bytes and never a read of none, and it
//! lends before it reads the engine's events, only when its entry may owe and the socket has no
//! send in flight. The engine here is a stand-in that notes each call, so the tests open no
//! socket and run no protocol. `fake_host_send_test.zig` runs the same loop over the real engine.
const std = @import("std");
const server = @import("server");
const pump = @import("server_pump.zig");

const testing = std.testing;

/// The one connection of the tests, in slot 0. Generation 0 names no connection (decision 119).
const connection: server.ConnectionHandle = .{ .slot = 0, .generation = 1 };
/// What the stand-in engine lends.
const owed = "HTTP/1.1 200 OK\r\n\r\n";
/// The unread bytes of a test's socket, which the stand-in engine consumes whole.
const unread_len = 4;
/// The instant of each test's step.
const now_ns: u64 = 1;

/// The calls a test's steps make at most.
const calls_max = 32;

/// Stands in for the engine: counts each call and notes their order, reports the events a test
/// queued, one a call, and lends `owed`. Test-only.
const Engine = struct {
    stream_reads: usize = 0,
    event_reads: usize = 0,
    lends: usize = 0,
    queued: []const server.Event = &.{},
    /// A letter for each call, in order: `r` a read of bytes, `e` a read of events, `l` a lend.
    noted: [calls_max]u8 = undefined,
    noted_len: usize = 0,

    const Input = union(enum) { none, stream: server.StreamBytes };
    const Accepted = struct { tls: bool };

    fn note(engine: *Engine, call: u8) void {
        engine.noted[engine.noted_len] = call;
        engine.noted_len += 1;
    }

    fn calls(engine: *const Engine) []const u8 {
        return engine.noted[0..engine.noted_len];
    }

    pub fn receive(engine: *Engine, input: Input, _: u64, result: *server.ReceiveResult) void {
        switch (input) {
            .none => {
                engine.note('e');
                engine.event_reads += 1;
                result.consumed = 0;
            },
            .stream => |read| {
                engine.note('r');
                engine.stream_reads += 1;
                result.consumed = read.bytes.len;
            },
        }
        result.event = null;
        if (engine.queued.len == 0) return;
        result.event = engine.queued[0];
        engine.queued = engine.queued[1..];
    }

    pub fn output_stream(engine: *Engine, _: server.ConnectionHandle, _: u64) []const u8 {
        engine.note('l');
        engine.lends += 1;
        return owed;
    }

    pub fn accept(_: *Engine, _: Accepted, _: u64) ?server.ConnectionHandle {
        return connection;
    }
};

/// Stands in for the router: it hands back each event, as the router does with a connection's own
/// events. Test-only.
const Router = struct {
    pub fn handle(_: Router, _: *Engine, reported: *const server.Event) server.Handled {
        return .{ .event = reported };
    }
};

/// Stands in for a socket: its unread bytes, whether a send is in flight, and what it was lent.
/// Test-only.
const Socket = struct {
    sending: bool = false,
    input: [unread_len]u8 = @splat('x'),
    unread_len: usize = 0,
    given: []const u8 = "",

    pub fn unread(socket: *Socket) []u8 {
        return socket.input[0..socket.unread_len];
    }

    pub fn consume(socket: *Socket, consumed: usize) void {
        socket.unread_len -= consumed;
    }

    pub fn give(socket: *Socket, bytes: []const u8) void {
        socket.given = bytes;
    }
};

/// What the loop's functions read of a server: one entry, whose connection the engine holds.
/// Test-only.
const Run = struct {
    engine: Engine = .{},
    router: Router = .{},
    entries: [1]pump.Entry = .{.{ .handle = connection, .attached = true, .closing = false, .send_owed = false }},
    entry_of: [1]?u32 = .{0},
    sockets: [1]Socket = .{.{}},
    pending: std.bit_set.IntegerBitSet(1) = .initEmpty(),
    received: server.ReceiveResult = .{ .consumed = 0, .event = null },
    undrained: bool = false,
    over: bool = false,
    now_ns: u64 = 0,
};

/// The `send` the engine reports for the tests' connection.
const send_event = [_]server.Event{.{ .send = connection }};
/// An event of request `number` of the tests' connection, which the router takes and may answer.
fn request_event(number: u64) server.Event {
    return .{ .writable = .{ .id = .{ .connection = connection, .number = number }, .user_data = 0 } };
}
const one_request = [_]server.Event{request_event(1)};
const two_requests = [_]server.Event{ request_event(1), request_event(1 + 1) };
/// The `finished` of a response of the tests' connection, to which the router writes nothing.
const finished_event = [_]server.Event{.{ .finished = .{ .id = .{ .connection = connection, .number = 1 }, .user_data = 0, .result = .sent } }};

test "a step with no unread bytes passes the engine no read" {
    var run: Run = .{};
    pump.step(&run, 0, &run.sockets[0], now_ns);
    try testing.expectEqual(0, run.engine.stream_reads);
    // One read of the engine's events, which reports none.
    try testing.expectEqual(1, run.engine.event_reads);
    try testing.expect(!run.pending.isSet(0));
}

test "decision 176: a step passes its unread bytes once, and lends once for the engine's send" {
    var run: Run = .{};
    run.sockets[0].unread_len = unread_len;
    run.engine.queued = &send_event;
    pump.step(&run, 0, &run.sockets[0], now_ns);
    // The engine consumed the bytes with its `send`, and no read follows with none left.
    try testing.expectEqual(1, run.engine.stream_reads);
    try testing.expectEqual(0, run.sockets[0].unread_len);
    // The step gave the socket the bytes, and the entry owes nothing.
    try testing.expectEqual(1, run.engine.lends);
    try testing.expectEqualStrings(owed, run.sockets[0].given);
    try testing.expect(!run.entries[0].send_owed);
    // An entry that owes nothing asks the engine for nothing.
    pump.lend(&run, 0);
    try testing.expectEqual(1, run.engine.lends);
}

test "design §8 step 80: what the router wrote is lent before the engine's events are read" {
    var run: Run = .{};
    run.sockets[0].unread_len = unread_len;
    run.engine.queued = &one_request;
    pump.step(&run, 0, &run.sockets[0], now_ns);
    // The read reported the request, which the router may answer: the lend follows it, and the
    // read of the engine's events comes last.
    try testing.expectEqualStrings("rle", run.engine.calls()[0..3]);
    try testing.expectEqualStrings(owed, run.sockets[0].given);
    // The `finished` of a response brings no bytes, so its step asks for no lend.
    run.engine.queued = &finished_event;
    pump.step(&run, 0, &run.sockets[0], now_ns);
    try testing.expectEqual(1, run.engine.lends);
}

test "design §8 step 80: the router may write at the end of a request and at a writable" {
    var head: server.Request = undefined;
    head.end = false;
    try testing.expect(!pump.router_writes(&.{ .request = head }));
    head.end = true;
    try testing.expect(pump.router_writes(&.{ .request = head }));
    const id: server.RequestId = .{ .connection = connection, .number = 1 };
    try testing.expect(!pump.router_writes(&.{ .body = .{ .id = id, .bytes = "", .end = false } }));
    try testing.expect(pump.router_writes(&.{ .body = .{ .id = id, .bytes = "", .end = true } }));
    try testing.expect(pump.router_writes(&.{ .trailers = undefined }));
    try testing.expect(pump.router_writes(&one_request[0]) and !pump.router_writes(&finished_event[0]));
    try testing.expect(!pump.router_writes(&send_event[0]));
}

test "decision 119 as amended: over TLS a step lends once, after its last pass" {
    // The read reports the first request, and the engine holds the second for its events.
    var run: Run = .{};
    run.entries[0].tls = true;
    run.sockets[0].unread_len = unread_len;
    run.engine.queued = &two_requests;
    pump.step(&run, 0, &run.sockets[0], now_ns);
    // Both requests were routed before the one lend, which seals their responses into one record.
    try testing.expectEqualStrings("reeel", run.engine.calls());
    try testing.expectEqualStrings(owed, run.sockets[0].given);
    try testing.expect(!run.pending.isSet(0));
    // In cleartext a response is lent as soon as it is routed, before the events are read.
    var cleartext: Run = .{};
    cleartext.sockets[0].unread_len = unread_len;
    cleartext.engine.queued = &two_requests;
    pump.step(&cleartext, 0, &cleartext.sockets[0], now_ns);
    try testing.expectEqualStrings("rleele", cleartext.engine.calls());
    try testing.expectEqual(two_requests.len, cleartext.engine.lends);
}

test "design §8 step 80: what the router wrote to an event of the engine's is lent in the same step" {
    var run: Run = .{};
    run.engine.queued = &one_request;
    pump.step(&run, 0, &run.sockets[0], now_ns);
    // The socket had no unread bytes: the read of the events reported the request, and the next
    // pass lent what the router wrote. It read the events again, for what the lend brought.
    try testing.expectEqual(0, run.engine.stream_reads);
    try testing.expectEqualStrings("eele", run.engine.calls());
    try testing.expectEqualStrings(owed, run.sockets[0].given);
    try testing.expect(!run.pending.isSet(0));
}

test "decision 176: a socket with a send in flight takes no lend, and its entry stays owing" {
    var run: Run = .{};
    run.sockets[0].sending = true;
    run.engine.queued = &send_event;
    pump.step(&run, 0, &run.sockets[0], now_ns);
    try testing.expectEqual(0, run.engine.lends);
    // The entry stays owing, and waits for the send's end with no pass more.
    try testing.expect(run.entries[0].send_owed and !run.pending.isSet(0));
    // The send ends, and the next lend gives the socket what the entry owes.
    run.sockets[0].sending = false;
    pump.lend(&run, 0);
    try testing.expectEqual(1, run.engine.lends);
    try testing.expectEqualStrings(owed, run.sockets[0].given);
}

test "an entry that a new socket takes owes nothing of its last connection" {
    var run: Run = .{};
    // The entry's last connection ended while it owed bytes.
    run.entries[0] = .{ .handle = pump.no_connection, .attached = false, .closing = true, .send_owed = true };
    run.entry_of[0] = null;
    try testing.expect(pump.accept(&run, 0, true, now_ns));
    try testing.expect(run.entries[0].attached and !run.entries[0].closing);
    try testing.expect(!run.entries[0].send_owed and run.entries[0].tls);
    pump.lend(&run, 0);
    try testing.expectEqual(0, run.engine.lends);
}
