//! The tests of the calls `server_pump.zig` makes on its engine (decision 176, design §8 step 79):
//! a step passes the engine a socket's unread bytes and never a read of none, and a lend asks the
//! engine only when it reported a `send` and the socket has no send in flight. The engine here is
//! a stand-in that counts each call, so the tests open no socket and run no protocol.
//! `fake_host_send_test.zig` runs the same loop over the real engine.
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

/// Stands in for the engine: counts each call, reports the events a test queued, one a call, and
/// lends `owed`. Test-only.
const Engine = struct {
    stream_reads: usize = 0,
    event_reads: usize = 0,
    lends: usize = 0,
    queued: []const server.Event = &.{},

    const Input = union(enum) { none, stream: server.StreamBytes };
    const Accepted = struct { tls: bool };

    pub fn receive(engine: *Engine, input: Input, _: u64, result: *server.ReceiveResult) void {
        switch (input) {
            .none => {
                engine.event_reads += 1;
                result.consumed = 0;
            },
            .stream => |read| {
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

test "a step with no unread bytes passes the engine no read" {
    var run: Run = .{};
    pump.step(&run, 0, &run.sockets[0], now_ns);
    try testing.expectEqual(0, run.engine.stream_reads);
    // One read of the engine's events, which reports none.
    try testing.expectEqual(1, run.engine.event_reads);
    try testing.expect(!run.pending.isSet(0));
}

test "decision 176: a step passes its unread bytes once, and a lend asks the engine once for a send" {
    var run: Run = .{};
    run.sockets[0].unread_len = unread_len;
    run.engine.queued = &send_event;
    pump.step(&run, 0, &run.sockets[0], now_ns);
    // The engine consumed the bytes with its `send`, and no read follows with none left.
    try testing.expectEqual(1, run.engine.stream_reads);
    try testing.expectEqual(0, run.sockets[0].unread_len);
    // The entry owes, and the driver's lend gives the socket the bytes.
    try testing.expect(run.entries[0].send_owed);
    pump.lend(&run, 0);
    try testing.expectEqual(1, run.engine.lends);
    try testing.expectEqualStrings(owed, run.sockets[0].given);
    try testing.expect(!run.entries[0].send_owed);
    // An entry that owes nothing asks the engine for nothing.
    pump.lend(&run, 0);
    try testing.expectEqual(1, run.engine.lends);
}

test "decision 176: a socket with a send in flight takes no lend, and its entry stays owing" {
    var run: Run = .{};
    run.sockets[0].sending = true;
    run.engine.queued = &send_event;
    pump.step(&run, 0, &run.sockets[0], now_ns);
    pump.lend(&run, 0);
    try testing.expectEqual(0, run.engine.lends);
    try testing.expect(run.entries[0].send_owed);
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
    try testing.expect(pump.accept(&run, 0, false, now_ns));
    try testing.expect(run.entries[0].attached and !run.entries[0].closing);
    try testing.expect(!run.entries[0].send_owed);
    pump.lend(&run, 0);
    try testing.expectEqual(0, run.engine.lends);
}
