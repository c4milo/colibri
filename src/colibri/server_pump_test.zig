//! The tests of the calls `server_pump.zig` makes on its engine (design §8 step 79): a step passes
//! the engine a socket's unread bytes, and never a read of none. The engine here is a stand-in that
//! counts each call, so the tests open no socket and run no protocol. `fake_host_send_test.zig`
//! runs the same loop over the real engine.
const std = @import("std");
const server = @import("server");
const pump = @import("server_pump.zig");

const testing = std.testing;

/// The one connection of the tests, in slot 0. Generation 0 names no connection (decision 119).
const connection: server.ConnectionHandle = .{ .slot = 0, .generation = 1 };
/// The unread bytes of a test's socket, which the stand-in engine consumes whole.
const unread_len = 4;
/// The instant of each test's step.
const now_ns: u64 = 1;

/// Stands in for the engine: counts each read, and reports the events a test queued, one a call.
/// Test-only.
const Engine = struct {
    stream_reads: usize = 0,
    event_reads: usize = 0,
    queued: []const server.Event = &.{},

    const Input = union(enum) { none, stream: server.StreamBytes };

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
};

/// Stands in for the router: it hands back each event, as the router does with a connection's own
/// events. Test-only.
const Router = struct {
    pub fn handle(_: Router, _: *Engine, reported: *const server.Event) server.Handled {
        return .{ .event = reported };
    }
};

/// Stands in for a socket: its unread bytes. Test-only.
const Socket = struct {
    input: [unread_len]u8 = @splat('x'),
    unread_len: usize = 0,

    pub fn unread(socket: *Socket) []u8 {
        return socket.input[0..socket.unread_len];
    }

    pub fn consume(socket: *Socket, consumed: usize) void {
        socket.unread_len -= consumed;
    }
};

/// What the loop's functions read of a server: one entry, whose connection the engine holds.
/// Test-only.
const Run = struct {
    engine: Engine = .{},
    router: Router = .{},
    entries: [1]pump.Entry = .{.{ .handle = connection, .attached = true, .closing = false }},
    entry_of: [1]?u32 = .{0},
    sockets: [1]Socket = .{.{}},
    pending: std.bit_set.IntegerBitSet(1) = .initEmpty(),
    received: server.ReceiveResult = .{ .consumed = 0, .event = null },
    undrained: bool = false,
    over: bool = false,
    now_ns: u64 = 0,
};

test "a step with no unread bytes passes the engine no read" {
    var run: Run = .{};
    pump.step(&run, 0, &run.sockets[0], now_ns);
    try testing.expectEqual(0, run.engine.stream_reads);
    // One read of the engine's events, which reports none.
    try testing.expectEqual(1, run.engine.event_reads);
    try testing.expect(!run.pending.isSet(0));
}

test "a step passes its unread bytes to the engine once" {
    var run: Run = .{};
    run.sockets[0].unread_len = unread_len;
    pump.step(&run, 0, &run.sockets[0], now_ns);
    // The engine consumed the bytes, and no read follows with none left.
    try testing.expectEqual(1, run.engine.stream_reads);
    try testing.expectEqual(0, run.sockets[0].unread_len);
}
