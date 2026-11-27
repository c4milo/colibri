//! What the fake-host tests of a `.hosted` `colibri.Server` whose sockets send what the engine
//! lends share (decision 176, design §8 step 79): the server, its router, and a host that holds
//! each operation in flight until a test completes it, at the instant `now_ns` holds. The tests
//! open no socket. Test-only.
const std = @import("std");
const server = @import("server");
const host = @import("host.zig");
const server_module = @import("server.zig");
const support = @import("test_support.zig");
const fixture = @import("client_test_support.zig");

/// The turns a test runs at most, and the room each turn writes into.
pub const turns_max = 64;
pub const operations_len = 16;
/// The instant of `init`: the identity's Unix seconds and the host's first instant.
const started: server.Timestamp = .{ .unix_seconds = fixture.now_seconds, .monotonic_ns = 0 };
const response_bytes = 64;
/// The instant of each turn and completion.
pub var now_ns: u64 = 0;

const routes = .{
    .error_handler = on_error,
    .routes = .{
        .{ .get, "/", answer },
        .{ .get, "/stream", Stream },
    },
};
/// The bytes `/stream` writes: twice what a connection's output holds, so its second half waits
/// for a send to free room (design §8 step 46).
const stream_len = stream_outputs * server.constants.limits.output_len;
const stream_outputs = 2;

/// Writes `stream_len` bytes through `body()`, a message of `response_bytes` at a time. A message
/// that does not fit waits for the next `writable`.
const Stream = struct {
    pub const State = struct { written: usize = 0 };

    pub fn on_request(_: *void, _: *server.RequestContext, _: *State, _: *const server.Request, _: *server.Response) !void {}

    pub fn next(_: *void, _: *server.RequestContext, state: *State, response: *server.Response) !void {
        const writer = response.body();
        const message: [response_bytes]u8 = @splat('s');
        // Bounded: each pass writes one message.
        for (0..stream_len) |_| {
            if (state.written == stream_len) return response.end();
            const len = @min(message.len, stream_len - state.written);
            writer.writeAll(message[0..len]) catch return;
            state.written += len;
            try writer.flush();
        }
    }
};
const Router = server.Router(void, routes, .{ .requests = 1, .response_bytes = response_bytes, .body_bytes = 0, .header_bytes = 0 });

fn answer(_: *void, _: *server.RequestContext, _: *const server.Request, response: *server.Response) !void {
    try response.body().writeAll("body");
    try response.end();
}

fn on_error(_: *void, _: *server.RequestContext, _: *const server.Request, _: anyerror, response: *server.Response) void {
    // RFC 9110 §15.6.1: 500 (Internal Server Error).
    response.status = .internal_server_error;
}

/// A hosted server in cleartext with one TCP socket and no QUIC, placed outside any stack frame.
/// Test-only.
const TestServer = server_module.Server(.{ .tcp_connections = 1, .quic_connections = 0 }, .hosted);
pub var test_server: TestServer align(@alignOf(TestServer)) = undefined;
var router: Router align(@alignOf(Router)) = .{};
var context: void = {};
pub var operations: [operations_len]host.Operation align(@alignOf(host.Operation)) = undefined;

/// The one operation of `kind` among the first `len` of `operations`, or null.
pub fn find(len: usize, comptime kind: std.meta.Tag(host.Operation.Kind)) ?host.Operation {
    for (operations[0..len]) |operation| {
        if (operation.kind == kind) return operation;
    }
    return null;
}

/// The operations the fake host holds in flight, so that it ends each one.
pub const InFlight = struct {
    operations: [turns_max]host.Operation = undefined,
    len: usize = 0,

    /// Records each operation of `written`, except a cancel, which gets no completion.
    pub fn add(held: *InFlight, written: []const host.Operation) void {
        for (written) |operation| {
            if (operation.kind == .cancel) continue;
            held.operations[held.len] = operation;
            held.len += 1;
        }
    }

    /// Gives the operation `id` its final completion, `result`.
    pub fn complete(held: *InFlight, id: host.OperationId, result: host.Completion.Result) void {
        for (held.operations[0..held.len], 0..) |operation, at| {
            if (operation.id != id) continue;
            held.operations[at] = held.operations[held.len - 1];
            held.len -= 1;
            return test_server.complete(&.{ .id = id, .result = result }, now_ns);
        }
        unreachable; // The tests complete only operations a turn wrote.
    }

    /// The operation of `kind` in flight, or null.
    pub fn find(held: *const InFlight, comptime kind: std.meta.Tag(host.Operation.Kind)) ?host.Operation {
        for (held.operations[0..held.len]) |operation| {
            if (operation.kind == kind) return operation;
        }
        return null;
    }

    /// Gives each operation in flight its final completion: a close closes, and each other one
    /// ends cancelled.
    pub fn end_all(held: *InFlight) void {
        for (held.operations[0..held.len]) |operation| {
            const result: host.Completion.Result = if (operation.kind == .close) .closed else .canceled;
            test_server.complete(&.{ .id = operation.id, .result = result }, now_ns);
        }
        held.len = 0;
    }
};
pub var in_flight: InFlight align(@alignOf(InFlight)) = .{};

/// One turn whose room is the first `room` operations, which the host then holds in flight.
/// Returns how many it wrote.
pub fn turn(room: usize) usize {
    const turned = test_server.turn(now_ns, operations[0..room]);
    in_flight.add(operations[0..turned.operations]);
    return turned.operations;
}

/// Stops the server as a host does: `shutdown`, then turns that end each operation in flight,
/// until `stopped()` holds. Then frees it.
pub fn stop() !void {
    test_server.shutdown();
    for (0..turns_max) |_| {
        _ = turn(operations_len);
        in_flight.end_all();
        if (test_server.stopped()) return test_server.deinit();
    }
    return error.NotStopped;
}

/// Starts the server on `versions` at instant 0, and accepts one connection.
pub fn start(counter: *support.Counter, versions: server.Protocols) !void {
    router = .{};
    in_flight = .{};
    now_ns = 0;
    try test_server.init(&.{ .engine = .{ .cpu_features = .none(), .protocols = versions }, .crypto = counter.crypto(), .now = started }, &router, &context);
    const accept = find(turn(operations_len), .accept) orelse return error.OperationMissing;
    in_flight.complete(accept.id, .accepted);
}
