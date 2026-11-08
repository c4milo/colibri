//! The tests of the drivers of `colibri.Server` and `colibri.Client` on a fake host (decision 159,
//! design §8 step 44c). The test is the host: it reads the operations that each turn writes,
//! completes the ones it chooses, and moves its own clock. It waits at most 1 s at a time, so a
//! turn that names a late instant, or that asks for no wait while it has no work, shows in the
//! instants it is called at. The tests open no socket.
const std = @import("std");
const server = @import("server");
const client = @import("client");
const host = @import("host.zig");
const server_module = @import("server.zig");
const server_loop = @import("server_loop.zig");
const client_loop = @import("client_loop.zig");
const support = @import("test_support.zig");
const fixture = @import("client_test_support.zig");

const testing = std.testing;

/// The longest the fake host waits at a time, and the turns a test runs at most.
const host_wait_ns: u64 = 1_000_000_000;
const turns_max = 64;
/// The room each turn writes into.
const operations_len = 16;

/// RFC 9110 §15.6.1: 500 (Internal Server Error).
const internal_server_error: server.Status = .internal_server_error;
const response_bytes = 64;

const routes = .{
    .error_handler = on_error,
    .routes = .{
        .{ .get, "/", answer },
    },
};
const Router = server.Router(void, routes, .{ .requests = 1, .response_bytes = response_bytes, .body_bytes = 0 });

fn answer(_: *void, _: *const server.Request, _: void, _: void, response: *server.ResponseWriter) !void {
    try response.end();
}

fn on_error(_: *void, _: *const server.Request, _: anyerror, response: *server.ResponseWriter) void {
    response.status = internal_server_error;
}

/// A server in cleartext with one TCP socket and no QUIC, which the tests place outside any stack
/// frame. Test-only.
const TestServer = server_module.ServerOf(.{ .tcp_connections = 1, .quic_connections = 0 });
var test_server: TestServer align(@alignOf(TestServer)) = undefined;
var router: Router align(@alignOf(Router)) = .{};
var context: void = {};
const ServerRun = struct { server: *TestServer, router: *Router, context: *void };

/// Starts the server's driver at instant 0, with no host socket: the test is its host.
fn start_server(counter: *support.Counter) !ServerRun {
    router = .{};
    test_server.config = .{ .cpu = support.cpu(), .random = counter.random() };
    test_server.engine_config = .{};
    test_server.udp.served = false;
    test_server.stopping = .init(false);
    try server_loop.start(&test_server, 0);
    return .{ .server = &test_server, .router = &router, .context = &context };
}

/// The one operation of `kind` among `written`, or null.
fn find(written: []const host.Operation, comptime kind: std.meta.Tag(host.Operation.Kind)) ?host.Operation {
    for (written) |operation| {
        if (operation.kind == kind) return operation;
    }
    return null;
}

/// Accepts one connection and gives it half a head, as a peer that stops in its request does.
fn accept_half_head(running: *ServerRun, operations: []host.Operation) !void {
    const first = server_loop.turn(running, 0, operations);
    const accept = find(operations[0..first.operations], .accept).?;
    // Nothing is in flight but the accept, so the host waits for its completion alone.
    try testing.expectEqual(host.Wait.none, first.wait);
    server_loop.complete(running, &.{ .id = accept.id, .result = .accepted }, 0);
    const second = server_loop.turn(running, 0, operations);
    const receive = find(operations[0..second.operations], .receive).?;
    const half_head = "GET / HTTP/1.1\r\nHo";
    @memcpy(receive.kind.receive.buffer[0..half_head.len], half_head);
    server_loop.complete(running, &.{ .id = receive.id, .result = .{ .received = half_head.len } }, 0);
}

test "decision 159: a deadline fires on time under a host that waits 1 s, and no idle turn spins" {
    var counter: support.Counter = .{};
    var running = try start_server(&counter);
    var operations: [operations_len]host.Operation = undefined;
    try accept_half_head(&running, &operations);
    var turned = server_loop.turn(&running, 0, &operations);
    // Decision 110: a head that stops gets its 408 at the engine's deadline.
    const deadline_ns = test_server.engine.deadline_ns().?;
    try testing.expect(deadline_ns > host_wait_ns);
    var now_ns: u64 = 0;
    for (0..turns_max) |_| {
        if (find(operations[0..turned.operations], .send)) |send| {
            try testing.expectEqual(deadline_ns, now_ns);
            try testing.expect(std.mem.startsWith(u8, send.kind.send.bytes, "HTTP/1.1 408"));
            return;
        }
        // Each turn before the deadline has no work, so it names the deadline and no less.
        try testing.expectEqual(host.Wait{ .at_ns = deadline_ns }, turned.wait);
        now_ns = @min(turned.wait.at_ns, now_ns + host_wait_ns);
        turned = server_loop.turn(&running, now_ns, &operations);
    }
    return error.NoResponse;
}

test "decision 159: a server stops once each operation had its final completion" {
    var counter: support.Counter = .{};
    var running = try start_server(&counter);
    var operations: [operations_len]host.Operation = undefined;
    const first = server_loop.turn(&running, 0, &operations);
    const accept = find(operations[0..first.operations], .accept).?;
    test_server.shutdown();
    const second = server_loop.turn(&running, 1, &operations);
    // The shutdown cancels the accept, and the engine holds no connection.
    try testing.expectEqual(accept.id, find(operations[0..second.operations], .cancel).?.kind.cancel.target);
    try testing.expect(test_server.over);
    try testing.expect(!server_loop.finished(&test_server));
    server_loop.complete(&running, &.{ .id = accept.id, .result = .canceled }, 1);
    try testing.expect(server_loop.finished(&test_server));
}

/// The connect deadline of the client test: longer than one wait of the host, so the host waits
/// more than once.
const client_connect_ns: u64 = 1_500_000_000;

test "decision 153 ruling 9: a connect is cancelled at its deadline under a host that waits 1 s" {
    var counter: support.Counter = .{};
    var pool = fixture.pool_config(.{ .h2 = false }, false);
    pool.protocols.h3 = false;
    pool.timeouts.connect_ns = client_connect_ns;
    // A client with no QUIC opens no socket at `init`.
    try fixture.test_client.init(.{ .host = "127.0.0.1", .port = 1, .pool = pool, .random = counter.random(), .unix_seconds = fixture.now_seconds });
    defer fixture.test_client.deinit();
    client_loop.start(&fixture.test_client, 0);
    var handler: fixture.Handler = .{};
    try handler.request(1);
    var running: struct { client: *fixture.TestClient, handler: *fixture.Handler } = .{ .client = &fixture.test_client, .handler = &handler };
    var operations: [operations_len]host.Operation = undefined;
    var turned = client_loop.turn(&running, 0, &operations);
    const connect = find(operations[0..turned.operations], .connect).?;
    var now_ns: u64 = 0;
    for (0..turns_max) |_| {
        if (find(operations[0..turned.operations], .cancel)) |cancel| {
            try testing.expectEqual(connect.id, cancel.kind.cancel.target);
            try testing.expectEqual(client_connect_ns, now_ns);
            break;
        }
        now_ns = @min(turned.wait.at_ns, now_ns + host_wait_ns);
        turned = client_loop.turn(&running, now_ns, &operations);
    } else return error.NoCancel;
    // The connect ends cancelled, so the exchange ends refused: no octet of the request left.
    client_loop.complete(&running, &.{ .id = connect.id, .result = .canceled }, now_ns);
    turned = client_loop.turn(&running, now_ns, &operations);
    try testing.expectEqual(1, handler.finished);
    try testing.expectEqual(client.Result.refused, handler.exchanges[0].response.result);
}
