//! The tests of `.hosted` `colibri.Server` and `colibri.Client` objects on a fake host (decision
//! 159, design §8 steps 44c, 44d and 44g). The test is the host: it reads the operations that each
//! `turn` writes, completes the ones it chooses through `complete`, and moves its own clock. It
//! waits at most 1 s at a time, so a turn that names a late instant, or that asks for no wait
//! while it has no work, shows in the instants it is called at. The tests open no socket.
//!
//! `zig build colibri-loop-check` runs the halts of decision 159's rules 2 and 6
//! (`loop_check_test.zig`), because a test binary does not live through its own halt.
const std = @import("std");
const server = @import("server");
const client = @import("client");
const host = @import("host.zig");
const server_module = @import("server.zig");
const client_module = @import("client.zig");
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

/// A hosted server in cleartext with one TCP socket and no QUIC, and a hosted client with one TCP
/// connection, which the tests place outside any stack frame. Test-only.
const TestServer = server_module.Server(.{ .tcp_connections = 1, .quic_connections = 0 }, .hosted);
var test_server: TestServer align(@alignOf(TestServer)) = undefined;
var router: Router align(@alignOf(Router)) = .{};
var context: void = {};
const TestClient = client_module.Client(.{ .tcp_connections = 1, .requests = fixture.requests_max }, .hosted);
var test_client: TestClient align(@alignOf(TestClient)) = undefined;

/// Starts the hosted server: its host opened the listener alone.
fn start_server(counter: *support.Counter) !void {
    router = .{};
    try test_server.init(&.{ .cpu = support.cpu(), .random = counter.random() }, &router, &context);
}

/// The one operation of `kind` among `written`, or null.
fn find(written: []const host.Operation, comptime kind: std.meta.Tag(host.Operation.Kind)) ?host.Operation {
    for (written) |operation| {
        if (operation.kind == kind) return operation;
    }
    return null;
}

/// The operations that a fake host holds in flight, so that it can end each one.
const InFlight = struct {
    operations: [operations_len]host.Operation = undefined,
    len: usize = 0,

    /// Records each operation that `written` holds, except a cancel, which gets no completion.
    fn add(held: *InFlight, written: []const host.Operation) void {
        for (written) |operation| {
            if (operation.kind == .cancel) continue;
            held.operations[held.len] = operation;
            held.len += 1;
        }
    }

    /// Gives each operation in flight its final completion: a close closes, and each other one
    /// ends cancelled.
    fn end_all(held: *InFlight, object: anytype, now_ns: u64) void {
        for (held.operations[0..held.len]) |operation| {
            const result: host.Completion.Result = if (operation.kind == .close) .closed else .canceled;
            object.complete(&.{ .id = operation.id, .result = result }, now_ns);
        }
        held.len = 0;
    }
};

/// Stops `object` as a host does: it calls `shutdown`, then turns and ends each operation in
/// flight until `stopped()` holds. Its clock moves to each instant that a turn names, so a QUIC
/// connection's close can end (RFC 9000 §10.2). `held` holds the operations already in flight.
fn stop(object: anytype, held: *InFlight, start_ns: u64) !void {
    object.shutdown();
    var operations: [operations_len]host.Operation = undefined;
    var now_ns = start_ns;
    for (0..turns_max) |_| {
        const turned = object.turn(now_ns, &operations);
        held.add(operations[0..turned.operations]);
        held.end_all(object, now_ns);
        if (object.stopped()) return;
        if (turned.wait == .at_ns) now_ns = @max(now_ns, turned.wait.at_ns);
    }
    return error.NotStopped;
}

/// Accepts one connection and gives it half a head, as a peer that stops in its request does.
fn accept_half_head(operations: []host.Operation) !void {
    const first = test_server.turn(0, operations);
    const accept = (find(operations[0..first.operations], .accept) orelse return error.OperationMissing);
    // Nothing is in flight but the accept, so the host waits for its completion alone.
    try testing.expectEqual(host.Wait.none, first.wait);
    test_server.complete(&.{ .id = accept.id, .result = .accepted }, 0);
    const second = test_server.turn(0, operations);
    const receive = (find(operations[0..second.operations], .receive) orelse return error.OperationMissing);
    const half_head = "GET / HTTP/1.1\r\nHo";
    @memcpy(receive.kind.receive.buffer[0..half_head.len], half_head);
    test_server.complete(&.{ .id = receive.id, .result = .{ .received = half_head.len } }, 0);
}

test "decision 159: a deadline fires on time under a host that waits 1 s, and no idle turn spins" {
    var counter: support.Counter = .{};
    try start_server(&counter);
    var operations: [operations_len]host.Operation = undefined;
    try accept_half_head(&operations);
    var turned = test_server.turn(0, &operations);
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
        turned = test_server.turn(now_ns, &operations);
    }
    return error.NoResponse;
}

test "decision 159: a server stops once each operation had its final completion" {
    var counter: support.Counter = .{};
    try start_server(&counter);
    var operations: [operations_len]host.Operation = undefined;
    const first = test_server.turn(0, &operations);
    const accept = (find(operations[0..first.operations], .accept) orelse return error.OperationMissing);
    test_server.shutdown();
    const second = test_server.turn(1, &operations);
    // The shutdown cancels the accept, and the engine holds no connection.
    try testing.expectEqual(accept.id, (find(operations[0..second.operations], .cancel) orelse return error.OperationMissing).kind.cancel.target);
    try testing.expect(test_server.over);
    try testing.expect(!test_server.stopped());
    test_server.complete(&.{ .id = accept.id, .result = .canceled }, 1);
    try testing.expect(test_server.stopped());
    test_server.deinit();
}

test "decision 159: a hosted server whose host opened no listener writes no accept" {
    var counter: support.Counter = .{};
    router = .{};
    try test_server.init(&.{ .cpu = support.cpu(), .random = counter.random(), .sockets = .{ .listener = false } }, &router, &context);
    var operations: [operations_len]host.Operation = undefined;
    const turned = test_server.turn(0, &operations);
    try testing.expectEqual(0, turned.operations);
    var held: InFlight = .{};
    try stop(&test_server, &held, 0);
    test_server.deinit();
}

/// A program's handler for the hosted client: it records each exchange that ended, and makes
/// `more` requests from `on_finished`.
const HostedHandler = struct {
    exchanges: [fixture.requests_max]fixture.Exchange = @splat(.{}),
    requested: u32 = 0,
    finished: u32 = 0,
    more: u32 = 0,

    fn request(handler: *HostedHandler) !void {
        const exchange = &handler.exchanges[handler.requested];
        exchange.request.path = "/";
        exchange.response = .{ .body = &exchange.body };
        _ = try test_client.request(&exchange.request, &exchange.response);
        handler.requested += 1;
    }

    pub fn on_finished(handler: *HostedHandler, running: *TestClient, _: client.Finished) void {
        std.debug.assert(running == &test_client);
        handler.finished += 1;
        if (handler.more == 0) return;
        handler.more -= 1;
        handler.request() catch |failure| std.debug.panic("request failed: {t}", .{failure});
    }
};

/// A pool over h11 in cleartext alone.
fn h11_pool() client.Config {
    var pool = fixture.pool_config(.{ .h2 = false }, false);
    pool.protocols.h3 = false;
    return pool;
}

/// RFC 9112 §6: a response of 200 with an empty body, which ends the exchange.
const empty_response = "HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n";

test "decision 159: a request that on_finished makes leaves in the same turn" {
    var counter: support.Counter = .{};
    var handler: HostedHandler = .{ .more = 1 };
    try test_client.init(&.{ .destination = fixture.loopback(1), .pool = h11_pool(), .random = counter.random(), .unix_seconds = fixture.now_seconds }, &handler);
    try handler.request();
    var operations: [operations_len]host.Operation = undefined;
    var turned = test_client.turn(0, &operations);
    const connect = (find(operations[0..turned.operations], .connect) orelse return error.OperationMissing);
    test_client.complete(&.{ .id = connect.id, .result = .connected }, 0);
    turned = test_client.turn(0, &operations);
    const send = (find(operations[0..turned.operations], .send) orelse return error.OperationMissing);
    try testing.expect(std.mem.startsWith(u8, send.kind.send.bytes, "GET / HTTP/1.1\r\n"));
    const receive = (find(operations[0..turned.operations], .receive) orelse return error.OperationMissing);
    test_client.complete(&.{ .id = send.id, .result = .{ .sent = @intCast(send.kind.send.bytes.len) } }, 0);
    @memcpy(receive.kind.receive.buffer[0..empty_response.len], empty_response);
    test_client.complete(&.{ .id = receive.id, .result = .{ .received = empty_response.len } }, 0);
    turned = test_client.turn(0, &operations);
    // The first exchange ended inside this turn, and the request of its handler is in the same
    // turn's operations, on the same connection (RFC 9112 §9.3).
    try testing.expectEqual(1, handler.finished);
    try testing.expectEqual(2, handler.requested);
    const second = (find(operations[0..turned.operations], .send) orelse return error.OperationMissing);
    try testing.expect(std.mem.startsWith(u8, second.kind.send.bytes, "GET / HTTP/1.1\r\n"));
    var held: InFlight = .{};
    held.add(operations[0..turned.operations]);
    try stop(&test_client, &held, 0);
    test_client.deinit();
}

test "decision 156 ruling 13: a family with no UDP socket falls back to TCP" {
    var counter: support.Counter = .{};
    var handler: HostedHandler = .{};
    // The host opened a UDP socket of IPv6 alone, and the destination is IPv4.
    const pool = fixture.pool_config(.{ .prefer = .quic }, true);
    try test_client.init(&.{ .destination = fixture.loopback(fixture.https_port), .pool = pool, .random = counter.random(), .unix_seconds = fixture.now_seconds, .datagram = .{ .ipv6 = .{} } }, &handler);
    try handler.request();
    var operations: [operations_len]host.Operation = undefined;
    const turned = test_client.turn(0, &operations);
    // RFC 9114 §3.1: h3 needs QUIC, which needs a UDP socket of the address's family, so the
    // open of QUIC ends and the pool connects over TCP.
    const connect = (find(operations[0..turned.operations], .connect) orelse return error.OperationMissing);
    try testing.expectEqual(4, connect.kind.connect.address.len);
    try testing.expectEqual(null, find(operations[0..turned.operations], .send_datagram));
    // The socket of IPv6 receives, for a later destination of IPv6.
    try testing.expectEqual(0, count_on(operations[0..turned.operations], .receive_datagram, TestClient.datagram_ipv4));
    try testing.expectEqual(1, count_on(operations[0..turned.operations], .receive_datagram, TestClient.datagram_ipv6));
    var held: InFlight = .{};
    held.add(operations[0..turned.operations]);
    try stop(&test_client, &held, 0);
    test_client.deinit();
}

test "decision 159: a family with a UDP socket receives on it" {
    var counter: support.Counter = .{};
    var handler: HostedHandler = .{};
    const pool = fixture.pool_config(.{ .prefer = .quic }, true);
    try test_client.init(&.{ .destination = fixture.loopback(fixture.https_port), .pool = pool, .random = counter.random(), .unix_seconds = fixture.now_seconds, .datagram = .{ .ipv4 = .{} } }, &handler);
    var operations: [operations_len]host.Operation = undefined;
    const turned = test_client.turn(0, &operations);
    const receive = (find(operations[0..turned.operations], .receive_datagram) orelse return error.OperationMissing);
    try testing.expectEqual(TestClient.datagram_ipv4, receive.kind.receive_datagram.socket);
    // Decision 159: a host that reads no codepoint leaves the pool's ECN off.
    try testing.expect(!test_client.pool_config.ecn);
    var held: InFlight = .{};
    held.add(operations[0..turned.operations]);
    try stop(&test_client, &held, 0);
    test_client.deinit();
}

/// The operations of `kind` among `written` on `socket`.
fn count_on(written: []const host.Operation, comptime kind: std.meta.Tag(host.Operation.Kind), socket: host.SocketId) u32 {
    var count: u32 = 0;
    for (written) |operation| {
        if (operation.kind == kind and @field(operation.kind, @tagName(kind)).socket == socket) count += 1;
    }
    return count;
}

test "decision 156 ruling 13: a client receives on each family's socket and sends from its peer's" {
    var counter: support.Counter = .{};
    var handler: HostedHandler = .{};
    const pool = fixture.pool_config(.{ .prefer = .quic }, true);
    try test_client.init(&.{ .destination = fixture.loopback_ipv6_on(fixture.https_port), .pool = pool, .random = counter.random(), .unix_seconds = fixture.now_seconds, .datagram = .{ .ipv4 = .{}, .ipv6 = .{} } }, &handler);
    try handler.request();
    var operations: [operations_len]host.Operation = undefined;
    const turned = test_client.turn(0, &operations);
    const written = operations[0..turned.operations];
    try testing.expectEqual(1, count_on(written, .receive_datagram, TestClient.datagram_ipv4));
    try testing.expectEqual(1, count_on(written, .receive_datagram, TestClient.datagram_ipv6));
    // RFC 9000 §17.2.2: the first Initial goes to the destination, which is IPv6.
    const send = (find(written, .send_datagram) orelse return error.OperationMissing).kind.send_datagram;
    try testing.expectEqual(TestClient.datagram_ipv6, send.socket);
    try testing.expectEqual(16, send.to.len);
    try testing.expectEqual(0, count_on(written, .send_datagram, TestClient.datagram_ipv4));
    var held: InFlight = .{};
    held.add(written);
    try stop(&test_client, &held, 0);
    test_client.deinit();
}

/// The connect deadline of the client test: longer than one wait of the host, so the host waits
/// more than once.
const client_connect_ns: u64 = 1_500_000_000;

test "decision 153 ruling 9: a connect is cancelled at its deadline under a host that waits 1 s" {
    var counter: support.Counter = .{};
    var pool = h11_pool();
    pool.timeouts.connect_ns = client_connect_ns;
    var handler: HostedHandler = .{};
    try test_client.init(&.{ .destination = fixture.loopback(1), .pool = pool, .random = counter.random(), .unix_seconds = fixture.now_seconds }, &handler);
    try handler.request();
    var operations: [operations_len]host.Operation = undefined;
    var turned = test_client.turn(0, &operations);
    const connect = (find(operations[0..turned.operations], .connect) orelse return error.OperationMissing);
    var now_ns: u64 = 0;
    for (0..turns_max) |_| {
        if (find(operations[0..turned.operations], .cancel)) |cancel| {
            try testing.expectEqual(connect.id, cancel.kind.cancel.target);
            try testing.expectEqual(client_connect_ns, now_ns);
            break;
        }
        now_ns = @min(turned.wait.at_ns, now_ns + host_wait_ns);
        turned = test_client.turn(now_ns, &operations);
    } else return error.NoCancel;
    // The connect ends cancelled, so the exchange ends refused: no octet of the request left.
    test_client.complete(&.{ .id = connect.id, .result = .canceled }, now_ns);
    turned = test_client.turn(now_ns, &operations);
    try testing.expectEqual(1, handler.finished);
    try testing.expectEqual(client.Result.refused, handler.exchanges[0].response.result);
    var held: InFlight = .{};
    held.add(operations[0..turned.operations]);
    try stop(&test_client, &held, now_ns);
    test_client.deinit();
}

test "decision 156 ruling 11: a connection that opens after set_destination goes to a new address" {
    var counter: support.Counter = .{};
    var handler: HostedHandler = .{};
    try test_client.init(&.{ .destination = fixture.loopback(1), .pool = h11_pool(), .random = counter.random(), .unix_seconds = fixture.now_seconds }, &handler);
    try handler.request();
    var operations: [operations_len]host.Operation = undefined;
    var turned = test_client.turn(0, &operations);
    const first = (find(operations[0..turned.operations], .connect) orelse return error.OperationMissing);
    try testing.expectEqual(4, first.kind.connect.address.len);
    // The connect is refused, so the exchange ends refused (RFC 9110 §9.2.2: none of it left).
    test_client.complete(&.{ .id = first.id, .result = .{ .failed = .refused } }, 0);
    turned = test_client.turn(0, &operations);
    try testing.expectEqual(1, handler.finished);
    const close = (find(operations[0..turned.operations], .close) orelse return error.OperationMissing);
    test_client.complete(&.{ .id = close.id, .result = .closed }, 0);
    test_client.set_destination(fixture.loopback_ipv6_on(1));
    try handler.request();
    turned = test_client.turn(0, &operations);
    const second = (find(operations[0..turned.operations], .connect) orelse return error.OperationMissing);
    try testing.expectEqual(16, second.kind.connect.address.len);
    try testing.expectEqual(1, second.kind.connect.address.port);
    var held: InFlight = .{};
    held.add(operations[0..turned.operations]);
    try stop(&test_client, &held, 0);
    test_client.deinit();
}

test "decision 125: an open connection keeps its exchange after set_destination" {
    var counter: support.Counter = .{};
    var handler: HostedHandler = .{};
    try test_client.init(&.{ .destination = fixture.loopback(1), .pool = h11_pool(), .random = counter.random(), .unix_seconds = fixture.now_seconds }, &handler);
    try handler.request();
    var operations: [operations_len]host.Operation = undefined;
    var turned = test_client.turn(0, &operations);
    const connect = (find(operations[0..turned.operations], .connect) orelse return error.OperationMissing);
    test_client.complete(&.{ .id = connect.id, .result = .connected }, 0);
    turned = test_client.turn(0, &operations);
    const send = (find(operations[0..turned.operations], .send) orelse return error.OperationMissing);
    const receive = (find(operations[0..turned.operations], .receive) orelse return error.OperationMissing);
    test_client.set_destination(fixture.loopback_ipv6_on(1));
    test_client.complete(&.{ .id = send.id, .result = .{ .sent = @intCast(send.kind.send.bytes.len) } }, 0);
    @memcpy(receive.kind.receive.buffer[0..empty_response.len], empty_response);
    test_client.complete(&.{ .id = receive.id, .result = .{ .received = empty_response.len } }, 0);
    turned = test_client.turn(0, &operations);
    // The exchange ended on the connection to 127.0.0.1, and no connect was written for ::1.
    try testing.expectEqual(1, handler.finished);
    try testing.expectEqual(client.Result.response, handler.exchanges[0].response.result);
    try testing.expectEqual(null, find(operations[0..turned.operations], .connect));
    var held: InFlight = .{};
    held.add(operations[0..turned.operations]);
    try stop(&test_client, &held, 0);
    test_client.deinit();
}

test "decision 156 ruling 13: after set_destination to a family with no UDP socket, TCP opens at once" {
    var counter: support.Counter = .{};
    var handler: HostedHandler = .{};
    const pool = fixture.pool_config(.{ .prefer = .quic }, true);
    try test_client.init(&.{ .destination = fixture.loopback(fixture.https_port), .pool = pool, .random = counter.random(), .unix_seconds = fixture.now_seconds, .datagram = .{ .ipv4 = .{} } }, &handler);
    test_client.set_destination(fixture.loopback_ipv6_on(fixture.https_port));
    try handler.request();
    // A turn with room for one operation: the open of QUIC to ::1 ended before the TCP connect
    // was written, so the connect is the one operation.
    var operations: [1]host.Operation = undefined;
    const turned = test_client.turn(0, &operations);
    try testing.expectEqual(1, turned.operations);
    const connect = (find(operations[0..turned.operations], .connect) orelse return error.OperationMissing);
    try testing.expectEqual(16, connect.kind.connect.address.len);
    try testing.expectEqual(host.Wait.now, turned.wait);
    var held: InFlight = .{};
    held.add(operations[0..turned.operations]);
    try stop(&test_client, &held, 0);
    test_client.deinit();
}

test "decision 159: the pool's ECN and the segments hold only when each UDP socket has them" {
    var counter: support.Counter = .{};
    const pool = fixture.pool_config(.{ .prefer = .quic }, true);
    const able: host.Features = .{ .ecn = true, .segments = true };
    try test_client.init(&.{ .destination = fixture.loopback(fixture.https_port), .pool = pool, .random = counter.random(), .unix_seconds = fixture.now_seconds, .datagram = .{ .ipv4 = able, .ipv6 = .{} } }, null);
    // A later destination of IPv6 sends from a socket that reads no codepoint (decision 68 as
    // amended by decision 159).
    try testing.expect(!test_client.pool_config.ecn and !test_client.datagram_segments);
    var held: InFlight = .{};
    try stop(&test_client, &held, 0);
    test_client.deinit();
    try test_client.init(&.{ .destination = fixture.loopback(fixture.https_port), .pool = pool, .random = counter.random(), .unix_seconds = fixture.now_seconds, .datagram = .{ .ipv4 = able, .ipv6 = able } }, null);
    try testing.expect(test_client.pool_config.ecn and test_client.datagram_segments);
    try stop(&test_client, &held, 0);
    test_client.deinit();
}
