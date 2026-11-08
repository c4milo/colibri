//! The test of a staged close on the server's driver (decision 160), with the test as its host:
//! it reads the operations that each turn writes and completes the ones it chooses. The host
//! contract has no operation for a half-close, so the test takes it as colibri's own Rotor host
//! does, through `server_loop.take_half_close` and `server_loop.half_closed`. It opens no socket.
const std = @import("std");
const server = @import("server");
const host = @import("host.zig");
const server_module = @import("server.zig");
const server_loop = @import("server_loop.zig");
const socket_module = @import("socket.zig");
const support = @import("test_support.zig");

const testing = std.testing;

/// The room each turn writes into.
const operations_len = 16;
const response_bytes = 64;
/// RFC 9110 §15.6.1: 500 (Internal Server Error).
const internal_server_error: server.Status = .internal_server_error;

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

/// A hosted server in cleartext with one TCP socket and no QUIC, which the test places outside
/// any stack frame. Test-only.
const TestServer = server_module.Server(.{ .tcp_connections = 1, .quic_connections = 0 }, .hosted);
var test_server: TestServer align(@alignOf(TestServer)) = undefined;
var router: Router align(@alignOf(Router)) = .{};
var context: void = {};

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

/// Accepts one connection, gives it a request whose body is past `discard_len_max`, and takes the
/// whole response, so the connection closes in stages (RFC 9112 §9.6).
fn send_response(operations: []host.Operation) !void {
    const first = test_server.turn(0, operations);
    const accept = find(operations[0..first.operations], .accept).?;
    test_server.complete(&.{ .id = accept.id, .result = .accepted }, 0);
    const second = test_server.turn(0, operations);
    const receive = find(operations[0..second.operations], .receive).?;
    const head = "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1048576\r\n\r\nabc";
    @memcpy(receive.kind.receive.buffer[0..head.len], head);
    test_server.complete(&.{ .id = receive.id, .result = .{ .received = head.len } }, 0);
    const third = test_server.turn(0, operations);
    const send = find(operations[0..third.operations], .send).?;
    const sent: u32 = @intCast(send.kind.send.bytes.len);
    test_server.complete(&.{ .id = send.id, .result = .{ .sent = sent } }, 0);
    _ = test_server.turn(0, operations);
}

test "decision 160: the write side closes once the response is out, and a failed shutdown closes" {
    var counter: support.Counter = .{};
    try start_server(&counter);
    var operations: [operations_len]host.Operation = undefined;
    try send_response(&operations);
    const socket = server_loop.take_half_close(&test_server).?;
    try testing.expectEqual(0, @intFromEnum(socket));
    // One shutdown for each socket, and the socket's receive goes on.
    try testing.expectEqual(null, server_loop.take_half_close(&test_server));
    try testing.expect(test_server.sockets[0].receiving);
    server_loop.half_closed(&test_server, socket, false, 0);
    // The shutdown failed, so the next turn closes the socket.
    const turned = test_server.turn(0, &operations);
    const close = find(operations[0..turned.operations], .close).?;
    try testing.expectEqual(socket, close.kind.close.socket);
}

test "decision 160: a socket whose close completes before its shutdown is free once the shutdown ends" {
    var counter: support.Counter = .{};
    try start_server(&counter);
    var operations: [operations_len]host.Operation = undefined;
    try send_response(&operations);
    const socket = server_loop.take_half_close(&test_server).?;
    // The peer resets the connection while the shutdown is in flight, so the socket closes.
    const receive_id = test_server.operations.id(socket_module.slot_of(0, .receive));
    test_server.complete(&.{ .id = receive_id, .result = .{ .failed = .reset } }, 0);
    var turned = test_server.turn(0, &operations);
    const close = find(operations[0..turned.operations], .close).?;
    // Decision 159, rule 2: the close may complete before the shutdown that it ended.
    test_server.complete(&.{ .id = close.id, .result = .closed }, 0);
    turned = test_server.turn(0, &operations);
    try testing.expect(test_server.sockets[0].live);
    server_loop.half_closed(&test_server, socket, true, 0);
    turned = test_server.turn(0, &operations);
    try testing.expect(!test_server.sockets[0].live);
}
