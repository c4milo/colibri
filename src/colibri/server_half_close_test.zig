//! The tests of a staged close on the server's driver (decision 160), with the test as its host:
//! it reads the operations that each turn writes and completes the ones it chooses. The driver
//! writes `shutdown_send` for the write side, and the host gives it a `shut_down` completion
//! (decision 159 as amended on 2026-11-10). The tests open no socket.
const std = @import("std");
const server = @import("server");
const host = @import("host.zig");
const server_module = @import("server.zig");
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

/// Each turn gets this one instant, so the bound of `half_close_ns` cannot pass in a test.
const now_ns: u64 = 0;

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

/// Turns the server, and returns the operation of `kind` that the turn wrote.
fn turn_for(operations: []host.Operation, comptime kind: std.meta.Tag(host.Operation.Kind)) !host.Operation {
    const turned = test_server.turn(now_ns, operations);
    return find(operations[0..turned.operations], kind) orelse error.OperationMissing;
}

/// Gives the receive in flight on socket 0 the octets `octets`, as a peer sends them. No octets
/// is the peer's close.
fn deliver(octets: []const u8) void {
    const socket = &test_server.sockets[0];
    @memcpy(socket.receive_buffer()[0..octets.len], octets);
    const id = test_server.operations.id(socket_module.slot_of(0, .receive));
    test_server.complete(&.{ .id = id, .result = .{ .received = @intCast(octets.len) } }, now_ns);
}

/// Accepts one connection, gives it a request whose body is past `discard_len_max`, and takes the
/// whole response. The connection closes in stages (RFC 9112 §9.6), so the next turn writes the
/// shutdown of the write side, which this returns.
fn send_response(operations: []host.Operation) !host.Operation {
    const accept = try turn_for(operations, .accept);
    test_server.complete(&.{ .id = accept.id, .result = .accepted }, now_ns);
    _ = try turn_for(operations, .receive);
    deliver("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1048576\r\n\r\nabc");
    const send = try turn_for(operations, .send);
    // RFC 9110 §10.1.1: the Content-Length is past the bound, so the response says that the
    // server closes.
    try testing.expect(std.mem.indexOf(u8, send.kind.send.bytes, "\r\nConnection: close\r\n") != null);
    test_server.complete(&.{ .id = send.id, .result = .{ .sent = @intCast(send.kind.send.bytes.len) } }, now_ns);
    return turn_for(operations, .shutdown_send);
}

test "decision 160: the write side closes once the response is out, and a failed shutdown closes" {
    var counter: support.Counter = .{};
    try start_server(&counter);
    var operations: [operations_len]host.Operation = undefined;
    const shutdown = try send_response(&operations);
    try testing.expectEqual(0, @intFromEnum(shutdown.kind.shutdown_send.socket));
    // RFC 9112 §9.6: the socket's receive goes on, and the turn writes no second shutdown.
    try testing.expect(test_server.sockets[0].receiving and !test_server.sockets[0].closing);
    try testing.expectError(error.OperationMissing, turn_for(&operations, .shutdown_send));
    test_server.complete(&.{ .id = shutdown.id, .result = .{ .failed = .reset } }, now_ns);
    // The shutdown failed, so the next turn closes the socket.
    const close = try turn_for(&operations, .close);
    try testing.expectEqual(shutdown.kind.shutdown_send.socket, close.kind.close.socket);
}

test "decision 160: a socket whose close completes before its shutdown is free once the shutdown ends" {
    var counter: support.Counter = .{};
    try start_server(&counter);
    var operations: [operations_len]host.Operation = undefined;
    const shutdown = try send_response(&operations);
    // The peer resets the connection while the shutdown is in flight, so the socket closes.
    const receive_id = test_server.operations.id(socket_module.slot_of(0, .receive));
    test_server.complete(&.{ .id = receive_id, .result = .{ .failed = .reset } }, now_ns);
    const close = try turn_for(&operations, .close);
    // Decision 159, rule 2: the close may complete before the shutdown that it ended.
    test_server.complete(&.{ .id = close.id, .result = .closed }, now_ns);
    _ = test_server.turn(now_ns, &operations);
    try testing.expect(test_server.sockets[0].live);
    test_server.complete(&.{ .id = shutdown.id, .result = .canceled }, now_ns);
    _ = test_server.turn(now_ns, &operations);
    try testing.expect(!test_server.sockets[0].live);
}

test "decision 160: after the half-close the socket receives again, and the peer's close ends the connection" {
    var counter: support.Counter = .{};
    try start_server(&counter);
    var operations: [operations_len]host.Operation = undefined;
    const shutdown = try send_response(&operations);
    // RFC 9112 §9.6: the bound runs from the `half_close`, at the one instant of this test.
    try testing.expectEqual(now_ns + server.constants.limits.half_close_ns, test_server.engine.deadline_ns().?);
    test_server.complete(&.{ .id = shutdown.id, .result = .shut_down }, now_ns);
    const socket = &test_server.sockets[0];
    try testing.expect(socket.half_closing and !socket.closing and !socket.failed);
    // The client writes on, and the socket reads the octets. The next turn steps the socket: the
    // engine discards the octets, and the socket receives again.
    deliver("more of the body");
    _ = try turn_for(&operations, .receive);
    try testing.expect(socket.receiving and socket.unread().len == 0);
    // The peer closes first. The receive reads its close, and the connection ends with no `close`
    // from the engine.
    deliver("");
    const close = try turn_for(&operations, .close);
    try testing.expect(socket.failed and !test_server.entries[0].attached and !test_server.entries[0].closing);
    test_server.complete(&.{ .id = close.id, .result = .closed }, now_ns);
    _ = test_server.turn(now_ns, &operations);
    try testing.expect(!socket.live);
}
