//! The tests of a client's side of an h11 connection (`connection_client.zig`), split out because a
//! hand-written source file stays at or under 500 lines with its tests included (CLAUDE.md).
const std = @import("std");
const http = @import("http");
const constants = @import("../constants.zig");
const connection = @import("connection.zig");

const testing = std.testing;
const Connection = connection.Connection;
const Field = http.field.Field;

/// The connection and buffer the tests use, placed outside any stack frame.
var test_connection: Connection = undefined;
var test_output: [test_output_len]u8 = undefined;
const test_output_len = 512;

const host: []const Field = &.{.{ .name = "Host", .value = "h" }};

fn client(options: connection.Options) *Connection {
    test_connection.init(.client, options);
    return &test_connection;
}

fn get(target: *Connection, method: []const u8) !void {
    _ = try target.write_request(&test_output, method, "/", host);
}

fn expect_status(target: *Connection, input: []const u8, status: u16) !usize {
    const received = try target.receive(input);
    try testing.expectEqual(status, received.event.?.response.line.status.code);
    return received.consumed;
}

test "a response goes to its request, and its body arrives as data then end" {
    const target = client(.{});
    const written = try target.write_request(&test_output, "GET", "/a", host);
    try testing.expectEqualStrings("GET /a HTTP/1.1\r\nHost: h\r\n\r\n", test_output[0..written]);
    const input = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    const head = try expect_status(target, input, 200);
    try testing.expectEqualStrings("ok", (try target.receive(input[head..])).event.?.data);
    try testing.expectEqual(connection.Event.end, (try target.receive(input[input.len..])).event.?);
    try testing.expectEqual(0, target.outstanding_len);
    try testing.expectEqual(connection.Phase.head, target.phase);
}

test "RFC 9112 §9.2: pipelined responses go to requests in order, and HEAD's has no body" {
    const target = client(.{});
    try get(target, "HEAD");
    try get(target, "GET");
    try testing.expectEqual(2, target.outstanding_len);
    const input = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHTTP/1.1 204 \r\n\r\n";
    const first = try expect_status(target, input, 200);
    try testing.expectEqual(1, target.outstanding_len);
    _ = try expect_status(target, input[first..], 204);
    try testing.expectEqual(0, target.outstanding_len);
}

test "decision 88: no pipelining after a non-idempotent request until its final response" {
    const target = client(.{});
    try get(target, "POST");
    try testing.expectError(error.PipelineBlocked, target.write_request(&test_output, "GET", "/", host));
    // An interim response is not the final one (RFC 9112 §9.2).
    try testing.expectEqual(100, (try target.receive("HTTP/1.1 100 Continue\r\n\r\n")).event.?.interim.status.code);
    try testing.expectError(error.PipelineBlocked, target.write_request(&test_output, "GET", "/", host));
    _ = try expect_status(target, "HTTP/1.1 204 \r\n\r\n", 204);
    try get(target, "GET");
}

test "RFC 9112 §9.3.2: a connection opened to retry pipelines only after its first response" {
    const target = client(.{ .retrying = true });
    try get(target, "GET");
    try testing.expectError(error.PipelineBlocked, target.write_request(&test_output, "GET", "/", host));
    _ = try expect_status(target, "HTTP/1.1 204 \r\n\r\n", 204);
    try get(target, "GET");
    try get(target, "GET");
}

test "the queue holds pipeline_depth_max requests, and a body goes out before the next head" {
    var target = client(.{});
    for (0..constants.pipeline_depth_max) |_| try get(target, "GET");
    try testing.expectError(error.PipelineFull, target.write_request(&test_output, "GET", "/", host));
    target = client(.{});
    _ = try target.write_request(&test_output, "PUT", "/", &.{ host[0], .{ .name = "Content-Length", .value = "2" } });
    try testing.expectError(error.BodyInProgress, target.write_request(&test_output, "GET", "/", host));
    _ = try target.write_body(&test_output, "ab");
    _ = try target.write_end(&test_output, &.{});
    try get(target, "GET");
}

test "RFC 9112 §9.6: the close option ends the connection, and the unanswered requests are reported" {
    var target = client(.{});
    _ = try target.write_request(&test_output, "GET", "/", &.{ host[0], .{ .name = "Connection", .value = "close" } });
    try testing.expectError(error.ConnectionClosed, target.write_request(&test_output, "GET", "/", host));
    // The client closes after the final response to its close, not before, though the response
    // lacks one.
    target = client(.{});
    try get(target, "GET");
    _ = try target.write_request(&test_output, "GET", "/", &.{ host[0], .{ .name = "Connection", .value = "close" } });
    _ = try expect_status(target, "HTTP/1.1 204 \r\n\r\n", 204);
    try testing.expect(!target.should_close());
    _ = try expect_status(target, "HTTP/1.1 204 \r\n\r\n", 204);
    try testing.expect(target.should_close());
    target = client(.{});
    try get(target, "GET");
    try get(target, "GET");
    try get(target, "GET");
    _ = try expect_status(target, "HTTP/1.1 204 \r\nConnection: close\r\n\r\n", 204);
    try testing.expectEqual(connection.Phase.closed, target.phase);
    const closed = target.transport_closed();
    try testing.expectEqual(2, closed.unanswered);
    try testing.expect(!closed.incomplete);
}

test "RFC 9112 §8 and §6.3 rule 8: a close ends a close-delimited body, and cuts any other" {
    var target = client(.{});
    try get(target, "GET");
    try get(target, "GET");
    const input = "HTTP/1.0 200 OK\r\n\r\nall of it";
    const head = try expect_status(target, input, 200);
    try testing.expectEqualStrings("all of it", (try target.receive(input[head..])).event.?.data);
    const ended = target.transport_closed();
    try testing.expect(ended.ended_body and !ended.incomplete);
    try testing.expectEqual(1, ended.unanswered);
    target = client(.{});
    try get(target, "GET");
    _ = try expect_status(target, "HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n", 200);
    const cut = target.transport_closed();
    try testing.expect(cut.incomplete and !cut.ended_body);
    try testing.expectEqual(1, cut.unanswered);
}

test "RFC 9112 §9.2: octets with no request outstanding are refused, unless they are CRLF" {
    const target = client(.{});
    try testing.expectEqual(connection.Received{ .consumed = 2, .event = null }, try target.receive("\r\nHT"));
    try testing.expectEqual(connection.Received{ .consumed = 0, .event = null }, try target.receive("\r"));
    try testing.expectError(error.ConnectionFailed, target.receive("HTTP/1.1 200 OK\r\n\r\n"));
    try testing.expectEqual(error.ResponseUnexpected, target.failure.?);
    try testing.expect(!target.has_pending());
}

test "101 and malformed responses fail the connection, and a 2xx to CONNECT tunnels" {
    var target = client(.{});
    try get(target, "GET");
    try testing.expectError(error.ConnectionFailed, target.receive("HTTP/1.1 101 Switching Protocols\r\n\r\n"));
    try testing.expectEqual(error.UpgradeUnsupported, target.failure.?);
    target = client(.{});
    try get(target, "GET");
    try testing.expectError(error.ConnectionFailed, target.receive("HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n"));
    try testing.expectEqual(error.TransferEncodingWithContentLength, target.failure.?);
    try testing.expectEqual(1, target.transport_closed().unanswered);
    target = client(.{});
    _ = try target.write_request(&test_output, "CONNECT", "a:443", &.{.{ .name = "Host", .value = "a:443" }});
    _ = try expect_status(target, "HTTP/1.1 200 OK\r\n\r\n", 200);
    try testing.expectEqual(connection.Phase.tunnel, target.phase);
    try testing.expectEqualStrings("raw", (try target.receive("raw")).event.?.tunnel);
    try testing.expectEqual(3, try target.write_body(&test_output, "raw"));
}
