//! The tests of a client's side of an h11 connection (`connection_client.zig`), split out because a
//! hand-written source file stays at or under 500 lines with its tests included (CLAUDE.md).
const std = @import("std");
const http = @import("http");
const constants = @import("../constants.zig");
const connection = @import("connection.zig");

const testing = std.testing;
const Connection = connection.Connection;
const Field = http.Field;

/// The connection and buffer the tests use, placed outside any stack frame.
var test_connection: Connection align(@alignOf(Connection)) = undefined;
var test_output: [test_output_len]u8 = undefined;
const test_output_len = 512;

const host: []const Field = &.{.{ .name = "Host", .value = "h" }};

fn client(options: Connection.Options) *Connection {
    test_connection.init(options);
    return &test_connection;
}

fn get(target: *Connection, method: []const u8) !void {
    _ = try target.write_request(&test_output, method, "/", host);
}

fn expect_status(target: *Connection, input: []const u8, status: u16) !usize {
    const received = try target.receive(input, &.{});
    try testing.expectEqual(status, @intFromEnum(received.event.?.response.line.status));
    return received.consumed;
}

test "a response goes to its request, and its body arrives as data then end" {
    const target = client(.{ .role = .client });
    const written = try target.write_request(&test_output, "GET", "/a", host);
    try testing.expectEqualStrings("GET /a HTTP/1.1\r\nHost: h\r\n\r\n", test_output[0..written]);
    const input = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
    const head = try expect_status(target, input, 200);
    try testing.expectEqualStrings("ok", (try target.receive(input[head..], &.{})).event.?.data);
    try testing.expectEqual(connection.Connection.Event.end, (try target.receive(input[input.len..], &.{})).event.?);
    try testing.expectEqual(0, target.outstanding_len);
    try testing.expectEqual(connection.Phase.head, target.phase);
}

test "RFC 9112 §9.2: pipelined responses go to requests in order, and HEAD's has no body" {
    const target = client(.{ .role = .client });
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
    const target = client(.{ .role = .client });
    try get(target, "POST");
    try testing.expectError(error.PipelineBlocked, target.write_request(&test_output, "GET", "/", host));
    // An interim response is not the final one (RFC 9112 §9.2).
    try testing.expectEqual(100, @intFromEnum((try target.receive("HTTP/1.1 100 Continue\r\n\r\n", &.{})).event.?.interim.status));
    try testing.expectError(error.PipelineBlocked, target.write_request(&test_output, "GET", "/", host));
    _ = try expect_status(target, "HTTP/1.1 204 \r\n\r\n", 204);
    try get(target, "GET");
}

test "RFC 9112 §9.3.2: a connection opened to retry pipelines only after its first response" {
    const target = client(.{ .role = .client, .retrying = true });
    try get(target, "GET");
    try testing.expectError(error.PipelineBlocked, target.write_request(&test_output, "GET", "/", host));
    _ = try expect_status(target, "HTTP/1.1 204 \r\n\r\n", 204);
    try get(target, "GET");
    try get(target, "GET");
}

test "the queue holds pipeline_depth_max requests, and a body goes out before the next head" {
    var target = client(.{ .role = .client });
    for (0..constants.limits.pipeline_depth_max) |_| try get(target, "GET");
    try testing.expectError(error.PipelineFull, target.write_request(&test_output, "GET", "/", host));
    target = client(.{ .role = .client });
    _ = try target.write_request(&test_output, "PUT", "/", &.{ host[0], .{ .name = "Content-Length", .value = "2" } });
    try testing.expectError(error.BodyInProgress, target.write_request(&test_output, "GET", "/", host));
    _ = try target.write_body(&test_output, "ab");
    _ = try target.write_end(&test_output, &.{});
    try get(target, "GET");
}

test "RFC 9112 §9.6: the close option ends the connection, and the unanswered requests are reported" {
    var target = client(.{ .role = .client });
    _ = try target.write_request(&test_output, "GET", "/", &.{ host[0], .{ .name = "Connection", .value = "close" } });
    try testing.expectError(error.ConnectionClosed, target.write_request(&test_output, "GET", "/", host));
    // The client closes after the final response to its close, not before, though the response
    // lacks one.
    target = client(.{ .role = .client });
    try get(target, "GET");
    _ = try target.write_request(&test_output, "GET", "/", &.{ host[0], .{ .name = "Connection", .value = "close" } });
    _ = try expect_status(target, "HTTP/1.1 204 \r\n\r\n", 204);
    try testing.expect(!target.should_close());
    _ = try expect_status(target, "HTTP/1.1 204 \r\n\r\n", 204);
    try testing.expect(target.should_close());
    target = client(.{ .role = .client });
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
    var target = client(.{ .role = .client });
    try get(target, "GET");
    try get(target, "GET");
    const input = "HTTP/1.0 200 OK\r\n\r\nall of it";
    const head = try expect_status(target, input, 200);
    try testing.expectEqualStrings("all of it", (try target.receive(input[head..], &.{})).event.?.data);
    const ended = target.transport_closed();
    try testing.expect(ended.ended_body and !ended.incomplete);
    try testing.expectEqual(1, ended.unanswered);
    target = client(.{ .role = .client });
    try get(target, "GET");
    _ = try expect_status(target, "HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n", 200);
    const cut = target.transport_closed();
    try testing.expect(cut.incomplete and !cut.ended_body);
    try testing.expectEqual(1, cut.unanswered);
}

test "RFC 9112 §9.2: octets with no request outstanding are refused, unless they are CRLF" {
    const target = client(.{ .role = .client });
    try testing.expectEqual(connection.Received{ .consumed = 2, .event = null }, try target.receive("\r\nHT", &.{}));
    try testing.expectEqual(connection.Received{ .consumed = 0, .event = null }, try target.receive("\r", &.{}));
    try testing.expectError(error.ConnectionFailed, target.receive("HTTP/1.1 200 OK\r\n\r\n", &.{}));
    try testing.expectEqual(error.ResponseUnexpected, target.failure.?);
    try testing.expect(!target.has_pending());
}

test "101 and malformed responses fail the connection, and a 2xx to CONNECT tunnels" {
    var target = client(.{ .role = .client });
    try get(target, "GET");
    try testing.expectError(error.ConnectionFailed, target.receive("HTTP/1.1 101 Switching Protocols\r\n\r\n", &.{}));
    try testing.expectEqual(error.UpgradeUnsupported, target.failure.?);
    target = client(.{ .role = .client });
    try get(target, "GET");
    try testing.expectError(error.ConnectionFailed, target.receive("HTTP/1.1 200 OK\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n", &.{}));
    try testing.expectEqual(error.TransferEncodingWithContentLength, target.failure.?);
    try testing.expectEqual(1, target.transport_closed().unanswered);
    target = client(.{ .role = .client });
    _ = try target.write_request(&test_output, "CONNECT", "a:443", &.{.{ .name = "Host", .value = "a:443" }});
    _ = try expect_status(target, "HTTP/1.1 200 OK\r\n\r\n", 200);
    try testing.expectEqual(connection.Phase.tunnel, target.phase);
    try testing.expectEqualStrings("raw", (try target.receive("raw", &.{})).event.?.tunnel);
    try testing.expectEqual(3, try target.write_body(&test_output, "raw"));
}

test "RFC 9931 §8: a client writes nothing after a CONNECT until its 2xx" {
    const target = client(.{ .role = .client });
    _ = try target.write_request(&test_output, "CONNECT", "a:443", &.{.{ .name = "Host", .value = "a:443" }});
    // Neither a tunnel octet nor a pipelined request goes out before the answer.
    try testing.expectError(error.NoBody, target.write_body(&test_output, "raw"));
    try testing.expectError(error.PipelineBlocked, target.write_request(&test_output, "GET", "/", host));
    // A refusal opens no tunnel, and the connection takes the next request.
    _ = try expect_status(target, "HTTP/1.1 407 \r\nContent-Length: 0\r\n\r\n", 407);
    try testing.expectError(error.NoBody, target.write_body(&test_output, "raw"));
    try testing.expectEqual(connection.Phase.head, target.phase);
    try get(target, "GET");
}

test "decision 109: h11 implements no upgrade, so a request carrying Upgrade is not written" {
    const target = client(.{ .role = .client });
    const upgrade = [_]Field{ host[0], .{ .name = "upgrade", .value = "websocket" }, .{ .name = "Connection", .value = "upgrade" } };
    try testing.expectError(error.UpgradeUnsupported, target.write_request(&test_output, "GET", "/", &upgrade));
    try testing.expectEqual(0, target.outstanding_len);
    try get(target, "GET");
}

test "RFC 9110 §6.4.1: a 204 to CONNECT opens the tunnel as a 200 does" {
    const target = client(.{ .role = .client });
    _ = try target.write_request(&test_output, "CONNECT", "a:443", &.{.{ .name = "Host", .value = "a:443" }});
    _ = try expect_status(target, "HTTP/1.1 204 No Content\r\n\r\n", 204);
    try testing.expectEqual(connection.Phase.tunnel, target.phase);
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\n\r\n", (try target.receive("HTTP/1.1 200 OK\r\n\r\n", &.{})).event.?.tunnel);
}

test "decision 95: a fixed body's octets the caller sends itself are counted, not copied" {
    var target = client(.{ .role = .client });
    _ = try target.write_request(&test_output, "PUT", "/", &.{ host[0], .{ .name = "Content-Length", .value = "5" } });
    try target.count_body(2);
    // `write_body` and `count_body` share the one Content-Length.
    try testing.expectEqual(1, try target.write_body(&test_output, "c"));
    // RFC 9112 §6.2: no more octets than the Content-Length declared, and a refused count is not
    // counted.
    try testing.expectError(error.BodyTooLong, target.count_body(3));
    try testing.expectError(error.BodyIncomplete, target.write_end(&test_output, &.{}));
    try target.count_body(2);
    try testing.expectEqual(0, try target.write_end(&test_output, &.{}));
    // RFC 9112 §6: once the body ends there is nothing to count.
    try testing.expectError(error.NoBody, target.count_body(1));
    // RFC 9112 §7.1: a chunk needs its size line, so octets counted before a chunk head are
    // refused.
    target = client(.{ .role = .client });
    _ = try target.write_request(&test_output, "POST", "/", &.{ host[0], chunked_field });
    try testing.expectError(error.BodyTooLong, target.count_body(1));
}

const chunked_field: Field = .{ .name = "Transfer-Encoding", .value = "chunked" };

/// The server that reads back what the client wrote, and the octets of the body it read.
var test_server: Connection align(@alignOf(Connection)) = undefined;
var test_read: [test_output_len]u8 = undefined;

/// Writes a chunked POST whose body is `pieces`, each sent from the caller's memory after its chunk
/// head and counted, and returns the octets written into `test_output`.
fn write_pieces(target: *Connection, pieces: []const []const u8) !usize {
    var length = try target.write_request(&test_output, "POST", "/", &.{ host[0], chunked_field });
    for (pieces) |piece| {
        length += try target.write_chunk_head(test_output[length..], piece.len);
        // The caller sends the piece from its own memory, in place: here, after its head.
        @memcpy(test_output[length..][0..piece.len], piece);
        try target.count_body(piece.len);
        length += piece.len;
    }
    return length + try target.write_end(test_output[length..], &.{});
}

/// Reads `input` with a server's h11 connection, and returns the request body it read.
fn read_back(input: []const u8) ![]const u8 {
    test_server.init(.{ .role = .server });
    var offset: usize = 0;
    var read_len: usize = 0;
    // Bounded: each event takes at least an octet, or ends the body.
    for (0..input.len + 1) |_| {
        const received = try test_server.receive(input[offset..], &.{});
        offset += received.consumed;
        switch (received.event orelse return error.TestBodyUnended) {
            .request => {},
            .data => |octets| {
                @memcpy(test_read[read_len..][0..octets.len], octets);
                read_len += octets.len;
            },
            .end => return test_read[0..read_len],
            else => return error.TestEventUnexpected,
        }
    }
    return error.TestBodyUnended;
}

test "RFC 9112 §7.1: chunk heads frame pieces the caller sends in place, and a server reads them whole" {
    const target = client(.{ .role = .client });
    // The middle piece is 26 octets long, which reads 0x1a in hex and 26 in decimal.
    const pieces = [_][]const u8{ "first", "abcdefghijklmnopqrstuvwxyz", "end" };
    const length = try write_pieces(target, &pieces);
    const body = "5\r\nfirst\r\n1a\r\nabcdefghijklmnopqrstuvwxyz\r\n3\r\nend\r\n0\r\n\r\n";
    try testing.expect(std.mem.endsWith(u8, test_output[0..length], "\r\n\r\n" ++ body));
    try testing.expectEqualStrings("firstabcdefghijklmnopqrstuvwxyzend", try read_back(test_output[0..length]));
    try testing.expect(!target.writer.open());
}

test "RFC 9112 §7.1: a chunk head of length 0 is refused, as is one before the last chunk's data" {
    const target = client(.{ .role = .client });
    _ = try target.write_request(&test_output, "POST", "/", &.{ host[0], chunked_field });
    // A chunk-size of 0 is the last-chunk, which `write_end` writes.
    try testing.expectError(error.ChunkEmpty, target.write_chunk_head(&test_output, 0));
    try testing.expectEqualStrings("2\r\n", test_output[0..try target.write_chunk_head(&test_output, 2)]);
    try testing.expectError(error.ChunkIncomplete, target.write_chunk_head(&test_output, 1));
    try testing.expectError(error.ChunkIncomplete, target.write_end(&test_output, &.{}));
    try testing.expectError(error.BodyTooLong, target.count_body(3));
    // `write_body` copies more of the chunk's data, and the next head ends the chunk with CRLF.
    try testing.expectEqual(1, try target.write_body(&test_output, "a"));
    try target.count_body(1);
    try testing.expectEqualStrings("\r\n1\r\n", test_output[0..try target.write_chunk_head(&test_output, 1)]);
    // The CRLF and the head go out together, or not at all.
    try target.count_body(1);
    try testing.expectError(error.OutputTooSmall, target.write_chunk_head(test_output[0..4], 1));
    try testing.expectEqualStrings("\r\n0\r\n\r\n", test_output[0..try target.write_end(&test_output, &.{})]);
}

test "RFC 9112 §6.1: a body that is not chunked takes no chunk head" {
    const target = client(.{ .role = .client });
    _ = try target.write_request(&test_output, "PUT", "/", &.{ host[0], .{ .name = "Content-Length", .value = "2" } });
    try testing.expectError(error.BodyNotChunked, target.write_chunk_head(&test_output, 2));
    _ = try target.write_body(&test_output, "ab");
    _ = try target.write_end(&test_output, &.{});
    try testing.expectError(error.NoBody, target.write_chunk_head(&test_output, 1));
}
