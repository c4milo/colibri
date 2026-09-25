//! The tests of a server's side of an h11 connection (`connection_server.zig`), split out because
//! a hand-written source file stays at or under 500 lines with its tests included (CLAUDE.md).
const std = @import("std");
const http = @import("http");
const connection = @import("connection.zig");

const testing = std.testing;
const Connection = connection.Connection;
const Field = http.field.Field;

/// The connection and buffer the tests use, placed outside any stack frame.
var test_connection: Connection = undefined;
var test_output: [test_output_len]u8 = undefined;
const test_output_len = 512;

/// Calls `drain` makes past one per octet: the owed end, and the call that finds nothing.
const test_calls_past_len = 2;

fn server() *Connection {
    test_connection.init(.server, .{});
    return &test_connection;
}

/// Receives from `input` until the connection consumes nothing, and returns the octets consumed.
fn drain(target: *Connection, input: []const u8) !usize {
    var offset: usize = 0;
    for (0..input.len + test_calls_past_len) |_| {
        const received = try target.receive(input[offset..]);
        offset += received.consumed;
        if (received.consumed == 0 and received.event == null) return offset;
    }
    return error.TestUnexpectedResult;
}

fn expect_request(target: *Connection, input: []const u8, method: []const u8) !usize {
    const received = try target.receive(input);
    try testing.expectEqualStrings(method, received.event.?.request.line.method);
    return received.consumed;
}

test "requests are read one at a time, each after the last one's final response" {
    const target = server();
    const input = "GET /a HTTP/1.1\r\nHost: h\r\n\r\nGET /b HTTP/1.1\r\nHost: h\r\n\r\n";
    const first = try expect_request(target, input, "GET");
    // decision 92: the second request stays unread until the first is answered.
    try testing.expectEqual(connection.Received{ .consumed = 0, .event = null }, try target.receive(input[first..]));
    const written = try target.write_response(&test_output, 200, "OK", &.{.{ .name = "Content-Length", .value = "2" }});
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n", test_output[0..written]);
    try testing.expectEqual(2, try target.write_body(&test_output, "ok"));
    try testing.expectEqual(0, try target.write_end(&test_output, &.{}));
    const second = try target.receive(input[first..]);
    try testing.expectEqualStrings("/b", second.event.?.request.line.target);
    try testing.expectEqual(connection.Phase.waiting, target.phase);
}

test "a request body arrives as data then end, and a chunked one leaves its trailers" {
    var target = server();
    const fixed = "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\n\r\nabc";
    const head = try expect_request(target, fixed, "POST");
    const data = try target.receive(fixed[head..]);
    try testing.expectEqualStrings("abc", data.event.?.data);
    try testing.expectEqual(connection.Event.end, (try target.receive(fixed[head + data.consumed ..])).event.?);
    try testing.expectEqual(connection.Phase.waiting, target.phase);
    target = server();
    const coded = "POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\nT: v\r\n\r\n";
    try testing.expectEqual(coded.len, try drain(target, coded));
    try testing.expectEqualStrings("v", target.trailers.find("t").?.value);
    try testing.expectEqual(connection.Phase.waiting, target.phase);
}

test "RFC 9112 §9.3 and §9.6: the close option or HTTP/1.0 ends the connection after the response" {
    for ([_][]const u8{ "GET / HTTP/1.1\r\nHost: h\r\nConnection: keep-alive, Close\r\n\r\n", "GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n" }) |input| {
        const target = server();
        _ = try expect_request(target, input, "GET");
        const written = try target.write_response(&test_output, 204, "", &.{});
        try testing.expect(std.mem.indexOf(u8, test_output[0..written], "Connection: close\r\n") != null);
        try testing.expect(target.should_close());
    }
}

test "decision 92: a malformed request owes an error response with the close, by its status" {
    const cases = [_]struct { input: []const u8, status: []const u8 }{
        .{ .input = "GET / HTTP/1.1\r\n\r\n", .status = "400 Bad Request" },
        .{ .input = "GET / HTTP/2.0\r\nHost: h\r\n\r\n", .status = "505 HTTP Version Not Supported" },
        .{ .input = "POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: br, chunked\r\n\r\n", .status = "501 Not Implemented" },
        .{ .input = "GET / HTTP/1.1\nHost: h\n\n", .status = "400 Bad Request" },
    };
    for (cases) |case| {
        const target = server();
        try testing.expectError(error.ConnectionFailed, target.receive(case.input));
        try testing.expect(target.has_pending() and !target.should_close());
        const written = try target.write_pending(&test_output);
        try testing.expect(std.mem.startsWith(u8, test_output[0..written], "HTTP/1.1 "));
        try testing.expect(std.mem.indexOf(u8, test_output[0..written], case.status) != null);
        try testing.expect(std.mem.endsWith(u8, test_output[0..written], "\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"));
        try testing.expect(target.should_close());
        try testing.expectError(error.ConnectionClosed, target.write_response(&test_output, 200, "", &.{}));
    }
}

/// Octets the limit tests fill a request with.
var test_long: [test_long_len]u8 = undefined;
const test_long_len = 9000;

test "decision 92: a request line too long is a 414, and too many field lines a 431" {
    var target = server();
    @memcpy(test_long[0..5], "GET /");
    @memset(test_long[5..8200], 'a');
    try testing.expectError(error.ConnectionFailed, target.receive(test_long[0..8200]));
    try testing.expectEqual(414, target.reply_status.?);
    target = server();
    var length: usize = 0;
    const start = "GET / HTTP/1.1\r\nHost: h\r\n";
    @memcpy(test_long[0..start.len], start);
    length = start.len;
    for (0..128) |_| {
        @memcpy(test_long[length..][0..6], "a: b\r\n");
        length += 6;
    }
    @memcpy(test_long[length..][0..2], "\r\n");
    try testing.expectError(error.ConnectionFailed, target.receive(test_long[0 .. length + 2]));
    try testing.expectEqual(431, target.reply_status.?);
}

test "RFC 9112 §9.3: a response before the whole request body is read ends the connection" {
    const target = server();
    const input = "POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 10\r\n\r\nabc";
    _ = try expect_request(target, input, "POST");
    _ = try target.write_response(&test_output, 413, "", &.{.{ .name = "Content-Length", .value = "0" }});
    try testing.expect(target.should_close());
}

test "RFC 9112 §6.3: HEAD, 204 and 304 responses carry no body, and a response without a length ends with the connection" {
    var target = server();
    _ = try expect_request(target, "HEAD / HTTP/1.1\r\nHost: h\r\n\r\n", "HEAD");
    _ = try target.write_response(&test_output, 200, "", &.{.{ .name = "Content-Length", .value = "5" }});
    try testing.expectEqual(connection.Phase.head, target.phase);
    try testing.expectError(error.NoBody, target.write_body(&test_output, "x"));
    target = server();
    _ = try expect_request(target, "GET / HTTP/1.1\r\nHost: h\r\n\r\n", "GET");
    const written = try target.write_response(&test_output, 200, "", &.{});
    try testing.expect(std.mem.indexOf(u8, test_output[0..written], "Connection: close") != null);
    try testing.expectEqual(4, try target.write_body(&test_output, "rest"));
    _ = try target.write_end(&test_output, &.{});
    try testing.expect(target.should_close());
}

test "interim responses precede the final one, 101 is refused, and one final response answers a request" {
    const target = server();
    _ = try expect_request(target, "GET / HTTP/1.1\r\nHost: h\r\n\r\n", "GET");
    try testing.expectError(error.UpgradeUnsupported, target.write_response(&test_output, 101, "", &.{}));
    const interim = try target.write_response(&test_output, 100, "Continue", &.{});
    try testing.expectEqualStrings("HTTP/1.1 100 Continue\r\n\r\n", test_output[0..interim]);
    _ = try target.write_response(&test_output, 200, "", &.{.{ .name = "Content-Length", .value = "1" }});
    // RFC 9112 §9.2: one final response answers a request, even while its body is being written.
    try testing.expectError(error.NoRequest, target.write_response(&test_output, 200, "", &.{}));
    _ = try target.write_body(&test_output, "x");
    _ = try target.write_end(&test_output, &.{});
    try testing.expectError(error.NoRequest, target.write_response(&test_output, 200, "", &.{}));
    try testing.expectError(error.NoRequest, server().write_response(&test_output, 200, "", &.{}));
}

test "RFC 9112 §6.3 rule 2: a 2xx to CONNECT turns the connection into a tunnel" {
    const target = server();
    _ = try expect_request(target, "CONNECT a:443 HTTP/1.1\r\nHost: a:443\r\n\r\n", "CONNECT");
    _ = try target.write_response(&test_output, 200, "", &.{});
    try testing.expectEqual(connection.Phase.tunnel, target.phase);
    try testing.expectEqualStrings("raw", (try target.receive("raw")).event.?.tunnel);
    try testing.expectEqual(3, try target.write_body(&test_output, "raw"));
}

test "a body is written as the head declared it: no more and no fewer octets, chunks and trailers" {
    var target = server();
    _ = try expect_request(target, "GET / HTTP/1.1\r\nHost: h\r\n\r\n", "GET");
    _ = try target.write_response(&test_output, 200, "", &.{.{ .name = "Content-Length", .value = "2" }});
    try testing.expectError(error.BodyTooLong, target.write_body(&test_output, "abc"));
    try testing.expectError(error.BodyIncomplete, target.write_end(&test_output, &.{}));
    _ = try target.write_body(&test_output, "ab");
    // RFC 9112 §7.1.2: only the chunked coding carries a trailer section.
    try testing.expectError(error.TrailersWithoutChunked, target.write_end(&test_output, &.{Field{ .name = "T", .value = "v" }}));
    target = server();
    _ = try expect_request(target, "GET / HTTP/1.1\r\nHost: h\r\n\r\n", "GET");
    _ = try target.write_response(&test_output, 200, "", &.{.{ .name = "Transfer-Encoding", .value = "chunked" }});
    const chunk = try target.write_body(&test_output, "hi");
    try testing.expectEqualStrings("2\r\nhi\r\n", test_output[0..chunk]);
    const last = try target.write_end(&test_output, &.{Field{ .name = "T", .value = "v" }});
    try testing.expectEqualStrings("0\r\nT: v\r\n\r\n", test_output[0..last]);
    try testing.expectEqual(connection.Phase.head, target.phase);
}
