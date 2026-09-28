//! The tests of the server's h11 half (`connection_h11.zig`) in cleartext: requests arrive as the
//! server's events, and responses go out framed as RFC 9112 §6 requires.
const std = @import("std");
const support = @import("connection_test_support.zig");

const testing = std.testing;
const connection = &support.connection;

const get_request = "GET /index.html HTTP/1.1\r\nHost: example.test\r\n\r\n";
const content_type = [_]support.Field{.{ .name = "content-type", .value = "text/plain" }};
const ok: u16 = 200;
const no_content: u16 = 204;
const not_modified: u16 = 304;
const early_hints: u16 = 103;

/// Reads `request` and expects its head, with the id `id`.
fn expect_request(request: []const u8, id: u64) !support.Request {
    const received = try support.receive_copy(request);
    try testing.expectEqual(request.len, received.consumed);
    const head = received.event.?.request;
    try testing.expectEqual(id, head.id);
    return head;
}

test "RFC 9112 §3.3: a request's head arrives with its target URI's parts and its fields" {
    try support.start_cleartext(.h11);
    const head = try expect_request(get_request, 1);
    try testing.expectEqualStrings("GET", head.method);
    try testing.expectEqualStrings("http", head.scheme.?);
    try testing.expectEqualStrings("example.test", head.authority.?);
    try testing.expectEqualStrings("/index.html", head.path.?);
    try testing.expectEqualStrings("example.test", head.fields.find("host").?.value);
    try testing.expect(head.end);
}

test "RFC 9112 §7.1: content of unknown length goes out chunked to an HTTP/1.1 request" {
    try support.start_cleartext(.h11);
    _ = try expect_request(get_request, 1);
    try connection.respond(1, ok, &content_type, false);
    try testing.expectEqual(5, try connection.write_body(1, "hello", true));
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\n" ++
        "transfer-encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n", support.drain());
    // The response is whole, so the next request is read.
    _ = try expect_request(get_request, 2);
}

test "RFC 9110 §8.6: a response that ends with its head carries Content-Length: 0" {
    try support.start_cleartext(.h11);
    _ = try expect_request(get_request, 1);
    try connection.respond(1, ok, &.{}, true);
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n", support.drain());
}

test "RFC 9112 §6.3: a caller's own Content-Length frames the content, and more is refused" {
    try support.start_cleartext(.h11);
    _ = try expect_request(get_request, 1);
    const length = [_]support.Field{.{ .name = "content-length", .value = "5" }};
    try connection.respond(1, ok, &length, false);
    try testing.expectError(error.ContentLengthMismatch, connection.write_body(1, "hello!", true));
    try testing.expectEqual(5, try connection.write_body(1, "hello", true));
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\ncontent-length: 5\r\n\r\nhello", support.drain());
}

test "RFC 9112 §6.3 rule 1: a 204, a 304 and a response to HEAD carry no framing field" {
    try support.start_cleartext(.h11);
    _ = try expect_request(get_request, 1);
    try connection.respond(1, no_content, &.{}, true);
    try testing.expectEqualStrings("HTTP/1.1 204 No Content\r\n\r\n", support.drain());
    _ = try expect_request(get_request, 2);
    try connection.respond(2, not_modified, &.{}, true);
    try testing.expectEqualStrings("HTTP/1.1 304 Not Modified\r\n\r\n", support.drain());
    _ = try expect_request("HEAD / HTTP/1.1\r\nHost: a\r\n\r\n", 3);
    try connection.respond(3, ok, &content_type, false);
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\n\r\n", support.drain());
    // RFC 9110 §9.3.2: a response to HEAD has no content.
    try testing.expectError(error.SectionOutOfOrder, connection.write_body(3, "x", true));
}

test "RFC 9112 §6.3 rule 8: an HTTP/1.0 request's response runs until the close" {
    try support.start_cleartext(.h11);
    _ = try expect_request("GET / HTTP/1.0\r\n\r\n", 1);
    try connection.respond(1, ok, &.{}, false);
    _ = try connection.write_body(1, "hello", true);
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nhello", support.drain());
    try testing.expect(connection.should_close());
}

test "RFC 9110 §15.2: an interim response comes before the final one, and needs no framing" {
    try support.start_cleartext(.h11);
    _ = try expect_request(get_request, 1);
    try connection.respond(1, early_hints, &.{}, true);
    try connection.respond(1, ok, &.{}, true);
    // RFC 9112 §4: 103 is not one of RFC 9110 §15's codes, so its reason phrase is empty.
    try testing.expectEqualStrings("HTTP/1.1 103 \r\n\r\nHTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n", support.drain());
}

test "RFC 9112 §6.1: a request's content arrives as body events, then its end" {
    try support.start_cleartext(.h11);
    const request = "POST /upload HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\n\r\nhello";
    @memcpy(support.input[0..request.len], request);
    var received = try connection.receive(support.input[0..request.len], support.now_ns);
    try testing.expect(!received.event.?.request.end);
    var consumed = received.consumed;
    received = try connection.receive(support.input[consumed..request.len], support.now_ns);
    consumed += received.consumed;
    try testing.expectEqualStrings("hello", received.event.?.body.octets);
    try testing.expect(!received.event.?.body.end);
    received = try connection.receive(support.input[consumed..request.len], support.now_ns);
    try testing.expect(received.event.?.body.end);
    try testing.expectEqual(request.len, consumed + received.consumed);
}

test "RFC 9112 §7.1.2: a chunked request's trailer section ends it" {
    try support.start_cleartext(.h11);
    const request = "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n" ++
        "2\r\nhi\r\n0\r\ngrpc-status: 0\r\n\r\n";
    @memcpy(support.input[0..request.len], request);
    var consumed: usize = 0;
    var trailers: ?support.Trailers = null;
    // Bounded: the head, the data, and the end.
    for (0..request.len) |_| {
        const received = try connection.receive(support.input[consumed..request.len], support.now_ns);
        consumed += received.consumed;
        const reported = received.event orelse break;
        if (reported == .trailers) trailers = reported.trailers;
    }
    try testing.expectEqualStrings("0", trailers.?.fields.find("grpc-status").?.value);
    try testing.expectEqual(1, trailers.?.id);
}

test "RFC 9112 §3.2.2: an absolute-form target's authority replaces Host's" {
    try support.start_cleartext(.h11);
    const head = try expect_request("GET http://origin.test/a?b HTTP/1.1\r\nHost: other.test\r\n\r\n", 1);
    try testing.expectEqualStrings("http", head.scheme.?);
    try testing.expectEqualStrings("origin.test", head.authority.?);
    try testing.expectEqualStrings("/a?b", head.path.?);
    const bare = try expect_after_response("GET http://origin.test HTTP/1.1\r\nHost: origin.test\r\n\r\n", 2);
    // RFC 9110 §4.2.3: an empty path is "/".
    try testing.expectEqualStrings("/", bare.path.?);
}

/// Answers request `id - 1` and reads `request` as request `id`. Test-only.
fn expect_after_response(request: []const u8, id: u64) !support.Request {
    try connection.respond(id - 1, ok, &.{}, true);
    _ = support.drain();
    return expect_request(request, id);
}

test "RFC 9112 §9.3.2: h11 answers the request it read last, and no other" {
    try support.start_cleartext(.h11);
    _ = try expect_request(get_request, 1);
    try testing.expectError(error.RequestUnknown, connection.respond(2, ok, &.{}, true));
    try testing.expectError(error.RequestUnknown, connection.respond(0, ok, &.{}, true));
    try connection.respond(1, ok, &.{}, true);
    // A second final response is out of order.
    try testing.expectError(error.SectionOutOfOrder, connection.respond(1, ok, &.{}, true));
}

test "RFC 9112 §9.6: a shutdown ends the connection after the current response" {
    try support.start_cleartext(.h11);
    _ = try expect_request(get_request, 1);
    connection.shutdown();
    try testing.expect(!connection.should_close());
    try connection.respond(1, ok, &.{}, true);
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\ncontent-length: 0\r\nConnection: close\r\n\r\n", support.drain());
    try testing.expect(connection.should_close());
}

test "RFC 9112 §9.6: a shutdown with no request open ends the connection at once" {
    try support.start_cleartext(.h11);
    connection.shutdown();
    try testing.expect(connection.should_close());
    // A request that arrives after it is not read.
    try testing.expectEqual(null, (try support.receive_copy(get_request)).event);
}

test "RFC 9112 §9.6: h11 cannot cancel one request, so a cancel ends the connection" {
    try support.start_cleartext(.h11);
    _ = try expect_request(get_request, 1);
    connection.cancel(1);
    try testing.expect(connection.should_close());
    try testing.expectError(error.ConnectionClosed, connection.respond(1, ok, &.{}, true));
}

test "decision 92: a malformed request fails the connection, and the 400 goes out" {
    try support.start_cleartext(.h11);
    try testing.expectError(error.ConnectionFailed, support.receive_copy("GET / HTTP/1.1\r\n\r\n"));
    try testing.expect(!connection.should_close());
    const sent = support.drain();
    try testing.expect(std.mem.startsWith(u8, sent, "HTTP/1.1 400 Bad Request\r\n"));
    try testing.expect(connection.should_close());
}

test "RFC 9112 §3.2.3, §3.2.4: CONNECT's target is an authority, and OPTIONS * has the path *" {
    try support.start_cleartext(.h11);
    const connect = try expect_request("CONNECT origin.test:443 HTTP/1.1\r\nHost: origin.test:443\r\n\r\n", 1);
    try testing.expectEqual(null, connect.scheme);
    try testing.expectEqualStrings("origin.test:443", connect.authority.?);
    try testing.expectEqual(null, connect.path);
    // RFC 9112 §6.3 rule 2: a 2xx to CONNECT makes the connection a tunnel, with no framing field.
    try connection.respond(1, ok, &.{}, false);
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\n\r\n", support.drain());
    try support.start_cleartext(.h11);
    const options = try expect_request("OPTIONS * HTTP/1.1\r\nHost: a\r\n\r\n", 1);
    try testing.expectEqualStrings("*", options.path.?);
}

test "RFC 9112 §7.1.2: a chunked response's trailer section ends it" {
    try support.start_cleartext(.h11);
    _ = try expect_request(get_request, 1);
    const trailers = [_]support.Field{.{ .name = "grpc-status", .value = "0" }};
    // RFC 9110 §6.5: trailers follow a final response.
    try testing.expectError(error.SectionOutOfOrder, connection.write_trailers(1, &trailers));
    try connection.respond(1, ok, &.{}, false);
    try testing.expectEqual(0, try connection.write_body(1, "", false));
    _ = try connection.write_body(1, "hi", false);
    try connection.write_trailers(1, &trailers);
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n" ++
        "2\r\nhi\r\n0\r\ngrpc-status: 0\r\n\r\n", support.drain());
}

test "RFC 9112 §7.1.2: a response framed by Content-Length carries no trailer section" {
    try support.start_cleartext(.h11);
    _ = try expect_request(get_request, 1);
    const length = [_]support.Field{.{ .name = "content-length", .value = "2" }};
    try connection.respond(1, ok, &length, false);
    _ = try connection.write_body(1, "hi", false);
    const trailers = [_]support.Field{.{ .name = "grpc-status", .value = "0" }};
    try testing.expectError(error.TrailersRefused, connection.write_trailers(1, &trailers));
}

test "RFC 9112 §9.6: a cancel of another request leaves the connection open" {
    try support.start_cleartext(.h11);
    _ = try expect_request(get_request, 1);
    connection.cancel(2);
    try connection.respond(1, ok, &.{}, true);
    try testing.expect(!connection.should_close());
}

/// Field lines a response may carry, and one more. Test-only.
var many_fields: [core_field_count_max]support.Field align(@alignOf(support.Field)) = @splat(.{ .name = "x-a", .value = "b" });
const core_field_count_max = @import("core").constants.field_count_max;

test "RFC 9110 §5.4: a response whose framing field makes one line too many is refused" {
    try support.start_cleartext(.h11);
    _ = try expect_request(get_request, 1);
    try testing.expectError(error.SectionTooLarge, connection.respond(1, ok, &many_fields, true));
    try testing.expectEqual(0, connection.output_len);
}

/// Content that fills the output. Test-only.
var filling: [support.server_constants.output_len]u8 = @splat('x');

test "RFC 9112 §7.1: content waits once the output holds no whole chunk, and ends once all is out" {
    try support.start_cleartext(.h11);
    _ = try expect_request(get_request, 1);
    try connection.respond(1, ok, &.{}, false);
    // Not every octet fits, so the body does not end on this call.
    const taken = try connection.write_body(1, &filling, true);
    try testing.expect(taken > 0 and taken < filling.len);
    try testing.expectError(error.Blocked, connection.write_body(1, filling[taken..], true));
    _ = support.drain();
    try testing.expectEqual(filling.len - taken, try connection.write_body(1, filling[taken..], true));
    try testing.expect(std.mem.endsWith(u8, support.drain(), "\r\n0\r\n\r\n"));
}

test "RFC 9112 §7.1: a response that ends with its head keeps room for its last chunk" {
    try support.start_cleartext(.h11);
    _ = try expect_request(get_request, 1);
    const chunked = [_]support.Field{.{ .name = "transfer-encoding", .value = "chunked" }};
    const head = "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n";
    // Room for the head, but not for the head and the last chunk: nothing goes out.
    const short_room = head.len + 1;
    connection.output_len = support.server_constants.output_len - short_room;
    const before = connection.output_len;
    try testing.expectError(error.NoSpaceLeft, connection.respond(1, ok, &chunked, true));
    try testing.expectEqual(before, connection.output_len);
    // Room for less than the last chunk holds no response at all.
    connection.output_len = support.server_constants.output_len - 1;
    try testing.expectError(error.NoSpaceLeft, connection.respond(1, ok, &chunked, true));
    connection.output_len = 0;
    try connection.respond(1, ok, &chunked, true);
    try testing.expectEqualStrings(head ++ "0\r\n\r\n", support.drain());
}

test "RFC 9112 §9.6: a shutdown waits for a request whose head is arriving" {
    try support.start_cleartext(.h11);
    const partial = "GET / HTTP/1.1\r\nHo";
    const received = try support.receive_copy(partial);
    try testing.expectEqual(null, received.event);
    connection.shutdown();
    try testing.expect(!connection.should_close());
}

test "RFC 9112 §8: a transport that closed ends the connection and every request on it" {
    try support.start_cleartext(.h11);
    _ = try expect_request(get_request, 1);
    // Idempotent: the second call leaves the connection as the first did.
    for (0..2) |_| {
        connection.transport_closed();
        try testing.expect(connection.should_close());
        try testing.expectError(error.ConnectionClosed, connection.respond(1, ok, &.{}, true));
        try testing.expectEqual(0, (try support.receive_copy(get_request)).consumed);
    }
}

const expecting_request = "PUT /f HTTP/1.1\r\nHost: a\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n";

test "RFC 9110 §10.1.1: a request expecting 100-continue gets the 100 before its content is read" {
    try support.start_cleartext(.h11);
    const head = try expect_request(expecting_request, 1);
    try testing.expectEqual(1, head.version.major);
    try testing.expectEqual(1, head.version.minor);
    try testing.expectEqualStrings("/f", head.target);
    try testing.expect(!head.end);
    // The caller reads on, so the 100 goes out, once.
    try testing.expectEqual(null, (try connection.receive(&.{}, support.now_ns)).event);
    try testing.expectEqualStrings("HTTP/1.1 100 Continue\r\n\r\n", support.drain());
    try testing.expectEqualStrings("", support.drain());
}

test "RFC 9110 §10.1.1: a final response, or the caller's own 100, replaces the 100 owed" {
    try support.start_cleartext(.h11);
    _ = try expect_request(expecting_request, 1);
    const content_too_large: u16 = 413;
    try connection.respond(1, content_too_large, &.{}, true);
    try testing.expectEqualStrings("HTTP/1.1 413 Content Too Large\r\ncontent-length: 0\r\n\r\n", support.drain());
    try testing.expectEqual(null, connection.continue_owed);
    try support.start_cleartext(.h11);
    _ = try expect_request(expecting_request, 1);
    const hundred: u16 = 100;
    try connection.respond(1, hundred, &.{}, false);
    try testing.expectEqualStrings("HTTP/1.1 100 Continue\r\n\r\n", support.drain());
}

test "RFC 9110 §10.1.1: an interim response other than 100 leaves the 100 owed" {
    try support.start_cleartext(.h11);
    _ = try expect_request(expecting_request, 1);
    try connection.respond(1, early_hints, &.{}, false);
    try testing.expectEqualStrings("HTTP/1.1 103 \r\n\r\nHTTP/1.1 100 Continue\r\n\r\n", support.drain());
}

test "RFC 9110 §10.1.1: the 100 waits for room, and goes out once there is some" {
    try support.start_cleartext(.h11);
    _ = try expect_request(expecting_request, 1);
    const short_room: usize = 4;
    connection.output_len = support.server_constants.output_len - short_room;
    try testing.expectEqual(0, (try connection.receive(&.{}, support.now_ns)).consumed);
    try testing.expectEqual(1, connection.continue_owed.?);
    connection.output_len = 0;
    try testing.expectEqualStrings("HTTP/1.1 100 Continue\r\n\r\n", support.drain());
}

test "RFC 9110 §10.1.1: a request cancelled before its 100 gets none" {
    try support.start_cleartext(.h11);
    _ = try expect_request(expecting_request, 1);
    connection.cancel(1);
    try testing.expectEqualStrings("", support.drain());
    try testing.expectEqual(null, connection.continue_owed);
}
