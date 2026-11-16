//! The tests of the `discard` phase of a server's h11 connection (decision 160): the rest of a
//! request body that the final response did not wait for is read and reported to no one, when its
//! known length fits a bound, so the connection serves the next request (RFC 9112 §9.3). A rest
//! past the bound, and a chunked one, closes the connection, and the response's head says so. A
//! program that reads on after its head says `.keep_reading`: its head says nothing, and a
//! chunked rest that it left is read to the bound.
const std = @import("std");
const http = @import("http");
const connection = @import("connection.zig");

const testing = std.testing;
const Connection = connection.Connection;
const Field = http.Field;

/// The connection and buffers the tests use, placed outside any stack frame.
var test_connection: Connection align(@alignOf(Connection)) = undefined;
var test_output: [test_output_len]u8 = undefined;
const test_output_len = 512;
var test_input: [test_input_len]u8 = undefined;
const test_input_len = 4096;

/// The bound the tests give a connection. It is small, so a body can pass it in one buffer.
const test_bound: u64 = 64;

/// The head of a request with a body of `content_len` octets, which the tests answer early.
fn post_head(buffer: []u8, content_len: u64) []const u8 {
    return std.fmt.bufPrint(buffer, "POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: {d}\r\n\r\n", .{content_len}) catch unreachable;
}

const chunked_head = "POST /a HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n";
const next_request = "GET /b HTTP/1.1\r\nHost: h\r\n\r\n";

fn server(discard_len_max: u64) *Connection {
    test_connection.init(.{ .role = .server, .discard_len_max = discard_len_max });
    return &test_connection;
}

/// Reads the request head at the start of `input`, and returns its octets.
fn read_head(target: *Connection, input: []const u8) !usize {
    const received = try target.receive(input, &.{});
    try testing.expect(received.event.? == .request);
    return received.consumed;
}

/// Writes a final 405 that ends with its head, before the body is read, and returns the head.
fn answer_early(target: *Connection) ![]const u8 {
    const written = try target.write_response(&test_output, @intFromEnum(http.Status.method_not_allowed), "Method Not Allowed", &.{.{ .name = "Content-Length", .value = "0" }});
    return test_output[0..written];
}

/// Writes a final 200 whose content stays open, for a program that reads the rest of the request
/// body, and returns the head.
fn answer_reading(target: *Connection) ![]const u8 {
    target.request_body = .keep_reading;
    const written = try target.write_response(&test_output, @intFromEnum(http.Status.ok), "OK", &.{.{ .name = "Content-Length", .value = "2" }});
    return test_output[0..written];
}

/// Writes the content that `answer_reading` declared, which ends the response.
fn end_response(target: *Connection) !void {
    _ = try target.write_body(&test_output, "ok");
    _ = try target.write_end(&test_output, &.{});
}

/// The passes of `read_to_end` that take no octet: the last data event, and the `end` event.
const end_passes = 2;

/// Receives the request body at the start of `input` until its `end` event, as a program that
/// reads it, and returns the octets consumed.
fn read_to_end(target: *Connection, input: []const u8) !usize {
    var offset: usize = 0;
    // Bounded: each pass reports an event or takes an octet at least.
    for (0..input.len + end_passes) |_| {
        const received = try target.receive(input[offset..], &.{});
        offset += received.consumed;
        if (received.event) |event| {
            if (event == .end) return offset;
        }
    }
    return error.TestUnexpectedResult;
}

/// Whether the head says the connection closes after it (RFC 9112 §9.6).
fn says_close(head: []const u8) bool {
    return std.mem.indexOf(u8, head, "Connection: close\r\n") != null;
}

/// Receives from `input` until the connection consumes nothing or reports an event. Returns the
/// octets consumed and the event, if any.
fn receive_until_event(target: *Connection, input: []const u8) !struct { consumed: usize, event: ?Connection.Event } {
    var offset: usize = 0;
    // Bounded: each pass that reports nothing takes an octet at least.
    for (0..input.len + 1) |_| {
        const received = try target.receive(input[offset..], &.{});
        offset += received.consumed;
        if (received.event != null) return .{ .consumed = offset, .event = received.event };
        if (received.consumed == 0) return .{ .consumed = offset, .event = null };
    }
    return error.TestUnexpectedResult;
}

test "decision 160: a body a response did not wait for is read, reported to no one, and the next request follows" {
    const target = server(test_bound);
    var head_buffer: [128]u8 = undefined;
    const head = post_head(&head_buffer, 40);
    @memcpy(test_input[0..head.len], head);
    @memset(test_input[head.len..][0..40], 'x');
    @memcpy(test_input[head.len + 40 ..][0..next_request.len], next_request);
    const input = test_input[0 .. head.len + 40 + next_request.len];
    const at = try read_head(target, input[0 .. head.len + 3]);
    // RFC 9112 §9.6: the connection stays open, so the head carries no close option.
    try testing.expect(!says_close(try answer_early(target)));
    try testing.expectEqual(connection.Phase.discard, target.phase);
    try testing.expect(!target.should_close());
    // RFC 9112 §9.3: the rest of the body is read, in parts, and none of it is reported.
    const part = try receive_until_event(target, input[at .. head.len + 20]);
    try testing.expectEqual(head.len + 20 - at, part.consumed);
    try testing.expectEqual(null, part.event);
    const rest = try receive_until_event(target, input[head.len + 20 ..]);
    try testing.expectEqualStrings("/b", rest.event.?.request.line.target);
    try testing.expectEqual(input.len - head.len - 20, rest.consumed);
}

test "decision 160: a Content-Length at the bound is read, and one octet past it closes after the response" {
    var head_buffer: [128]u8 = undefined;
    for ([_]u64{ test_bound, test_bound + 1 }) |content_len| {
        const target = server(test_bound);
        _ = try read_head(target, post_head(&head_buffer, content_len));
        const head = try answer_early(target);
        const fits = content_len <= test_bound;
        try testing.expectEqual(fits, target.phase == .discard);
        // RFC 9112 §9.3: a server that does not read the whole body closes after its response.
        try testing.expectEqual(!fits, target.should_close());
        // RFC 9110 §10.1.1: the head says whether the connection closes.
        try testing.expectEqual(!fits, says_close(head));
    }
}

test "decision 160 ruling 5 as amended: a chunked body closes after the response, and the head says so" {
    const body = "5\r\nhello\r\n0\r\n\r\n";
    const input = chunked_head ++ body ++ next_request;
    for ([_]bool{ false, true }) |content_open| {
        const target = server(test_bound);
        const at = try read_head(target, input);
        // RFC 9110 §10.1.1: no head knows where a chunked body ends, so the head says the close,
        // whether the response ends at its head or its content is open.
        if (content_open) {
            const written = try target.write_response(&test_output, @intFromEnum(http.Status.ok), "OK", &.{.{ .name = "Content-Length", .value = "2" }});
            try testing.expect(says_close(test_output[0..written]));
            _ = try target.write_body(&test_output, "ok");
            _ = try target.write_end(&test_output, &.{});
        } else {
            try testing.expect(says_close(try answer_early(target)));
        }
        // RFC 9112 §9.3: the connection closes with the body unread, and reads no next request.
        try testing.expectEqual(connection.Phase.closed, target.phase);
        try testing.expect(target.should_close());
        const rest = try receive_until_event(target, input[at..]);
        try testing.expectEqual(null, rest.event);
        try testing.expectEqual(0, rest.consumed);
    }
}

test "decision 160: a request that carries the close option is not read past its response" {
    const target = server(test_bound);
    const input = "POST /a HTTP/1.1\r\nHost: h\r\nConnection: close\r\nContent-Length: 4\r\n\r\n";
    _ = try read_head(target, input);
    // RFC 9112 §9.6: a server that received the close option sends it in its response.
    try testing.expect(says_close(try answer_early(target)));
    try testing.expect(target.should_close());
}

test "decision 160: with no bound, a body a response did not wait for closes the connection" {
    var head_buffer: [128]u8 = undefined;
    for ([_][]const u8{ chunked_head, post_head(&head_buffer, 1) }) |head| {
        const target = server(0);
        _ = try read_head(target, head);
        // RFC 9110 §10.1.1: no octet of the body is read, so the head says that the server closes.
        try testing.expect(says_close(try answer_early(target)));
        try testing.expect(target.should_close());
    }
}

test "decision 160 ruling 5 as amended: a response whose content is open says the close at its head when the rest does not fit" {
    var head_buffer: [128]u8 = undefined;
    const past_len = 8;
    for ([_]bool{ false, true }) |reads_past| {
        const target = server(test_bound);
        _ = try read_head(target, post_head(&head_buffer, test_bound + past_len));
        const written = try target.write_response(&test_output, @intFromEnum(http.Status.ok), "OK", &.{.{ .name = "Content-Length", .value = "2" }});
        // RFC 9110 §10.1.1: the rest is past the bound at the head, so the head says the close.
        try testing.expect(says_close(test_output[0..written]));
        if (reads_past) {
            @memset(test_input[0..past_len], 'x');
            const received = try target.receive(test_input[0..past_len], &.{});
            try testing.expectEqual(past_len, received.event.?.data.len);
        }
        _ = try target.write_body(&test_output, "ok");
        _ = try target.write_end(&test_output, &.{});
        // RFC 9112 §9.6: the head said the close, so the connection closes whatever the program
        // read after it.
        try testing.expectEqual(connection.Phase.closed, target.phase);
        try testing.expect(target.should_close());
    }
}

test "decision 160: a response whose content is open says nothing at its head when the rest fits, and its end starts the discard" {
    var head_buffer: [128]u8 = undefined;
    const target = server(test_bound);
    const head = post_head(&head_buffer, test_bound);
    @memcpy(test_input[0..head.len], head);
    @memset(test_input[head.len..][0..test_bound], 'x');
    @memcpy(test_input[head.len + test_bound ..][0..next_request.len], next_request);
    const input = test_input[0 .. head.len + test_bound + next_request.len];
    const at = try read_head(target, input[0..head.len]);
    const written = try target.write_response(&test_output, @intFromEnum(http.Status.ok), "OK", &.{.{ .name = "Content-Length", .value = "2" }});
    // RFC 9112 §9.6: the rest fits the bound, so the connection stays open and the head says so.
    try testing.expect(!says_close(test_output[0..written]));
    _ = try target.write_body(&test_output, "ok");
    _ = try target.write_end(&test_output, &.{});
    try testing.expectEqual(connection.Phase.discard, target.phase);
    // RFC 9112 §9.3: the rest of the body is read and reported to no one, and the next request
    // follows it.
    const rest = try receive_until_event(target, input[at..]);
    try testing.expectEqualStrings("/b", rest.event.?.request.line.target);
    try testing.expectEqual(input.len - at, rest.consumed);
}

test "decision 160: a response's head is refused while its request's body is discarded" {
    const target = server(test_bound);
    var head_buffer: [128]u8 = undefined;
    _ = try read_head(target, post_head(&head_buffer, 8));
    _ = try answer_early(target);
    // RFC 9112 §9.2: one final response answers a request.
    try testing.expectError(error.NoRequest, target.write_response(&test_output, 200, "OK", &.{}));
}

test "decision 160 ruling 5 as amended: a program that reads on says nothing at its head, and a body it reads whole keeps the connection" {
    const input = chunked_head ++ "5\r\nhello\r\n0\r\n\r\n" ++ next_request;
    const target = server(test_bound);
    var at = try read_head(target, input);
    // RFC 9110 §10.1.1: a server says that it closes, or it continues to read the content.
    try testing.expect(!says_close(try answer_reading(target)));
    at += try read_to_end(target, input[at..]);
    try testing.expectEqual(connection.Phase.waiting, target.phase);
    try end_response(target);
    // RFC 9112 §9.3: the body was read whole, so the connection serves the next request.
    try testing.expect(!target.should_close());
    const rest = try receive_until_event(target, input[at..]);
    try testing.expectEqualStrings("/b", rest.event.?.request.line.target);
    // Each request starts at `.discard`: a program that reads no more of this one says the close.
    try testing.expectEqual(connection.RequestBody.discard, target.request_body);
}

test "decision 160: a chunked rest that a program left, and that ends within the bound, is read with its trailers" {
    const input = chunked_head ++ "5\r\nhello\r\n0\r\nx-t: 1\r\n\r\n" ++ next_request;
    const target = server(test_bound);
    const at = try read_head(target, input);
    try testing.expect(!says_close(try answer_reading(target)));
    // The response ends before the body does, so the `discard` phase reads the rest.
    try end_response(target);
    try testing.expectEqual(connection.Phase.discard, target.phase);
    const rest = try receive_until_event(target, input[at..]);
    try testing.expectEqualStrings("/b", rest.event.?.request.line.target);
    // RFC 9112 §7.1.2: the next request's trailers are its own.
    try testing.expectEqual(0, target.trailers.len());
}

test "decision 160: a chunked rest that a program left, and that does not end within the bound, closes the connection" {
    const target = server(test_bound);
    // The chunk's data ends at the bound, and its CRLF and the last chunk lie past it.
    const data_len = test_bound - "40\r\n".len;
    var buffer: [256]u8 = undefined;
    const chunk = std.fmt.bufPrint(&buffer, "{x}\r\n", .{data_len}) catch unreachable;
    @memcpy(test_input[0..chunked_head.len], chunked_head);
    var length = chunked_head.len;
    @memcpy(test_input[length..][0..chunk.len], chunk);
    length += chunk.len;
    @memset(test_input[length..][0..data_len], 'y');
    length += data_len;
    @memcpy(test_input[length..][0.."\r\n0\r\n\r\n".len], "\r\n0\r\n\r\n");
    length += "\r\n0\r\n\r\n".len;
    const at = try read_head(target, test_input[0..length]);
    try testing.expect(!says_close(try answer_reading(target)));
    try end_response(target);
    const rest = try receive_until_event(target, test_input[at..length]);
    try testing.expectEqual(null, rest.event);
    // The body took every octet the bound allowed, and no more.
    try testing.expectEqual(test_bound, rest.consumed);
    try testing.expect(target.should_close());
}

test "decision 160: a known rest that a program left closes the connection when it is past the bound" {
    var head_buffer: [128]u8 = undefined;
    const past_len = 8;
    for ([_]bool{ false, true }) |reads_past| {
        const target = server(test_bound);
        _ = try read_head(target, post_head(&head_buffer, test_bound + past_len));
        try testing.expect(!says_close(try answer_reading(target)));
        if (reads_past) {
            @memset(test_input[0..past_len], 'x');
            const received = try target.receive(test_input[0..past_len], &.{});
            try testing.expectEqual(past_len, received.event.?.data.len);
        }
        try end_response(target);
        // RFC 9112 §9.3: the rest fits the bound only when the program read the octets past it.
        try testing.expectEqual(reads_past, target.phase == .discard);
        try testing.expectEqual(!reads_past, target.should_close());
    }
}

test "decision 160: a malformed chunk in a discarded body fails the connection, which owes no second response" {
    const target = server(test_bound);
    const input = chunked_head ++ "zz\r\n";
    const at = try read_head(target, input);
    _ = try answer_reading(target);
    try end_response(target);
    try testing.expectError(error.ConnectionFailed, target.receive(input[at..], &.{}));
    try testing.expect(!target.has_pending());
    try testing.expect(target.should_close());
}
