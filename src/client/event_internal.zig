//! What the client's own files call on a `Request` and a `Response`, and no program does
//! (decision 115): the Content-Length a request sends, and clearing a response before an exchange
//! writes it. `client.zig` does not export this file, so a program reaches neither.
const std = @import("std");
const assert = std.debug.assert;
const http = @import("http");
const event = @import("event.zig");
const constants = @import("constants.zig");
const headers = @import("headers.zig");

const Request = event.Request;
const Response = event.Response;

/// The Content-Length value of `request`, written into `digits`, or null when it sends none.
/// RFC 9110 §8.6: a user agent sends one when the request has content, or when its method gives
/// content a meaning, as POST's and PUT's do (RFC 9110 §9.3.3, §9.3.4). A streamed request sends
/// the length it states, and none when it states none (decision 153 ruling 7).
pub fn content_length(request: *const Request, digits: []u8) ?[]const u8 {
    if (request.streamed.request) {
        const stated = request.streamed.request_len orelse return null;
        return std.fmt.bufPrint(digits, "{d}", .{stated}) catch unreachable;
    }
    const method = http.method.standard(request.method);
    const defines_content = method == .post or method == .put;
    if (request.body.len == 0 and !defines_content) return null;
    return std.fmt.bufPrint(digits, "{d}", .{request.body.len}) catch unreachable;
}

/// Whether h11 sends `request`'s body chunked: it goes in pieces and states no length (RFC 9112
/// §7.1, decision 153 ruling 7).
pub fn chunked(request: *const Request) bool {
    return request.streamed.request and request.streamed.request_len == null;
}

/// Clears what the client writes into `response`, so an exchange writes it anew, and keeps where
/// the response goes.
pub fn clear(response: *Response) void {
    response.result = .pending;
    response.status = 0;
    response.interims = 0;
    response.body_len = 0;
    response.body_sent = 0;
    response.error_code = 0;
    response.coding = null;
    headers.clear(&response.headers);
    headers.clear(&response.trailers);
    assert(response.result == .pending and response.body_len == 0);
}

const testing = std.testing;

test "clearing a response makes it pending again, and keeps where the response goes" {
    var buffer: [8]u8 = undefined;
    var response: Response = .{ .headers = .{ .buffer = &buffer, .len = 5 }, .trailers = .{ .buffer = &buffer, .len = 3 } };
    response.result = .response;
    response.status = 200;
    response.body_len = 3;
    response.coding = .gzip;
    clear(&response);
    try testing.expectEqual(.pending, response.result);
    try testing.expectEqual(0, response.body_len);
    try testing.expectEqual(null, response.coding);
    try testing.expectEqual(0, response.headers.len);
    try testing.expectEqual(0, response.trailers.len);
    try testing.expectEqual(buffer.len, response.headers.buffer.len);
}

test "RFC 9110 §8.6: a request names its content's length, and a POST or PUT names it when empty" {
    var digits: [constants.limits.content_length_digits_max]u8 = undefined;
    const get: Request = .{ .method = "GET", .path = "/" };
    try testing.expectEqual(null, content_length(&get, &digits));
    const empty_post: Request = .{ .method = "POST", .path = "/" };
    try testing.expectEqualStrings("0", content_length(&empty_post, &digits).?);
    const put: Request = .{ .method = "PUT", .path = "/", .body = "abc" };
    try testing.expectEqualStrings("3", content_length(&put, &digits).?);
}

test "decision 153: a streamed request states the length it names, and none when it names none" {
    var digits: [constants.limits.content_length_digits_max]u8 = undefined;
    const stated: Request = .{ .method = "POST", .path = "/", .streamed = .{ .request = true, .request_len = 26 } };
    try testing.expectEqualStrings("26", content_length(&stated, &digits).?);
    try testing.expect(!chunked(&stated));
    const unstated: Request = .{ .method = "POST", .path = "/", .streamed = .{ .request = true } };
    try testing.expectEqual(null, content_length(&unstated, &digits));
    try testing.expect(chunked(&unstated));
}
