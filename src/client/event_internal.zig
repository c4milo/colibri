//! What the client's own files call on a `Request` and a `Response`, and no program does
//! (decision 115): the Content-Length a request sends, and clearing a response before an exchange
//! writes it. `client.zig` does not export this file, so a program reaches neither.
const std = @import("std");
const assert = std.debug.assert;
const http = @import("http");
const event = @import("event.zig");
const constants = @import("constants.zig");

const Request = event.Request;
const Response = event.Response;

/// The Content-Length value of `request`, written into `digits`, or null when it sends none.
/// RFC 9110 §8.6: a user agent sends one when the request has content, or when its method gives
/// content a meaning, as POST's and PUT's do (RFC 9110 §9.3.3, §9.3.4).
pub fn content_length(request: *const Request, digits: []u8) ?[]const u8 {
    const method = http.method.standard(request.method);
    const defines_content = method == .post or method == .put;
    if (request.body.len == 0 and !defines_content) return null;
    return std.fmt.bufPrint(digits, "{d}", .{request.body.len}) catch unreachable;
}

/// Clears what the client writes into `response`, so an exchange writes it anew, and keeps where
/// the response goes.
pub fn clear(response: *Response) void {
    response.result = .pending;
    response.status = 0;
    response.interims = 0;
    response.body_len = 0;
    response.values_len = 0;
    response.body_sent = 0;
    response.error_code = 0;
    response.coding = null;
    for (response.wanted) |*wanted| wanted.value = null;
    assert(response.result == .pending and response.body_len == 0);
}

const testing = std.testing;

test "clearing a response makes it pending again, and keeps where the response goes" {
    var wanted = [_]event.WantedHeader{.{ .name = "content-type", .value = "text/plain" }};
    var response: Response = .{ .wanted = &wanted };
    response.result = .response;
    response.status = 200;
    response.body_len = 3;
    response.coding = .gzip;
    clear(&response);
    try testing.expectEqual(.pending, response.result);
    try testing.expectEqual(0, response.body_len);
    try testing.expectEqual(null, response.coding);
    try testing.expectEqual(null, response.wanted[0].value);
    try testing.expectEqualStrings("content-type", response.wanted[0].name);
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
