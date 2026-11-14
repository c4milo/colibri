//! The tests of the 100-continue expectation (`expect.zig`). Split out of `expect.zig` so its
//! fixture stays out of the library file.
const std = @import("std");
const http = @import("http");
const event = @import("event.zig");
const expect_module = @import("expect.zig");

const expects_continue = expect_module.expects_continue;

const testing = std.testing;

/// The section the tests read, outside any stack frame. Test-only.
var test_section: http.FieldSection align(@alignOf(http.FieldSection)) = undefined;
/// The section's lines, which each request's headers point to. Test-only.
var test_lines: http.FieldSection.Slice align(@alignOf(http.FieldSection.Slice)) = undefined;
/// The body a request's event points to, whose every read fails (decision 163 ruling 4).
var test_body: std.Io.Reader align(@alignOf(std.Io.Reader)) = event.failing_reader;

/// A request carrying `expect` as its Expect value, at `version`, with content when `end` is
/// false. Test-only.
fn request_with(expect: []const u8, version: event.Version, end: bool) !event.Request {
    test_section.init();
    try test_section.append("host", "a");
    try test_section.append("Expect", expect);
    test_lines = test_section.slice();
    return .{
        .id = event.id_of(1),
        .method = "PUT",
        .version = version,
        .target = "/",
        .scheme = "http",
        .authority = "a",
        .path = "/",
        .query = null,
        .headers = .{ .lines = &test_lines, .first = 0 },
        .body = &test_body,
        .end = end,
    };
}

/// HTTP/1.0, HTTP/1.1 and HTTP/2, numbered as RFC 9110 §2.5 numbers them. Test-only.
const http_1_0: event.Version = .{ .major = 1, .minor = 0 };
const http_1_1: event.Version = .{ .major = 1, .minor = 1 };
const http_2: event.Version = .{ .major = h2_major, .minor = 0 };
const h2_major: u8 = 2;

test "RFC 9110 §10.1.1: a request with content and 100-continue expects a 100, in any case" {
    try testing.expect(expects_continue(try request_with("100-continue", http_1_1, false)));
    try testing.expect(expects_continue(try request_with("100-Continue", http_2, false)));
    try testing.expect(expects_continue(try request_with("foo, 100-continue ", http_1_1, false)));
}

test "RFC 9110 §10.1.1: no 100 for HTTP/1.0, for a request with no content, or for another member" {
    try testing.expect(!expects_continue(try request_with("100-continue", http_1_0, false)));
    try testing.expect(!expects_continue(try request_with("100-continue", http_1_1, true)));
    try testing.expect(!expects_continue(try request_with("200-ok", http_1_1, false)));
}

test "RFC 9110 §10.1.1: the expectation is the Expect field's, and no other field's" {
    var request = try request_with("200-ok", http_1_1, false);
    try test_section.append("x-note", "100-continue");
    // The lines are slices of the section as it was, so the test takes them again.
    test_lines = test_section.slice();
    try testing.expectEqualStrings("100-continue", request.headers.find("x-note").?.value);
    try testing.expect(!expects_continue(request));
}
