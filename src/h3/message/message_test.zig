//! The tests of `message.zig`, split out because a hand-written source file stays at or under 500
//! lines with its tests included (CLAUDE.md).
//!
//! What they pin is not the shared rules — `src/http/` and h2's tests already cover those — but
//! the three places h3 parts from h2, which is what decision 51's split has to get right.
const std = @import("std");
const http = @import("http");
const constants = @import("../constants.zig");
const message = @import("message.zig");

const testing = std.testing;
const Field = http.field.Field;
const FieldSection = http.FieldSection;

/// The section the tests fill, placed outside any stack frame.
var test_section: FieldSection = undefined;

/// Fills `test_section` with `fields`, in order.
fn section_of(fields: []const Field) !*const FieldSection {
    test_section.init();
    for (fields) |line| try test_section.append(line.name, line.value);
    return &test_section;
}

/// The lines a request the tests build carries: the four request pseudo-headers and Host.
const request_line_count: usize = 5;

fn request_lines(authority: ?[]const u8, host: ?[]const u8) [request_line_count]Field {
    return .{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = authority orelse "" },
        .{ .name = "host", .value = host orelse "" },
    };
}

test "a request the rules admit is returned with what it holds" {
    const lines = request_lines("example.com", "example.com");
    const request = try message.validate_request(try section_of(&lines));
    try testing.expectEqualStrings("GET", request.method);
    try testing.expectEqualStrings("https", request.scheme.?);
    try testing.expectEqualStrings("/", request.path.?);
    try testing.expectEqualStrings("example.com", request.authority.?);
    try testing.expect(!request.is_connect);
    try testing.expectEqual(null, request.content_length);
}

test "RFC 9114 §4.3.1: a request in a scheme with a mandatory authority carries one" {
    // Neither :authority nor Host, which RFC 9113 §8.3.1 permits and RFC 9114 §4.3.1 does not.
    // This is the clearest case of a rule h3 has and h2 does not.
    const lines = [_]Field{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
    };
    try testing.expectError(
        error.AuthorityMissing,
        message.validate_request(try section_of(&lines)),
    );
}

test "RFC 9114 §4.3.1: an authority that is present is not empty, and two that differ are refused" {
    // Present and empty, one way round and then the other.
    for ([_][2][]const u8{ .{ "", "example.com" }, .{ "example.com", "" } }) |pair| {
        const lines = request_lines(pair[0], pair[1]);
        try testing.expectError(
            error.AuthorityEmpty,
            message.validate_request(try section_of(&lines)),
        );
    }
    // Both present and different. colibri normalizes no URI, so a difference of case is a
    // difference: RFC 9114 §4.3.1 says "the same value" and colibri takes the strict side.
    for ([_][2][]const u8{ .{ "example.com", "other.example" }, .{ "example.com", "EXAMPLE.com" } }) |pair| {
        const lines = request_lines(pair[0], pair[1]);
        try testing.expectError(
            error.AuthorityHostDiffer,
            message.validate_request(try section_of(&lines)),
        );
    }
    // Either one alone is enough, so a request with only Host passes.
    const host_only = [_]Field{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "host", .value = "example.com" },
    };
    const request = try message.validate_request(try section_of(&host_only));
    try testing.expectEqual(null, request.authority);
}

test "RFC 9110 §5.5: h3 refuses a value that starts or ends with whitespace, as h2 does" {
    // The rule RFC 9113 §8.2.1 states and RFC 9114 does not. `http` reports it as its own reason
    // so each protocol may answer differently; both answer the same way, for different citations.
    for ([_][]const u8{ " leading", "trailing " }) |value| {
        const lines = [_]Field{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":path", .value = "/" },
            .{ .name = ":authority", .value = "example.com" },
            .{ .name = "x-test", .value = value },
        };
        try testing.expectError(
            error.FieldValueInvalid,
            message.validate_request(try section_of(&lines)),
        );
    }
}

test "RFC 9114 §4.3.1 and §4.1.2: a repeated pseudo-header is refused, whichever it is" {
    // §4.3.1 names :method, :scheme and :path. §4.1.2 makes an invalid value for any
    // pseudo-header malformed, so colibri refuses a repeated :authority too.
    for ([_][]const u8{ ":method", ":scheme", ":path", ":authority" }) |name| {
        const lines = [_]Field{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":path", .value = "/" },
            .{ .name = ":authority", .value = "example.com" },
            .{ .name = name, .value = "repeated" },
        };
        try testing.expectError(
            error.PseudoHeaderRepeated,
            message.validate_request(try section_of(&lines)),
        );
    }
}

test "the shared rules reach h3 under h3's own error names" {
    const cases = [_]struct { lines: []const Field, reason: anyerror }{
        .{ .lines = &.{.{ .name = ":scheme", .value = "https" }}, .reason = error.MethodMissing },
        .{ .lines = &.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":path", .value = "/" },
        }, .reason = error.SchemeMissing },
        .{ .lines = &.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":path", .value = "/" },
            .{ .name = ":authority", .value = "example.com" },
            .{ .name = "connection", .value = "keep-alive" },
        }, .reason = error.ConnectionSpecificField },
        .{ .lines = &.{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":path", .value = "/" },
            .{ .name = ":authority", .value = "example.com" },
            .{ .name = ":protocol", .value = "websocket" },
        }, .reason = error.PseudoHeaderUndefined },
        .{ .lines = &request_lines("user@example.com", "user@example.com"), .reason = error.AuthorityUserinfo },
    };
    for (cases) |case| {
        try testing.expectError(case.reason, message.validate_request(try section_of(case.lines)));
    }
}

test "RFC 9114 §4.3.2: a response carries :status, and h3 has no END_STREAM rule to apply" {
    const lines = [_]Field{.{ .name = ":status", .value = "200" }};
    const response = try message.validate_response(try section_of(&lines));
    try testing.expectEqual(200, response.status.code);
    // RFC 9113 §8.1 refuses an interim response with END_STREAM. h3 has no such flag, so an
    // interim response is returned and the connection decides, with no rule to break here.
    const interim = [_]Field{.{ .name = ":status", .value = "103" }};
    const early = try message.validate_response(try section_of(&interim));
    try testing.expect(early.status.is_interim());
    // RFC 9114 §4.3.2: a response without :status is malformed.
    try testing.expectError(error.StatusMissing, message.validate_response(try section_of(&.{})));
}

test "RFC 9114 §4.3: a trailer section carries no pseudo-header" {
    try message.validate_trailers(try section_of(&.{.{ .name = "x-checksum", .value = "0" }}));
    try testing.expectError(
        error.PseudoHeaderInTrailers,
        message.validate_trailers(try section_of(&.{.{ .name = ":status", .value = "200" }})),
    );
}

test "RFC 9114 §4.1.2: every malformed message is one stream error, H3_MESSAGE_ERROR" {
    try testing.expectEqual(constants.error_message_error, message.verdict(error.MethodMissing));
    try testing.expectEqual(constants.error_message_error, message.verdict(error.AuthorityMissing));
    // RFC 9114 §8.1 assigns H3_MESSAGE_ERROR the value 0x010e.
    try testing.expectEqual(0x010e, constants.error_message_error);
}
