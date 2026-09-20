//! Steps 1 and 2 of the check order message.zig states (invariant 7), which are the line-level
//! rules RFC 9113 §8 shares with RFC 9114 §4. The rules themselves live in
//! `http.message_lines` ([decision 51](../../../docs/decisions.md)); this file names h2's errors
//! for the reasons that module returns, which is [decision 15](../../../docs/decisions.md)'s
//! split.
//!
//! Two of the mappings are the whole reason the split has a shape. RFC 9113 §8.2.1 states both
//! the field-value character rule and the leading-or-trailing-whitespace rule, so h2 answers
//! `FieldValueInvalid` to either; RFC 9114 states only the first, so `http` keeps them apart and
//! h3 will map them differently. And RFC 9113 §8.3 forbids a repeat of any pseudo-header name,
//! where RFC 9114 §4.3.1 requires exactly one `:method`, `:scheme` and `:path` and says nothing
//! about `:authority` or `:status`, so h2 refuses every repeat here and h3 will not.
//!
//! Every error is one of message.zig's `Error`: a malformed message, which RFC 9113 §8.1.1 makes
//! a stream error of type PROTOCOL_ERROR. Decision 19 rests on the first pass. `:protocol` is a
//! pseudo-header RFC 9113 does not define, so it is `PseudoHeaderUndefined`, which ends the
//! stream, not the connection.
const std = @import("std");
const http = @import("http");
const message = @import("message.zig");

const Error = message.Error;
const Field = http.field.Field;
const FieldSection = http.FieldSection;

/// The names the shared module owns, re-exported so the rest of h2 reads one name per thing.
pub const Kind = http.message_lines.Kind;
pub const Seen = http.message_lines.Seen;
pub const definitions = http.message_lines.definitions;
pub const is_pseudo_header = http.message_lines.is_pseudo_header;

/// Checks every line of `section`, as a message of `kind`, against steps 1 and 2, and records
/// what step 3 reads. Each reason `http` returns becomes the h2 error RFC 9113 §8 assigns it.
pub fn walk(section: *const FieldSection, kind: Kind) Error!Seen {
    return http.message_lines.walk(section, kind) catch |reason| switch (reason) {
        // RFC 9113 §8.3: all pseudo-header fields appear before all regular field lines.
        error.PseudoHeaderAfterRegular => error.PseudoHeaderAfterRegular,
        // RFC 9113 §8.1: trailers must not include pseudo-header fields.
        error.PseudoHeaderInTrailers => error.PseudoHeaderInTrailers,
        // RFC 9113 §8.3: an undefined pseudo-header, or one defined only for the other kind.
        error.PseudoHeaderUndefined => error.PseudoHeaderUndefined,
        // RFC 9113 §8.3: the same pseudo-header field name must not appear more than once, and
        // §8.3 says it of any pseudo-header, so h2 refuses every repeat.
        error.PseudoHeaderRepeated => error.PseudoHeaderRepeated,
        // RFC 9113 §8.2.1: an invalid field name.
        error.FieldNameInvalid => error.FieldNameInvalid,
        // RFC 9113 §8.2.1 states the forbidden octets and the whitespace position in two MUSTs,
        // and h2 answers one error to both.
        error.FieldValueCharacter, error.FieldValueWhitespace => error.FieldValueInvalid,
        // RFC 9113 §8.2.2: a connection-specific field, or TE outside a request.
        error.ConnectionSpecificField => error.ConnectionSpecificField,
        // RFC 9113 §8.2.2: TE with a member other than "trailers".
        error.TeNotTrailers => error.TeNotTrailers,
    };
}

const testing = std.testing;

/// The section the tests fill, placed outside any stack frame.
var test_section: FieldSection = undefined;

fn line_of(name: []const u8, value: []const u8) Field {
    return .{ .name = name, .value = value };
}

/// Fills `test_section` with `fields`, in order.
fn section_of(fields: []const Field) !*const FieldSection {
    test_section.init();
    for (fields) |field| try test_section.append(field.name, field.value);
    return &test_section;
}

/// The four request pseudo-headers h2spec's http2/8.1.2 cases start from, in its order.
const common_request = [_]Field{
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":scheme", .value = "http" },
    .{ .name = ":path", .value = "/" },
    .{ .name = ":authority", .value = "example.org" },
};

/// The five names RFC 9113 §8.2.2 lists as connection-specific.
const connection_specific_names = [_][]const u8{
    "connection", "proxy-connection", "keep-alive", "transfer-encoding", "upgrade",
};

/// `common_request` followed by `extra`.
fn request_with(extra: []const Field) !*const FieldSection {
    _ = try section_of(&common_request);
    for (extra) |field| try test_section.append(field.name, field.value);
    return &test_section;
}

fn expect_request(err: Error, section: *const FieldSection) !void {
    try testing.expectError(err, message.validate_request(section));
}

fn expect_response(err: Error, section: *const FieldSection) !void {
    try testing.expectError(err, message.validate_response(section, false));
}

fn expect_trailers(err: Error, section: *const FieldSection) !void {
    try testing.expectError(err, message.validate_trailers(section));
}

test "http2/8.1.2/1: a field name with an uppercase letter is FieldNameInvalid, and its lowercase twin passes" {
    try expect_request(error.FieldNameInvalid, try request_with(&.{line_of("X-TEST", "ok")}));
    try expect_request(error.FieldNameInvalid, try request_with(&.{line_of("x-tesT", "ok")}));
    _ = try message.validate_request(try request_with(&.{line_of("x-test", "ok")}));
}

test "an uppercase letter at either end of 0x41-0x5a, or as the first octet alone, is FieldNameInvalid" {
    for ([_][]const u8{ "X-test", "x-A", "x-Z", "A", "Z", "Ax", "xZ" }) |name| {
        try expect_request(error.FieldNameInvalid, try request_with(&.{line_of(name, "ok")}));
        try expect_trailers(error.FieldNameInvalid, try section_of(&.{line_of(name, "ok")}));
    }
    // The neighbours of the range, 0x40 and 0x5b, are not tchar either; a and z are the lowercase
    // letters that pass.
    for ([_][]const u8{ "x-a", "x-z", "a", "z" }) |name| _ = try message.validate_request(try request_with(&.{line_of(name, "ok")}));
}

test "a name with a colon, SP, a control octet, a non-ASCII octet, a delimiter or no octet is FieldNameInvalid" {
    const names = [_][]const u8{ "a:b", "a b", "a\x00b", "a\x7fb", "caf\xc3\xa9", "a\"b", "", "x-@", "x-[" };
    for (names) |name| {
        try expect_request(error.FieldNameInvalid, try request_with(&.{line_of(name, "ok")}));
    }
    _ = try message.validate_request(try request_with(&.{line_of("x-custom_key.1~", "ok")}));
}

test "a value with NUL, LF, CR, another control octet or whitespace at an end is FieldValueInvalid, on any line" {
    const values = [_][]const u8{ "a\x00", "a\nb", "a\rb", "a\x01b", "a\x7f", " a", "a ", "\ta", "a\t" };
    for (values) |value| {
        try expect_request(error.FieldValueInvalid, try request_with(&.{line_of("x-test", value)}));
        const pseudo = try section_of(&.{ line_of(":method", "GET"), line_of(":path", value) });
        try expect_request(error.FieldValueInvalid, pseudo);
    }
    const inner = try request_with(&.{ line_of("x-empty", ""), line_of("x-inner", "a\tb c\x80") });
    _ = try message.validate_request(inner);
}

test "within a line, step 2 checks the name, then the value, then the connection-specific rule" {
    try expect_request(error.FieldNameInvalid, try request_with(&.{line_of("X-TEST", " a")}));
    try expect_request(error.FieldNameInvalid, try request_with(&.{line_of("Connection", "close")}));
    try expect_request(error.FieldValueInvalid, try request_with(&.{line_of("connection", "a\r")}));
    try expect_request(error.FieldValueInvalid, try request_with(&.{line_of("te", "trailers ")}));
    try expect_trailers(error.FieldValueInvalid, try section_of(&.{line_of("te", " trailers")}));
}

test "http2/8.1.2.1/1: an undefined pseudo-header such as :test is PseudoHeaderUndefined" {
    try expect_request(error.PseudoHeaderUndefined, try request_with(&.{line_of(":test", "ok")}));
    try expect_request(error.PseudoHeaderUndefined, try request_with(&.{line_of(":", "ok")}));
    // Extended CONNECT is an undefined pseudo-header, a stream error (decision 19).
    try expect_request(error.PseudoHeaderUndefined, try request_with(&.{line_of(":protocol", "websocket")}));
    // The comparison is exact, so an uppercase letter leaves the name undefined.
    try expect_request(error.PseudoHeaderUndefined, try section_of(&.{line_of(":Method", "GET")}));
    const response = try section_of(&.{ line_of(":status", "200"), line_of(":test", "ok") });
    try expect_response(error.PseudoHeaderUndefined, response);
    _ = try message.validate_request(try request_with(&.{}));
}

test "a pseudo-header name that extends or shortens a defined one is PseudoHeaderUndefined" {
    for ([_][]const u8{ ":methodx", ":method:", ":pat", ":paths", ":schemes", ":authority2" }) |name| {
        try expect_request(error.PseudoHeaderUndefined, try section_of(&.{ line_of(":method", "GET"), line_of(name, "GET") }));
    }
    try expect_request(error.PseudoHeaderUndefined, try section_of(&.{line_of(":methodx", "GET")}));
    try expect_response(error.PseudoHeaderUndefined, try section_of(&.{ line_of(":status", "200"), line_of(":status2", "x") }));
    try expect_response(error.PseudoHeaderUndefined, try section_of(&.{line_of(":statu", "200")}));
}

test "http2/8.1.2.1/2: :status in a request is PseudoHeaderUndefined, and so is each request pseudo-header in a response" {
    try expect_request(error.PseudoHeaderUndefined, try request_with(&.{line_of(":status", "200")}));
    for (common_request) |request_only| {
        try expect_response(error.PseudoHeaderUndefined, try section_of(&.{ line_of(":status", "200"), request_only }));
    }
    const response = try message.validate_response(try section_of(&.{line_of(":status", "200")}), false);
    try testing.expectEqual(200, response.status.code);
}

test "http2/8.1.2.1/3: :method in trailers is PseudoHeaderInTrailers, and trailers without a pseudo-header pass" {
    try expect_trailers(error.PseudoHeaderInTrailers, try section_of(&.{line_of(":method", "POST")}));
    try expect_trailers(error.PseudoHeaderInTrailers, try section_of(&.{line_of(":status", "200")}));
    // In a trailer section no pseudo-header is defined, so even an unknown one is InTrailers.
    try expect_trailers(error.PseudoHeaderInTrailers, try section_of(&.{line_of(":test", "ok")}));
    try message.validate_trailers(try section_of(&.{ line_of("x-checksum", "abc"), line_of("x-checksum", "def") }));
    try message.validate_trailers(try section_of(&.{}));
}

test "http2/8.1.2.1/4: a regular line before the pseudo-headers is PseudoHeaderAfterRegular, in every kind" {
    const request = try section_of(&.{ line_of("x-test", "ok"), common_request[0], common_request[1] });
    try expect_request(error.PseudoHeaderAfterRegular, request);
    // Step 1 checks a line's position before its definition, so an undefined pseudo-header after a
    // regular line is PseudoHeaderAfterRegular, and so is any pseudo-header after one in trailers.
    try expect_request(error.PseudoHeaderAfterRegular, try request_with(&.{ line_of("x-test", "ok"), line_of(":test", "ok") }));
    try expect_response(error.PseudoHeaderAfterRegular, try section_of(&.{ line_of("x-test", "ok"), line_of(":status", "200") }));
    try expect_trailers(error.PseudoHeaderAfterRegular, try section_of(&.{ line_of("x-test", "ok"), line_of(":status", "200") }));
    _ = try message.validate_request(try request_with(&.{line_of("x-test", "ok")}));
}

test "a line with an empty name is a regular line, so a pseudo-header after it is PseudoHeaderAfterRegular" {
    try expect_request(error.PseudoHeaderAfterRegular, try section_of(&.{ line_of("", "x"), line_of(":method", "GET") }));
    try expect_response(error.PseudoHeaderAfterRegular, try section_of(&.{ line_of("", ""), line_of(":status", "200") }));
    try expect_request(error.FieldNameInvalid, try request_with(&.{line_of("", "x")}));
}

test "http2/8.1.2.2/1: connection: keep-alive, and each field RFC 9113 §8.2.2 lists, is ConnectionSpecificField in every kind" {
    for (connection_specific_names) |name| {
        try expect_request(error.ConnectionSpecificField, try request_with(&.{line_of(name, "keep-alive")}));
        try expect_response(error.ConnectionSpecificField, try section_of(&.{ line_of(":status", "200"), line_of(name, "close") }));
        try expect_trailers(error.ConnectionSpecificField, try section_of(&.{line_of(name, "close")}));
    }
    _ = try message.validate_request(try request_with(&.{line_of("x-connection", "keep-alive")}));
}

test "http2/8.1.2.2/2: te: trailers, deflate is TeNotTrailers, and TE of trailers passes in any case" {
    const deflate = [_]Field{ line_of("trailers", "test"), line_of("te", "trailers, deflate") };
    try expect_request(error.TeNotTrailers, try request_with(&deflate));
    try expect_request(error.TeNotTrailers, try request_with(&.{line_of("te", "gzip")}));
    _ = try message.validate_request(try request_with(&.{line_of("te", "trailers")}));
    // "trailers" is a quoted string, which matches in any case (RFC 5234 §2.3, decision 15).
    _ = try message.validate_request(try request_with(&.{line_of("te", "Trailers")}));
}

test "TE in a response or in trailers is ConnectionSpecificField, even with the value trailers" {
    try expect_response(error.ConnectionSpecificField, try section_of(&.{ line_of(":status", "200"), line_of("te", "trailers") }));
    try expect_trailers(error.ConnectionSpecificField, try section_of(&.{line_of("te", "trailers")}));
}

test "http2/8.1.2.3/5, /6, /7: a repeated :method, :scheme or :path is PseudoHeaderRepeated, and so is :authority or :status" {
    for (common_request) |repeat| {
        try expect_request(error.PseudoHeaderRepeated, try request_with(&.{repeat}));
    }
    try expect_response(error.PseudoHeaderRepeated, try section_of(&.{ line_of(":status", "200"), line_of(":status", "200") }));
    const request = try message.validate_request(try section_of(&common_request));
    try testing.expectEqualStrings("example.org", request.authority.?);
}

test "a pseudo-header repeated with an empty value is PseudoHeaderRepeated, because empty is not absent" {
    const path_twice = [_]Field{ line_of(":method", "GET"), line_of(":scheme", "ftp"), line_of(":path", ""), line_of(":path", "") };
    try expect_request(error.PseudoHeaderRepeated, try section_of(&path_twice));
    try expect_request(error.PseudoHeaderRepeated, try section_of(&.{ line_of(":method", ""), line_of(":method", "GET") }));
    try expect_response(error.PseudoHeaderRepeated, try section_of(&.{ line_of(":status", ""), line_of(":status", "200") }));
    const once = try message.validate_request(try section_of(path_twice[0..3]));
    try testing.expectEqualStrings("", once.path.?);
}

test "walk records each pseudo-header value, and whether a regular line was seen" {
    const seen = try walk(try request_with(&.{line_of("x-test", "ok")}), .request);
    try testing.expectEqualStrings("GET", seen.method.?);
    try testing.expectEqualStrings("http", seen.scheme.?);
    try testing.expectEqualStrings("/", seen.path.?);
    try testing.expectEqualStrings("example.org", seen.authority.?);
    try testing.expect(seen.regular_seen and seen.status == null);
    const none = try walk(try section_of(&common_request), .request);
    try testing.expect(!none.regular_seen);
}

test "step 1 reads every line before step 2, so a later pseudo-header is reported before an earlier bad name" {
    // X-TEST breaks §8.2.1, but the :method after it breaks §8.3, which step 1 reads first.
    try expect_request(error.PseudoHeaderAfterRegular, try section_of(&.{ line_of("X-TEST", "ok"), line_of(":method", "GET") }));
    // Likewise a repeated pseudo-header after a bad value on an earlier pseudo-header.
    try expect_request(error.PseudoHeaderRepeated, try section_of(&.{ line_of(":method", " GET"), line_of(":method", "GET") }));
    try expect_request(error.FieldNameInvalid, try section_of(&.{ line_of(":method", "GET"), line_of("X-TEST", "ok") }));
}
