//! Steps 1 and 2 of the check order message.zig states (invariant 7): the pseudo-header rules of
//! RFC 9113 §8.3 and the field rules of §8.2, over the lines of a decoded field section. `walk`
//! reads the section twice in arrival order and fills a `Seen` record, which message_request.zig
//! and message.zig read for step 3.
//!
//! The first pass applies §8.3 and the second applies §8.2. A pseudo-header that breaks §8.3 is
//! therefore reported before a regular line that breaks §8.2, even when the regular line arrived
//! first. Within a pass, the first line that breaks a rule names the error. Within a line, the
//! rules run in the order message.zig lists them: step 1 checks position, then the trailer rule,
//! then the definition, then the repeat; step 2 checks the name, then the value, then the
//! connection-specific rule.
//!
//! Every error is one of message.zig's `Error`: a malformed message, which RFC 9113 §8.1.1 makes a
//! stream error of type PROTOCOL_ERROR. Decision 19 rests on step 1. `:protocol` is a pseudo-header
//! RFC 9113 does not define, so it is `PseudoHeaderUndefined`, and the peer loses the stream, not
//! the connection.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const http = @import("http");
const message = @import("message.zig");

const Error = message.Error;
const Field = http.field.Field;
const FieldSection = http.FieldSection;

/// Which message a section holds. The kind decides which pseudo-headers are defined (RFC 9113
/// §8.3) and whether TE may appear (§8.2.2).
pub const Kind = enum { request, response, trailers };

/// The five pseudo-headers RFC 9113 defines (§8.3.1, §8.3.2).
const Pseudo = enum { method, scheme, authority, path, status };

/// One defined pseudo-header: its name as §8.3.1 or §8.3.2 spells it, and the kind it is defined
/// for.
const Definition = struct { name: []const u8, pseudo: Pseudo, kind: Kind };

/// The five definitions, in the order §8.3.1 and §8.3.2 give them.
pub const definitions = [_]Definition{
    .{ .name = ":method", .pseudo = .method, .kind = .request },
    .{ .name = ":scheme", .pseudo = .scheme, .kind = .request },
    .{ .name = ":authority", .pseudo = .authority, .kind = .request },
    .{ .name = ":path", .pseudo = .path, .kind = .request },
    .{ .name = ":status", .pseudo = .status, .kind = .response },
};

/// The colon every pseudo-header name starts with (RFC 9113 §8.3).
const pseudo_header_prefix = ":";

/// What `walk` records. Every slice points into the section.
pub const Seen = struct {
    /// The `:method` value, or null when the section has none (RFC 9113 §8.3.1).
    method: ?[]const u8 = null,
    /// The `:scheme` value, or null (RFC 9113 §8.3.1).
    scheme: ?[]const u8 = null,
    /// The `:authority` value, or null (RFC 9113 §8.3.1).
    authority: ?[]const u8 = null,
    /// The `:path` value, or null (RFC 9113 §8.3.1).
    path: ?[]const u8 = null,
    /// The `:status` value, or null (RFC 9113 §8.3.2).
    status: ?[]const u8 = null,
    /// True once step 1 has read a regular line. No pseudo-header may follow one (RFC 9113 §8.3).
    regular_seen: bool = false,

    fn slot(seen: *Seen, pseudo: Pseudo) *?[]const u8 {
        return switch (pseudo) {
            .method => &seen.method,
            .scheme => &seen.scheme,
            .authority => &seen.authority,
            .path => &seen.path,
            .status => &seen.status,
        };
    }
};

/// Checks every line of `section`, as a message of `kind`, against steps 1 and 2, and records
/// what step 3 reads.
pub fn walk(section: *const FieldSection, kind: Kind) Error!Seen {
    assert(section.len() <= core.constants.field_count_max);
    var seen: Seen = .{};
    for (0..section.len()) |index| try check_pseudo_header(&seen, kind, section.get(@intCast(index)));
    for (0..section.len()) |index| try check_line(kind, section.get(@intCast(index)));
    const request_pseudo_seen = seen.method != null or seen.scheme != null or
        seen.authority != null or seen.path != null;
    assert(kind == .request or !request_pseudo_seen);
    assert(kind == .response or seen.status == null);
    return seen;
}

/// True for a name that starts with a colon, which RFC 9113 §8.3 makes a pseudo-header name.
pub fn is_pseudo_header(name: []const u8) bool {
    return std.mem.startsWith(u8, name, pseudo_header_prefix);
}

/// Step 1 for one line. A regular line only marks that one was seen. A pseudo-header must come
/// before every regular line, be defined for `kind`, and not repeat; its value is recorded.
fn check_pseudo_header(seen: *Seen, kind: Kind, line: Field) Error!void {
    if (!is_pseudo_header(line.name)) {
        seen.regular_seen = true;
        return;
    }
    // RFC 9113 §8.3: all pseudo-header fields appear before all regular field lines.
    if (seen.regular_seen) return error.PseudoHeaderAfterRegular;
    // RFC 9113 §8.1: trailers must not include pseudo-header fields.
    if (kind == .trailers) return error.PseudoHeaderInTrailers;
    // RFC 9113 §8.3: an undefined pseudo-header, or one defined only for the other kind, is
    // malformed.
    const slot = slot_of(seen, kind, line.name) orelse return error.PseudoHeaderUndefined;
    // RFC 9113 §8.3: the same pseudo-header field name must not appear more than once.
    if (slot.* != null) return error.PseudoHeaderRepeated;
    slot.* = line.value;
    assert(slot.* != null and !seen.regular_seen);
}

/// The slot in `seen` for the pseudo-header `name` in a message of `kind`, or null when `kind`
/// does not define it. The comparison is exact, because RFC 9113 §8.2 makes every name lowercase.
fn slot_of(seen: *Seen, kind: Kind, name: []const u8) ?*?[]const u8 {
    assert(kind != .trailers);
    assert(is_pseudo_header(name));
    for (definitions) |definition| {
        // RFC 9113 §8.3: a pseudo-header field is valid only in the context it is defined for.
        const defined = definition.kind == kind and std.mem.eql(u8, name, definition.name);
        if (defined) return seen.slot(definition.pseudo);
    }
    return null;
}

/// Step 2 for one line. A pseudo-header's name was compared exactly in step 1, so only its value
/// is read here.
fn check_line(kind: Kind, line: Field) Error!void {
    if (is_pseudo_header(line.name)) return check_value(line.value);
    try check_name(line.name);
    try check_value(line.value);
    try check_connection_specific(kind, line);
}

/// A regular field name, against RFC 9113 §8.2.1.
fn check_name(name: []const u8) Error!void {
    assert(!is_pseudo_header(name));
    assert(name.len <= core.constants.field_name_len_max);
    for (name) |octet| {
        // RFC 9113 §8.2.1: a field name must not contain 0x41-0x5a, the uppercase letters.
        if (std.ascii.isUpper(octet)) return error.FieldNameInvalid;
    }
    http.field.validate_name(name) catch |reason| switch (reason) {
        // RFC 9113 §8.2.1: no octet in 0x00-0x20 or 0x7f-0xff and no colon, and none of them is a
        // tchar. Any other octet outside a token fails RFC 9110 §5.1, which §8.2.1 asks a
        // recipient to check and to treat as malformed.
        error.FieldNameNotToken => return error.FieldNameInvalid,
        // RFC 9113 §8.2.1 asks for RFC 9110 §5.1's check, and a token holds at least one tchar.
        error.FieldNameEmpty => return error.FieldNameInvalid,
        // `FieldSection.append` holds every name to `field_name_len_max`, asserted above.
        error.FieldNameTooLong => unreachable,
    };
}

/// A field value on any line, against RFC 9113 §8.2.1.
fn check_value(value: []const u8) Error!void {
    assert(value.len <= core.constants.field_value_len_max);
    http.field.validate_value(value) catch |reason| switch (reason) {
        // RFC 9113 §8.2.1: a field value must not contain NUL, LF or CR at any position.
        error.FieldValueNulCarriageReturnOrLineFeed => return error.FieldValueInvalid,
        // RFC 9113 §8.2.1: a field value must not start or end with SP or HTAB.
        error.FieldValueLeadingWhitespace => return error.FieldValueInvalid,
        // RFC 9113 §8.2.1: a field value must not start or end with SP or HTAB.
        error.FieldValueTrailingWhitespace => return error.FieldValueInvalid,
        // RFC 9113 §8.2.1: a recipient checks a value against RFC 9110 §5.5, which admits no other
        // control octet, and treats a violation as malformed.
        error.FieldValueControl => return error.FieldValueInvalid,
        // `FieldSection.append` holds every value to `field_value_len_max`, asserted above.
        error.FieldValueTooLong => unreachable,
    };
}

/// The connection-specific rule of RFC 9113 §8.2.2, with its one exception for TE.
fn check_connection_specific(kind: Kind, line: Field) Error!void {
    const which = http.connection_specific.classify(line.name) orelse return;
    // RFC 9113 §8.2.2: a message containing a connection-specific field is malformed.
    if (which != .te) return error.ConnectionSpecificField;
    // RFC 9113 §8.2.2: TE is the one exception, and only in a request.
    if (kind != .request) return error.ConnectionSpecificField;
    // RFC 9113 §8.2.2: TE must not contain any value other than "trailers".
    if (!http.connection_specific.te_is_trailers(line.value)) return error.TeNotTrailers;
    assert(kind == .request and which == .te);
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
    // The neighbours of the range, 0x40 and 0x5b, are not tchar either; a and z are the legal twins.
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
