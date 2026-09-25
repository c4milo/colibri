//! The field lines of a head (RFC 9112 §5), read into a `FieldSection`, the one model h2 and h3
//! fill too (decision 15). The octets arrive as `message_scan` delimited them: each line ends with
//! CRLF, no line holds another CR or LF, and the empty line ends the section.
//!
//! RFC 9112 leaves three choices, and colibri takes the strict side of each where the RFC lets it:
//!   - whitespace between the start line and the first field line (§2.2) is refused, for both
//!     roles;
//!   - whitespace between a field name and its colon (§5.1) is refused. A server MUST refuse it
//!     with 400; a user agent has no rule of its own, and colibri refuses it there too;
//!   - obs-fold (§5.2) in a request is refused, which a server may do. In a response, a user agent
//!     MUST replace each obs-fold with SP, so the client joins the folded lines of one value with
//!     one SP.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const http = @import("http");
const constants = @import("../constants.zig");
const message_scan = @import("message_scan.zig");

const FieldSection = http.FieldSection;
const Role = message_scan.Role;

pub const Error = error{
    /// Whitespace between the start line and the first field line (RFC 9112 §2.2).
    WhitespaceBeforeFields,
    /// A field line with no colon (RFC 9112 §5).
    FieldLineInvalid,
    /// Whitespace between a field name and its colon (RFC 9112 §5.1).
    WhitespaceBeforeColon,
    /// A field name that is not a token, or is longer than colibri accepts (RFC 9110 §5.1).
    FieldNameInvalid,
    /// A field value holding NUL or another control, or longer than colibri accepts
    /// (RFC 9110 §5.5).
    FieldValueInvalid,
    /// obs-fold in a request (RFC 9112 §5.2).
    ObsFold,
    /// A section larger than `field_section_size_max` (RFC 9110 §5.4).
    SectionTooLarge,
    /// A section of more than `field_count_max` lines (RFC 9110 §5.4).
    TooManyLines,
};

/// The CR and LF that end every line (RFC 9112 §2.1).
const line_end = "\r\n";

/// OWS and RWS are made of SP and HTAB (RFC 9110 §5.6.3).
const whitespace = " \t";

/// The octet that joins the lines of a folded value (RFC 9112 §5.2).
const fold_replacement = " ";

/// Most lines a head holds: every line takes at least its CRLF.
const lines_max = constants.head_len_max / line_end.len;

/// Reads the field lines of `octets`, up to and including the empty line that ends them, into
/// `section`, which it empties first.
pub fn parse(role: Role, octets: []const u8, section: *FieldSection) Error!void {
    assert(octets.len <= constants.head_len_max);
    assert(std.mem.endsWith(u8, octets, line_end));
    section.init();
    var rest = octets;
    for (0..lines_max) |index| {
        const line, rest = std.mem.cut(u8, rest, line_end) orelse unreachable;
        if (line.len == 0) {
            assert(rest.len == 0);
            return;
        }
        if (!is_whitespace(line[0])) {
            try append_line(section, line);
            continue;
        }
        // RFC 9112 §2.2: whitespace between the start line and the first field line is invalid,
        // or the line is ignored; colibri refuses it.
        if (index == 0) return error.WhitespaceBeforeFields;
        // RFC 9112 §5.2: a server may reject obs-fold in a request with 400, and colibri does.
        if (role == .request) return error.ObsFold;
        try join_fold(section, line);
    }
    unreachable;
}

/// `field-line = field-name ":" OWS field-value OWS` (RFC 9112 §5).
fn append_line(section: *FieldSection, line: []const u8) Error!void {
    assert(line.len > 0 and !is_whitespace(line[0]));
    // RFC 9112 §5: a field name, then a colon.
    const name, const value_octets = std.mem.cutScalar(u8, line, ':') orelse
        return error.FieldLineInvalid;
    // RFC 9112 §5.1: no whitespace is allowed between the field name and the colon.
    if (std.mem.trimEnd(u8, name, whitespace).len != name.len) return error.WhitespaceBeforeColon;
    // RFC 9110 §5.1: field-name = token.
    http.field.validate_name(name) catch return error.FieldNameInvalid;
    // RFC 9112 §5.1: the OWS before and after the value is not part of it.
    const value = std.mem.trim(u8, value_octets, whitespace);
    // RFC 9110 §5.5: a value holds field-vchar, SP and HTAB, and no NUL, CR, LF or other CTL.
    http.field.validate_value(value) catch return error.FieldValueInvalid;
    section.append(name, value) catch |failure| return switch (failure) {
        error.SectionTooLarge => error.SectionTooLarge,
        error.TooManyLines => error.TooManyLines,
    };
}

/// A line that continues the last value, `obs-fold = OWS CRLF RWS` (RFC 9112 §5.2), in a
/// response. A line that is only whitespace adds nothing.
fn join_fold(section: *FieldSection, line: []const u8) Error!void {
    assert(section.len() > 0);
    assert(line.len > 0 and is_whitespace(line[0]));
    const segment = std.mem.trim(u8, line, whitespace);
    if (segment.len == 0) return;
    // RFC 9110 §5.5: the joined value holds the same octets a value may hold.
    http.field.validate_value(segment) catch return error.FieldValueInvalid;
    const last = section.get(section.len() - 1);
    const joined_len = last.value.len + fold_replacement.len + segment.len;
    // RFC 9110 §5.4: no predefined limit on a value, so colibri's applies to the joined one.
    if (joined_len > core.constants.field_value_len_max) return error.FieldValueInvalid;
    // RFC 9112 §5.2: a user agent MUST replace each obs-fold with one or more SP octets. After an
    // empty value that SP would lead the value, and RFC 9112 §5.1 leaves leading OWS out of it.
    if (last.value.len > 0) section.extend_last(fold_replacement) catch return error.SectionTooLarge;
    // RFC 9110 §5.4: no predefined limit on a section, so colibri's applies to the joined value.
    section.extend_last(segment) catch return error.SectionTooLarge;
}

fn is_whitespace(octet: u8) bool {
    return octet == ' ' or octet == '\t';
}

const testing = std.testing;

/// The section the tests fill, placed outside any stack frame.
var test_section: FieldSection = undefined;

fn expect_fields(role: Role, octets: []const u8, expected: []const http.field.Field) !void {
    try parse(role, octets, &test_section);
    try testing.expectEqual(expected.len, test_section.len());
    for (expected, 0..) |want, index| {
        const got = test_section.get(@intCast(index));
        try testing.expectEqualStrings(want.name, got.name);
        try testing.expectEqualStrings(want.value, got.value);
    }
}

fn expect_refused(role: Role, octets: []const u8, err: Error) !void {
    try testing.expectError(err, parse(role, octets, &test_section));
}

test "field lines read in order, with the OWS around each value left out" {
    try expect_fields(.request, "Host: a\r\nX-Two:  b c \t\r\nEmpty:\r\n\r\n", &.{
        .{ .name = "Host", .value = "a" },
        .{ .name = "X-Two", .value = "b c" },
        .{ .name = "Empty", .value = "" },
    });
    try expect_fields(.response, "\r\n", &.{});
}

test "RFC 9112 §5.1: whitespace before the colon is refused in either role" {
    try expect_refused(.request, "Host : a\r\n\r\n", error.WhitespaceBeforeColon);
    try expect_refused(.request, "Host\t: a\r\n\r\n", error.WhitespaceBeforeColon);
    try expect_refused(.response, "Content-Length : 5\r\n\r\n", error.WhitespaceBeforeColon);
}

test "a line with no colon, an empty or non-token name, or a control in the value is refused" {
    try expect_refused(.request, "Host a\r\n\r\n", error.FieldLineInvalid);
    try expect_refused(.request, ": a\r\n\r\n", error.FieldNameInvalid);
    try expect_refused(.request, "Ho(st: a\r\n\r\n", error.FieldNameInvalid);
    try expect_refused(.request, "Host: a\x00b\r\n\r\n", error.FieldValueInvalid);
    try expect_refused(.response, "Host: a\x0bb\r\n\r\n", error.FieldValueInvalid);
    try expect_fields(.request, "X: a\x80\xff\tb\r\n\r\n", &.{.{ .name = "X", .value = "a\x80\xff\tb" }});
}

test "RFC 9112 §2.2: whitespace before the first field line is refused in either role" {
    try expect_refused(.request, " Host: a\r\n\r\n", error.WhitespaceBeforeFields);
    try expect_refused(.response, "\tX: a\r\n\r\n", error.WhitespaceBeforeFields);
}

test "RFC 9112 §5.2: obs-fold is refused in a request and joined with one SP in a response" {
    try expect_refused(.request, "X: a\r\n b\r\n\r\n", error.ObsFold);
    try expect_fields(.response, "X: a \r\n \t b\r\n\tc\r\nY: d\r\n\r\n", &.{
        .{ .name = "X", .value = "a b c" },
        .{ .name = "Y", .value = "d" },
    });
    // A continuation that is only whitespace adds nothing, and one after an empty value adds no
    // leading SP (RFC 9112 §5.1).
    try expect_fields(.response, "X: a\r\n  \r\nZ:\r\n b\r\n\r\n", &.{
        .{ .name = "X", .value = "a" },
        .{ .name = "Z", .value = "b" },
    });
    try expect_refused(.response, "X: a\r\n b\x00\r\n\r\n", error.FieldValueInvalid);
}

test "a folded value is held to field_value_len_max once joined" {
    const limit = core.constants.field_value_len_max;
    var octets: [limit + 32]u8 = undefined;
    const head = "X: ";
    const fold = "\r\n z\r\n\r\n";
    const first_len = limit - 2;
    @memcpy(octets[0..head.len], head);
    @memset(octets[head.len..][0..first_len], 'v');
    @memcpy(octets[head.len + first_len ..][0..fold.len], fold);
    const total = head.len + first_len + fold.len;
    try parse(.response, octets[0..total], &test_section);
    try testing.expectEqual(limit, test_section.get(0).value.len);
    // One octet more in the first line takes the joined value one past the limit.
    @memset(octets[head.len..][0 .. first_len + 1], 'v');
    @memcpy(octets[head.len + first_len + 1 ..][0..fold.len], fold);
    try expect_refused(.response, octets[0 .. total + 1], error.FieldValueInvalid);
}

test "the section's own limits refuse a head with too many lines" {
    var octets: [core.constants.field_count_max * 6 + 8]u8 = undefined;
    var length: usize = 0;
    for (0..core.constants.field_count_max + 1) |_| {
        @memcpy(octets[length..][0..6], "a: b\r\n");
        length += 6;
    }
    @memcpy(octets[length..][0..2], "\r\n");
    try expect_refused(.request, octets[0 .. length + 2], error.TooManyLines);
}
