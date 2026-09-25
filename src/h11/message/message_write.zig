//! Writes one head of an HTTP/1.1 message into the caller's buffer (design §4.1): a client's request
//! head or a server's response head. The version is always HTTP/1.1, because RFC 9112 §2.3 has an
//! implementation send its own version.
//!
//! A writer refuses what colibri would refuse to read, and the rules RFC 9112 and RFC 9110 place on
//! a sender that a head alone decides:
//!   - a request carries exactly one valid Host (RFC 9112 §3.2);
//!   - no message carries both Content-Length and Transfer-Encoding (RFC 9112 §6.2);
//!   - no 1xx or 204 response carries Transfer-Encoding (RFC 9112 §6.1) or Content-Length
//!     (RFC 9110 §8.6).
//!
//! A write is all or nothing: on an error, the caller's buffer holds no head.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const http = @import("http");
const message_start = @import("message_start.zig");
const message_target = @import("message_target.zig");

const Field = http.field.Field;
const Writer = core.writer.Writer;

pub const Error = error{
    /// The caller's buffer cannot hold the head.
    OutputTooSmall,
    /// A method that is not a token (RFC 9110 §9.1).
    MethodInvalid,
    /// A request-target that is no form of RFC 9112 §3.2, or not one its method takes.
    TargetInvalid,
    /// A status that is not three digits from 100 to 599 (RFC 9110 §15).
    StatusInvalid,
    /// A reason phrase holding an octet other than HTAB, SP, VCHAR or obs-text (RFC 9112 §4).
    ReasonInvalid,
    /// A field name that is not a token (RFC 9110 §5.1).
    FieldNameInvalid,
    /// A field value holding a control, or leading or trailing whitespace (RFC 9110 §5.5).
    FieldValueInvalid,
    /// A request with no Host, or with more than one (RFC 9112 §3.2).
    HostInvalid,
    /// Content-Length with Transfer-Encoding (RFC 9112 §6.2), or either in a response whose status
    /// forbids it (RFC 9112 §6.1, RFC 9110 §8.6).
    FramingInvalid,
};

/// The version colibri writes (RFC 9112 §2.3).
const version = "HTTP/1.1";

/// The field names the framing rules read. Names compare case-insensitively (RFC 9110 §5.1).
const host_name = "Host";
const content_length_name = "Content-Length";
const transfer_encoding_name = "Transfer-Encoding";

/// `method SP request-target SP HTTP-version CRLF`, the field lines and the empty line
/// (RFC 9112 §2.1, §3). Returns the octets written.
pub fn write_request_head(output: []u8, method: []const u8, target: []const u8, fields: []const Field) Error!usize {
    // RFC 9110 §9.1: method = token.
    http.method.validate(method) catch return error.MethodInvalid;
    const line: message_start.RequestLine = .{ .method = method, .target = target, .version = .{ .major = 1, .minor = 1 } };
    // RFC 9112 §3.2: a request-target of one of the four forms, as its method takes it.
    _ = message_target.target_form(line) catch return error.TargetInvalid;
    try check_fields(fields);
    // RFC 9112 §3.2: a client MUST send one Host in every HTTP/1.1 request.
    if (count_named(fields, host_name) != 1) return error.HostInvalid;
    // RFC 9110 §7.2: Host = uri-host [ ":" port ].
    if (!http.uri.is_host_port(find(fields, host_name).?)) return error.HostInvalid;
    var writer = Writer.init(output);
    // RFC 9112 §2.1: a head is its start line, field lines and empty line whole, so a buffer
    // that holds less holds no head at all.
    write_head(&writer, fields, .{ method, " ", target, " ", version }) catch return error.OutputTooSmall;
    return writer.written().len;
}

/// `HTTP-version SP status-code SP [ reason-phrase ] CRLF`, the field lines and the empty line
/// (RFC 9112 §2.1, §4). The SP after the status is written even when `reason` is empty, as §4
/// requires. Returns the octets written.
pub fn write_response_head(output: []u8, status: u16, reason: []const u8, fields: []const Field) Error!usize {
    // RFC 9110 §15: a status code is three digits from 100 to 599.
    const code = http.status.Status.from_code(status) catch return error.StatusInvalid;
    // RFC 9112 §4: reason-phrase = 1*( HTAB / SP / VCHAR / obs-text ).
    message_start.check_reason(reason) catch return error.ReasonInvalid;
    try check_fields(fields);
    const forbids_framing = code.is_interim() or status == @intFromEnum(http.status.Code.no_content);
    const framed = find(fields, content_length_name) != null or find(fields, transfer_encoding_name) != null;
    // RFC 9112 §6.1 and RFC 9110 §8.6: no Transfer-Encoding or Content-Length in a 1xx or 204.
    if (forbids_framing and framed) return error.FramingInvalid;
    var digits: [http.constants.status_digits_len]u8 = undefined;
    var writer = Writer.init(output);
    // RFC 9112 §2.1: a head is its start line, field lines and empty line whole, so a buffer
    // that holds less holds no head at all.
    write_head(&writer, fields, .{ version, " ", code.write_digits(&digits), " ", reason }) catch return error.OutputTooSmall;
    return writer.written().len;
}

/// Every field line is valid, and Content-Length and Transfer-Encoding are not both present.
fn check_fields(fields: []const Field) Error!void {
    for (fields) |line| {
        // RFC 9110 §5.1: field-name = token.
        http.field.validate_name(line.name) catch return error.FieldNameInvalid;
        // RFC 9110 §5.5: no NUL, CR, LF or other control, and RFC 9112 §5.2: no obs-fold, which a
        // value without CR and LF cannot hold.
        http.field.validate_value(line.value) catch return error.FieldValueInvalid;
    }
    const both = find(fields, content_length_name) != null and find(fields, transfer_encoding_name) != null;
    // RFC 9112 §6.2: a sender MUST NOT send Content-Length in a message with Transfer-Encoding.
    if (both) return error.FramingInvalid;
    try check_framing(fields);
}

/// The framing fields colibri writes: one Content-Length of 1*DIGIT that fits a u64, and a
/// Transfer-Encoding of chunked alone, since colibri encodes no other coding (decision 91).
fn check_framing(fields: []const Field) Error!void {
    // RFC 9110 §8.6: one Content-Length value; colibri writes no list of repeats.
    if (count_named(fields, content_length_name) > 1) return error.FramingInvalid;
    if (find(fields, content_length_name)) |value| {
        // RFC 9110 §8.6: Content-Length = 1*DIGIT.
        if (value.len == 0 or !http.uri.is_port(value)) return error.FramingInvalid;
        // RFC 9110 §8.6: a length colibri can count, which a u64 holds.
        _ = std.fmt.parseUnsigned(u64, value, http.constants.content_length_radix) catch return error.FramingInvalid;
    }
    // RFC 9112 §6.1: colibri applies chunked, once, as the only coding it writes.
    if (count_named(fields, transfer_encoding_name) > 1) return error.FramingInvalid;
    if (find(fields, transfer_encoding_name)) |value| {
        // RFC 9112 §7.1: the chunked coding's name, compared case-insensitively (§7).
        if (!std.ascii.eqlIgnoreCase(value, "chunked")) return error.FramingInvalid;
    }
}

/// The start line's parts, a CRLF, each field line and the empty line.
/// A start line's parts: three elements and the two SPs between them (RFC 9112 §3, §4).
const start_line_parts = 5;

fn write_head(writer: *Writer, fields: []const Field, start_line: [start_line_parts][]const u8) core.writer.Error!void {
    for (start_line) |part| try writer.write_bytes(part);
    try writer.write_bytes("\r\n");
    for (fields) |line| {
        // RFC 9112 §5: field-line = field-name ":" OWS field-value OWS, with the one SP §5.1 prefers.
        try writer.write_bytes(line.name);
        try writer.write_bytes(": ");
        try writer.write_bytes(line.value);
        try writer.write_bytes("\r\n");
    }
    try writer.write_bytes("\r\n");
}

fn count_named(fields: []const Field, name: []const u8) usize {
    var count: usize = 0;
    for (fields) |line| {
        if (http.field.names_equal(line.name, name)) count += 1;
    }
    return count;
}

fn find(fields: []const Field, name: []const u8) ?[]const u8 {
    for (fields) |line| {
        if (http.field.names_equal(line.name, name)) return line.value;
    }
    return null;
}

const testing = std.testing;
const message = @import("message.zig");

/// The buffer and section the tests use, placed outside any stack frame.
var test_output: [test_output_len]u8 = undefined;
const test_output_len = 256;
var test_section: http.FieldSection = undefined;

test "a request head written is read back as written" {
    const written = try write_request_head(&test_output, "POST", "/upload?x=1", &.{
        .{ .name = "Host", .value = "example.org" },
        .{ .name = "Content-Length", .value = "2" },
    });
    try testing.expectEqualStrings("POST /upload?x=1 HTTP/1.1\r\nHost: example.org\r\nContent-Length: 2\r\n\r\n", test_output[0..written]);
    var scanner: message.Scanner = .{};
    const request = (try message.read_request(&scanner, test_output[0..written], &test_section)).?;
    try testing.expectEqual(written, request.head_len);
    try testing.expectEqualStrings("POST", request.line.method);
    try testing.expectEqual(message.Length{ .fixed = 2 }, request.body.length);
}

test "a response head written is read back, and the SP after the status stays with no reason" {
    const written = try write_response_head(&test_output, 204, "", &.{});
    try testing.expectEqualStrings("HTTP/1.1 204 \r\n\r\n", test_output[0..written]);
    const ok = try write_response_head(&test_output, 200, "OK", &.{.{ .name = "Transfer-Encoding", .value = "chunked" }});
    var scanner: message.Scanner = .{};
    const response = (try message.read_response(&scanner, .other, test_output[0..ok], &test_section)).?;
    try testing.expectEqual(200, response.line.status.code);
    try testing.expectEqual(message.Length.chunked, response.body.length);
}

test "RFC 9112 §3.2: a request is written with exactly one valid Host" {
    try testing.expectError(error.HostInvalid, write_request_head(&test_output, "GET", "/", &.{}));
    try testing.expectError(error.HostInvalid, write_request_head(&test_output, "GET", "/", &.{
        .{ .name = "Host", .value = "a" },
        .{ .name = "host", .value = "a" },
    }));
    try testing.expectError(error.HostInvalid, write_request_head(&test_output, "GET", "/", &.{.{ .name = "Host", .value = "u@a" }}));
}

test "the start line is checked: method, target form, status and reason" {
    const host: []const Field = &.{.{ .name = "Host", .value = "a" }};
    try testing.expectError(error.MethodInvalid, write_request_head(&test_output, "G T", "/", host));
    try testing.expectError(error.TargetInvalid, write_request_head(&test_output, "GET", "", host));
    try testing.expectError(error.TargetInvalid, write_request_head(&test_output, "GET", "*", host));
    try testing.expectError(error.TargetInvalid, write_request_head(&test_output, "CONNECT", "/", host));
    try testing.expectError(error.TargetInvalid, write_request_head(&test_output, "GET", "/a b", host));
    try testing.expectError(error.StatusInvalid, write_response_head(&test_output, 99, "", &.{}));
    try testing.expectError(error.StatusInvalid, write_response_head(&test_output, 600, "", &.{}));
    try testing.expectError(error.ReasonInvalid, write_response_head(&test_output, 200, "O\r\nK", &.{}));
}

test "field lines are checked, and framing fields go where RFC 9112 and RFC 9110 allow" {
    try testing.expectError(error.FieldNameInvalid, write_response_head(&test_output, 200, "", &.{.{ .name = "a b", .value = "c" }}));
    try testing.expectError(error.FieldValueInvalid, write_response_head(&test_output, 200, "", &.{.{ .name = "a", .value = "b\r\n c" }}));
    try testing.expectError(error.FieldValueInvalid, write_response_head(&test_output, 200, "", &.{.{ .name = "a", .value = " b" }}));
    try testing.expectError(error.FramingInvalid, write_response_head(&test_output, 200, "", &.{
        .{ .name = "Content-Length", .value = "1" },
        .{ .name = "Transfer-Encoding", .value = "chunked" },
    }));
    try testing.expectError(error.FramingInvalid, write_response_head(&test_output, 204, "", &.{.{ .name = "Content-Length", .value = "0" }}));
    try testing.expectError(error.FramingInvalid, write_response_head(&test_output, 101, "", &.{.{ .name = "Transfer-Encoding", .value = "chunked" }}));
    _ = try write_response_head(&test_output, 304, "", &.{.{ .name = "Content-Length", .value = "5" }});
}

test "framing fields are one digit-only Content-Length or a Transfer-Encoding of chunked" {
    for ([_][]const u8{ "", "-1", "+5", "1_0", "0x5", "5,5", "99999999999999999999" }) |value| {
        try testing.expectError(error.FramingInvalid, write_response_head(&test_output, 200, "", &.{.{ .name = "Content-Length", .value = value }}));
    }
    try testing.expectError(error.FramingInvalid, write_response_head(&test_output, 200, "", &.{
        .{ .name = "Content-Length", .value = "1" },
        .{ .name = "Content-Length", .value = "1" },
    }));
    try testing.expectError(error.FramingInvalid, write_response_head(&test_output, 200, "", &.{
        .{ .name = "Transfer-Encoding", .value = "chunked" },
        .{ .name = "Transfer-Encoding", .value = "chunked" },
    }));
    for ([_][]const u8{ "gzip, chunked", "gzip", "chunked, chunked" }) |value| {
        try testing.expectError(error.FramingInvalid, write_response_head(&test_output, 200, "", &.{.{ .name = "Transfer-Encoding", .value = value }}));
    }
    _ = try write_response_head(&test_output, 200, "", &.{.{ .name = "transfer-encoding", .value = "Chunked" }});
    _ = try write_response_head(&test_output, 200, "", &.{.{ .name = "Content-Length", .value = "0" }});
}

test "a head that does not fit is not written, and one that fits exactly is" {
    const fields: []const Field = &.{.{ .name = "Host", .value = "a" }};
    const expected = "GET / HTTP/1.1\r\nHost: a\r\n\r\n";
    try testing.expectError(error.OutputTooSmall, write_request_head(test_output[0 .. expected.len - 1], "GET", "/", fields));
    try testing.expectEqual(expected.len, try write_request_head(test_output[0..expected.len], "GET", "/", fields));
}
