//! Writes one head of an HTTP/1.1 message into the caller's buffer (design §4.1): a client's request
//! head or a server's response head. The version is always HTTP/1.1, because RFC 9112 §2.3 has an
//! implementation send its own version.
//!
//! A writer refuses what colibri would refuse to read, and the rules RFC 9112 and RFC 9110 place on
//! a sender that a head alone decides:
//!   - a request carries exactly one valid Host (RFC 9112 §3.2);
//!   - no message carries both Content-Length and Transfer-Encoding (RFC 9112 §6.2);
//!   - a CONNECT request declares no content (RFC 9110 §9.3.6, decision 109);
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
const message_write_fields = @import("message_write_fields.zig");

const Field = http.Field;
const Writer = core.Writer;
const Checked = message_write_fields.Checked;

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
    /// Content-Length with Transfer-Encoding (RFC 9112 §6.2), either in a response whose status
    /// forbids it (RFC 9112 §6.1, RFC 9110 §8.6), or content declared on a CONNECT request
    /// (RFC 9110 §9.3.6).
    FramingInvalid,
};

/// The version colibri writes (RFC 9112 §2.3).
const version = "HTTP/1.1";

/// `method SP request-target SP HTTP-version CRLF`, the field lines and the empty line
/// (RFC 9112 §2.1, §3). Returns the octets written.
pub fn write_request_head(output: []u8, method: []const u8, target: []const u8, fields: []const Field) Error!usize {
    var checked: Checked = .{};
    checked.add(fields);
    return write_request_head_checked(output, method, target, fields, &checked);
}

/// `write_request_head`, with `checked` from the caller's own pass over `fields`.
pub fn write_request_head_checked(output: []u8, method: []const u8, target: []const u8, fields: []const Field, checked: *const Checked) Error!usize {
    assert(fields.len > 0 or checked.host.value == null);
    // RFC 9110 §9.1: method = token.
    http.method.validate(method) catch return error.MethodInvalid;
    const line: message_start.RequestLine = .{ .method = method, .target = target, .version = .{ .major = 1, .minor = 1 } };
    // RFC 9112 §3.2: a request-target of one of the four forms, as its method takes it.
    _ = message_target.target_form(line) catch return error.TargetInvalid;
    // RFC 9110 §5.1 and §5.5: the first field line that is not valid.
    if (checked.invalid) |invalid| return invalid;
    try check_framing(checked);
    // RFC 9110 §9.3.6: a CONNECT request message does not have content.
    if (http.method.standard(method) == .connect and declares_content(checked)) return error.FramingInvalid;
    // RFC 9112 §3.2: a client MUST send one Host in every HTTP/1.1 request.
    const host = checked.host.value orelse return error.HostInvalid;
    // RFC 9112 §3.2: one Host, and no second line of it.
    if (checked.host.repeated) return error.HostInvalid;
    // RFC 9110 §7.2: Host = uri-host [ ":" port ].
    if (!http.uri.is_host_port(host)) return error.HostInvalid;
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
    var checked: Checked = .{};
    checked.add(fields);
    return write_response_head_checked(output, status, reason, fields, &checked);
}

/// `write_response_head`, with `checked` from the caller's own pass over `fields`.
pub fn write_response_head_checked(output: []u8, status: u16, reason: []const u8, fields: []const Field, checked: *const Checked) Error!usize {
    assert(fields.len > 0 or !checked.names_framing());
    // RFC 9110 §15: a status code is three digits from 100 to 599.
    const code = http.Status.from_code(status) catch return error.StatusInvalid;
    // RFC 9112 §4: reason-phrase = 1*( HTAB / SP / VCHAR / obs-text ).
    message_start.check_reason(reason) catch return error.ReasonInvalid;
    // RFC 9110 §5.1 and §5.5: the first field line that is not valid.
    if (checked.invalid) |invalid| return invalid;
    try check_framing(checked);
    const forbids_framing = code.is_interim() or status == @intFromEnum(http.status.Code.no_content);
    // RFC 9112 §6.1 and RFC 9110 §8.6: no Transfer-Encoding or Content-Length in a 1xx or 204.
    if (forbids_framing and checked.names_framing()) return error.FramingInvalid;
    var digits: [http.constants.protocol.status_digits_len]u8 = undefined;
    var writer = Writer.init(output);
    // RFC 9112 §2.1: a head is its start line, field lines and empty line whole, so a buffer
    // that holds less holds no head at all.
    write_head(&writer, fields, .{ version, " ", code.write_digits(&digits), " ", reason }) catch return error.OutputTooSmall;
    return writer.written().len;
}

/// The framing fields colibri writes: not Content-Length with Transfer-Encoding, one
/// Content-Length of 1*DIGIT that fits a u64, and a Transfer-Encoding of chunked alone, since
/// colibri encodes no other coding (decision 91).
fn check_framing(checked: *const Checked) Error!void {
    const content_length = &checked.content_length;
    const transfer_encoding = &checked.transfer_encoding;
    // RFC 9112 §6.2: a sender MUST NOT send Content-Length in a message with Transfer-Encoding.
    if (content_length.value != null and transfer_encoding.value != null) return error.FramingInvalid;
    // RFC 9110 §8.6: one Content-Length value; colibri writes no list of repeats.
    if (content_length.repeated) return error.FramingInvalid;
    if (content_length.value) |value| {
        // RFC 9110 §8.6: Content-Length = 1*DIGIT.
        if (value.len == 0 or !http.uri.is_port(value)) return error.FramingInvalid;
        // RFC 9110 §8.6: a length colibri can count, which a u64 holds.
        if (checked.content_length_octets == null) return error.FramingInvalid;
    }
    // RFC 9112 §6.1: colibri applies chunked, once, as the only coding it writes.
    if (transfer_encoding.repeated) return error.FramingInvalid;
    if (transfer_encoding.value) |value| {
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

/// Whether a request's fields declare content: a Transfer-Encoding, or a Content-Length above 0
/// (RFC 9112 §6.3 rules 4 to 7). `check_framing` has accepted both.
fn declares_content(checked: *const Checked) bool {
    if (checked.transfer_encoding.value != null) return true;
    if (checked.content_length.value == null) return false;
    return checked.content_length_octets.? > 0;
}

const testing = std.testing;
const message = @import("message.zig");

/// The buffer and section the tests use, placed outside any stack frame.
threadlocal var test_output: [test_output_len]u8 = undefined;
const test_output_len = 256;
threadlocal var test_section: http.FieldSection align(@alignOf(http.FieldSection)) = undefined;

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

test "RFC 9110 §9.3.6: a CONNECT request is written with no content" {
    const host: Field = .{ .name = "Host", .value = "a:1" };
    try testing.expectError(error.FramingInvalid, write_request_head(&test_output, "CONNECT", "a:1", &.{ host, .{ .name = "Content-Length", .value = "5" } }));
    try testing.expectError(error.FramingInvalid, write_request_head(&test_output, "CONNECT", "a:1", &.{ host, .{ .name = "Transfer-Encoding", .value = "chunked" } }));
    _ = try write_request_head(&test_output, "CONNECT", "a:1", &.{ host, .{ .name = "Content-Length", .value = "00" } });
    _ = try write_request_head(&test_output, "CONNECT", "a:1", &.{host});
}

test "a head that does not fit is not written, and one that fits exactly is" {
    const fields: []const Field = &.{.{ .name = "Host", .value = "a" }};
    const expected = "GET / HTTP/1.1\r\nHost: a\r\n\r\n";
    try testing.expectError(error.OutputTooSmall, write_request_head(test_output[0 .. expected.len - 1], "GET", "/", fields));
    try testing.expectEqual(expected.len, try write_request_head(test_output[0..expected.len], "GET", "/", fields));
}

test "RFC 9110 §5.1 and §5.5: a field line that is not valid is refused before a framing rule, wherever it stands" {
    try testing.expectError(error.FieldNameInvalid, write_response_head(&test_output, 200, "", &.{
        .{ .name = "Content-Length", .value = "1" },
        .{ .name = "Content-Length", .value = "1" },
        .{ .name = "a b", .value = "c" },
    }));
    try testing.expectError(error.FieldValueInvalid, write_response_head(&test_output, 200, "", &.{
        .{ .name = "Transfer-Encoding", .value = "gzip" },
        .{ .name = "a", .value = " b" },
    }));
    // RFC 9112 §6.1 and RFC 9110 §8.6: the rule of a 1xx or 204 comes after the lines too.
    try testing.expectError(error.FieldNameInvalid, write_response_head(&test_output, 204, "", &.{
        .{ .name = "Content-Length", .value = "0" },
        .{ .name = "a b", .value = "c" },
    }));
    // RFC 9110 §9.3.6: and so does the rule of a CONNECT request.
    try testing.expectError(error.FieldNameInvalid, write_request_head(&test_output, "CONNECT", "a:1", &.{
        .{ .name = "Content-Length", .value = "5" },
        .{ .name = "a b", .value = "c" },
    }));
}

test "the first field line that is not valid decides the error, and a line's name comes before its value" {
    try testing.expectError(error.FieldValueInvalid, write_response_head(&test_output, 200, "", &.{
        .{ .name = "a", .value = " b" },
        .{ .name = "a b", .value = "c" },
    }));
    try testing.expectError(error.FieldNameInvalid, write_response_head(&test_output, 200, "", &.{
        .{ .name = "a b", .value = "c" },
        .{ .name = "a", .value = " b" },
    }));
    try testing.expectError(error.FieldNameInvalid, write_response_head(&test_output, 200, "", &.{.{ .name = "a b", .value = " c" }}));
}

test "the start line is refused before the field lines: the status, then the reason, then the method and target" {
    const invalid: []const Field = &.{.{ .name = "a b", .value = "c" }};
    try testing.expectError(error.StatusInvalid, write_response_head(&test_output, 99, "O\r\nK", invalid));
    try testing.expectError(error.ReasonInvalid, write_response_head(&test_output, 200, "O\r\nK", invalid));
    try testing.expectError(error.MethodInvalid, write_request_head(&test_output, "G T", "", invalid));
    try testing.expectError(error.TargetInvalid, write_request_head(&test_output, "GET", "", invalid));
}

test "RFC 9110 §9.3.6 and RFC 9112 §3.2: the framing rules are applied before the Host is read" {
    try testing.expectError(error.FramingInvalid, write_request_head(&test_output, "CONNECT", "a:1", &.{.{ .name = "Content-Length", .value = "5" }}));
    try testing.expectError(error.FramingInvalid, write_request_head(&test_output, "GET", "/", &.{
        .{ .name = "Host", .value = "u@a" },
        .{ .name = "Host", .value = "a" },
        .{ .name = "Content-Length", .value = "x" },
    }));
    // The first Host is read, and the second is refused even when the first is valid.
    try testing.expectError(error.HostInvalid, write_request_head(&test_output, "GET", "/", &.{
        .{ .name = "Host", .value = "a" },
        .{ .name = "Host", .value = "u@a" },
    }));
    _ = try write_request_head(&test_output, "GET", "/", &.{ .{ .name = "Hosx", .value = "u@a" }, .{ .name = "HOST", .value = "a:1" } });
}

test "RFC 9110 §5.1: a framing field is found by its name in any case, and a name one octet away is a plain line" {
    try testing.expectError(error.FramingInvalid, write_response_head(&test_output, 200, "", &.{
        .{ .name = "content-length", .value = "1" },
        .{ .name = "TRANSFER-ENCODING", .value = "chunked" },
    }));
    const written = try write_response_head(&test_output, 204, "", &.{
        .{ .name = "content-lengtx", .value = "x" },
        .{ .name = "Transfer-Encodinx", .value = "gzip" },
    });
    try testing.expectEqualStrings("HTTP/1.1 204 \r\ncontent-lengtx: x\r\nTransfer-Encodinx: gzip\r\n\r\n", test_output[0..written]);
    try testing.expectError(error.HostInvalid, write_request_head(&test_output, "GET", "/", &.{.{ .name = "Hosx", .value = "a" }}));
}
