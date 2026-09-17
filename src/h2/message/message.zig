//! The checks RFC 9113 §8 applies to a decoded field section. Each entry point reads the section
//! as one kind of message and returns what the section holds, or the `Error` that names why the
//! message is malformed. `validate_request` returns a `Request`, `validate_response` returns a
//! `Response`, and `validate_trailers` returns nothing. Nothing here reads a frame or tracks a
//! stream. The connection decides whether a HEADERS frame opens a request, carries a response or
//! carries trailers, and calls the matching function. It learns whether a response is interim from
//! `Response.status.is_interim()`.
//!
//! Every `Error` is a malformed message, which RFC 9113 §8.1.1 makes a stream error of type
//! PROTOCOL_ERROR. `verdict` holds that stream error, and the connection sends its code in a
//! RST_STREAM.
//!
//! This file is the request and response validation of design §8 step 4. `http` returns reasons
//! and this file names h2's errors (decision 15). An undefined pseudo-header such as `:protocol` is
//! a stream error, never a connection error (decision 19). Every assertion checks a value colibri
//! computed, or a length `FieldSection.append` already asserted, and never a value the peer chose
//! (invariant 24). message_fuzz.zig drives all three entry points with raw octets in every name and
//! every value, after any sequence of lines from its table, to show it.
//!
//! Every section is checked in this order (invariant 7). message_lines.zig holds steps 1 and 2,
//! message_request.zig holds step 3 for a request, and this file holds step 3 for a response and
//! step 4. A trailer section takes steps 1 and 2 only.
//!   1. Every line in arrival order, against the pseudo-header rules of RFC 9113 §8.3:
//!      - a pseudo-header after a regular line is `PseudoHeaderAfterRegular`;
//!      - any pseudo-header in a trailer section is `PseudoHeaderInTrailers` (§8.1);
//!      - a pseudo-header the kind does not define is `PseudoHeaderUndefined`. A request defines
//!        `:method`, `:scheme`, `:authority` and `:path` (§8.3.1), and a response defines
//!        `:status` (§8.3.2);
//!      - a pseudo-header name already seen is `PseudoHeaderRepeated`.
//!   2. Every line again in arrival order, against the field rules of §8.2. Within a line:
//!      - a regular name that is empty, or holds an uppercase letter, a colon or another octet
//!        outside RFC 9110 §5.1's token, is `FieldNameInvalid` (§8.2.1);
//!      - a value on any line that holds NUL, LF, CR or another control octet, or starts or ends
//!        with SP or HTAB, is `FieldValueInvalid` (§8.2.1);
//!      - a connection-specific name is `ConnectionSpecificField` (§8.2.2), except TE in a
//!        request, which is `TeNotTrailers` when its value holds a member other than "trailers".
//!   3. The rules of the kind:
//!      - a request without `:method` is `MethodMissing`, and one whose method is not a token is
//!        `MethodInvalid` (§8.3.1);
//!      - a CONNECT request with `:scheme` or `:path` is `ConnectWithSchemeOrPath`, one without
//!        `:authority` is `ConnectWithoutAuthority`, and one whose `:authority` is not a non-empty
//!        host, a colon and a non-empty decimal port is `ConnectAuthorityInvalid` (§8.5);
//!      - any other request without `:scheme` is `SchemeMissing`, one with an empty `:scheme` is
//!        `SchemeInvalid`, and one without `:path` is `PathMissing` (§8.3.1);
//!      - a `:path` of `*` in a request other than OPTIONS is `PathInvalid` (RFC 9110 §7.1);
//!      - for an http or https scheme, an empty `:path` is `PathEmpty`, and a `:path` that is not
//!        `*` and does not start with `/` is `PathInvalid` (§8.3.1, RFC 9110 §4.1);
//!      - a response without `:status` is `StatusMissing` (§8.3.2), one whose status is not three
//!        digits from 100 to 599 is `StatusInvalid`, and an interim one with END_STREAM set is
//!        `InterimWithEndStream` (§8.1).
//!   4. A content-length that `http.content_length.from_section` refuses is `ContentLengthInvalid`
//!      (RFC 9113 §8.1.1). That file states its own order.
//!
//! Where a rule leaves a choice, colibri takes the strict side:
//!   - §8.2.1 says a recipient SHOULD check names and values against RFC 9110 §5.1 and §5.5.
//!     colibri does, so it also refuses a name holding a delimiter such as `"` and a value holding
//!     a control octet other than NUL, LF and CR.
//!   - RFC 9110 §8.6 lets a recipient either reject a content-length that repeats one decimal value
//!     or read one instance of it. colibri reads one instance whether the repeats arrive on two
//!     lines or as a list on one, because RFC 9110 §5.3 makes those the same message. It refuses a
//!     repeat whose octets differ, and a value that does not fit a u64.
//!
//! Not checked here:
//!   - whether content-length equals the sum of the DATA payload lengths (§8.1.1). That check is
//!     the connection's, and `content_length` gives it the value;
//!   - whether a HEADERS frame carrying trailers, or following a final response, has END_STREAM
//!     set (§8.1). That check is the connection's too;
//!   - a 101 status. §8.6 says h2 does not support 101 but does not make the response malformed,
//!     so this file returns it as interim and the connection decides what to do with it;
//!   - whether a Host field names the entity `:authority` names, a SHOULD of §8.3.1;
//!   - whether `:authority` holds the userinfo subcomponent §8.3.1 forbids, and the syntax of
//!     `:authority` outside CONNECT;
//!   - the RFC 3986 grammar of a scheme, a host, a path segment and a query, which §8.3.1 and
//!     RFC 9110 §4.1 cite and docs/rfcs does not carry; the leading `/` of `:path` for a scheme
//!     other than http and https; and the range of a CONNECT port;
//!   - a content-length in a trailer section, which step 4 does not read.
const std = @import("std");
const assert = std.debug.assert;
const http = @import("http");
const constants = @import("../constants.zig");
const stream = @import("../stream/stream.zig");
const message_lines = @import("message_lines.zig");
const message_request = @import("message_request.zig");
const message_fuzz = @import("message_fuzz.zig");

const Field = http.field.Field;
const FieldSection = http.FieldSection;
const Status = http.status.Status;
const Seen = message_lines.Seen;

/// Why a field section is a malformed message. Every one is a stream error of PROTOCOL_ERROR
/// (RFC 9113 §8.1.1), which `verdict` holds.
pub const Error = error{
    /// A regular field name that is empty or holds an uppercase letter, a colon or another octet
    /// outside a token (RFC 9113 §8.2.1).
    FieldNameInvalid,
    /// A field value that holds NUL, LF, CR or another control octet, or starts or ends with SP or
    /// HTAB (RFC 9113 §8.2.1).
    FieldValueInvalid,
    /// A pseudo-header field after a regular field line (RFC 9113 §8.3).
    PseudoHeaderAfterRegular,
    /// A pseudo-header field name that appears twice (RFC 9113 §8.3).
    PseudoHeaderRepeated,
    /// A pseudo-header field the message's kind does not define: an unknown one, a request one in
    /// a response, or a response one in a request (RFC 9113 §8.3).
    PseudoHeaderUndefined,
    /// A pseudo-header field in a trailer section (RFC 9113 §8.1, §8.3).
    PseudoHeaderInTrailers,
    /// A connection-specific field, or TE in a response or a trailer section (RFC 9113 §8.2.2).
    ConnectionSpecificField,
    /// TE in a request with a member other than "trailers" (RFC 9113 §8.2.2).
    TeNotTrailers,
    /// A request without `:method` (RFC 9113 §8.3.1).
    MethodMissing,
    /// A `:method` that is not a token (RFC 9113 §8.3.1, RFC 9110 §9.1).
    MethodInvalid,
    /// A request other than CONNECT without `:scheme` (RFC 9113 §8.3.1).
    SchemeMissing,
    /// A `:scheme` that is empty, and so is not the scheme portion of a target URI (RFC 9113
    /// §8.3.1).
    SchemeInvalid,
    /// A request other than CONNECT without `:path` (RFC 9113 §8.3.1).
    PathMissing,
    /// An empty `:path` in a request for an http or https URI (RFC 9113 §8.3.1).
    PathEmpty,
    /// A `:path` of `*` in a request other than OPTIONS (RFC 9110 §7.1), or a `:path` for an http
    /// or https URI that neither starts with `/` nor is `*` (RFC 9113 §8.3.1, RFC 9110 §4.1).
    PathInvalid,
    /// A CONNECT request with `:scheme` or `:path` (RFC 9113 §8.5).
    ConnectWithSchemeOrPath,
    /// A CONNECT request without `:authority` (RFC 9113 §8.5).
    ConnectWithoutAuthority,
    /// A CONNECT `:authority` that is not a non-empty host, a colon and a non-empty decimal port
    /// (RFC 9113 §8.5, RFC 9110 §9.3.6).
    ConnectAuthorityInvalid,
    /// A response without `:status` (RFC 9113 §8.3.2).
    StatusMissing,
    /// A `:status` that is not three digits from 100 to 599 (RFC 9113 §8.3, RFC 9110 §15).
    StatusInvalid,
    /// A content-length that is not a list of one repeated 1*DIGIT value fitting a u64. No such
    /// value equals the sum of the DATA payload lengths, which RFC 9113 §8.1.1 makes malformed;
    /// RFC 9110 §8.6 gives the grammar.
    ContentLengthInvalid,
    /// A HEADERS frame with END_STREAM set that carries an informational status (RFC 9113 §8.1).
    InterimWithEndStream,
};

/// The verdict every `Error` carries: a malformed message is a stream error of type
/// PROTOCOL_ERROR (RFC 9113 §8.1.1).
pub const verdict: stream.Verdict = .{ .stream_error = constants.error_protocol_error };

/// A request the section holds. Every slice points into the section and stays valid until the
/// section's next `append`, `clear` or `init`.
pub const Request = struct {
    /// The `:method` value, a token (RFC 9113 §8.3.1, RFC 9110 §9.1).
    method: []const u8,
    /// The `:scheme` value; null in a CONNECT request (RFC 9113 §8.5).
    scheme: ?[]const u8,
    /// The `:authority` value; null when the request carries none (RFC 9113 §8.3.1).
    authority: ?[]const u8,
    /// The `:path` value; null in a CONNECT request (RFC 9113 §8.5).
    path: ?[]const u8,
    /// The content-length, which the connection compares with the sum of the DATA payload lengths
    /// (RFC 9113 §8.1.1); null when the request carries none.
    content_length: ?u64,
    /// True when `method` is exactly CONNECT (RFC 9113 §8.5, RFC 9110 §9.1).
    is_connect: bool,
};

/// A response the section holds. `status.is_interim()` says whether a final response follows.
pub const Response = struct {
    /// The `:status` value (RFC 9113 §8.3.2).
    status: Status,
    /// The content-length, which the connection compares with the sum of the DATA payload lengths
    /// (RFC 9113 §8.1.1); null when the response carries none.
    content_length: ?u64,
};

/// Reads `section` as a request (RFC 9113 §8.3.1, §8.5).
pub fn validate_request(section: *const FieldSection) Error!Request {
    const seen = try message_lines.walk(section, .request);
    const is_connect = try message_request.check(seen);
    const content_length = try content_length_of(section, seen);
    const method = seen.method.?;
    assert(is_connect == (http.method.standard(method) == .connect));
    assert(seen.status == null);
    return .{
        .method = method,
        .scheme = seen.scheme,
        .authority = seen.authority,
        .path = seen.path,
        .content_length = content_length,
        .is_connect = is_connect,
    };
}

/// Reads `section` as a response (RFC 9113 §8.3.2). `end_stream` is the END_STREAM flag of the
/// HEADERS frame that carried it, which §8.1 forbids on an interim response.
pub fn validate_response(section: *const FieldSection, end_stream: bool) Error!Response {
    const seen = try message_lines.walk(section, .response);
    // RFC 9113 §8.3.2: :status is included in all responses, interim responses included.
    const digits = seen.status orelse return error.StatusMissing;
    // RFC 9113 §8.3: an invalid pseudo-header field is malformed; RFC 9110 §15: three digits from
    // 100 to 599.
    const status = Status.from_digits(digits) catch return error.StatusInvalid;
    // RFC 9113 §8.1: a HEADERS frame with END_STREAM set that carries an informational status
    // code is malformed.
    if (end_stream and status.is_interim()) return error.InterimWithEndStream;
    const content_length = try content_length_of(section, seen);
    assert(!end_stream or !status.is_interim());
    assert(seen.method == null and seen.path == null);
    return .{ .status = status, .content_length = content_length };
}

/// Reads `section` as a trailer section: no pseudo-header field (RFC 9113 §8.1), and every line
/// valid (§8.2.1, §8.2.2).
pub fn validate_trailers(section: *const FieldSection) Error!void {
    const seen = try message_lines.walk(section, .trailers);
    assert(seen.method == null and seen.status == null);
    assert(seen.regular_seen == (section.len() > 0));
}

/// Step 4: the content-length `section` declares, or null when it declares none.
fn content_length_of(section: *const FieldSection, seen: Seen) Error!?u64 {
    const content_length = http.content_length.from_section(section) catch |reason| switch (reason) {
        // RFC 9113 §8.1.1: a content-length that does not equal the sum of the DATA payload
        // lengths is malformed, and a value that is not 1*DIGIT (RFC 9110 §8.6) equals no sum.
        error.ContentLengthNotDigits => return error.ContentLengthInvalid,
        // RFC 9113 §8.1.1: two different values cannot both equal the sum, and RFC 9110 §8.6 lets
        // a recipient reject a repeated value.
        error.ContentLengthDiffers => return error.ContentLengthInvalid,
        // RFC 9110 §8.6: a recipient prevents parsing errors due to integer conversion overflows,
        // and colibri does so by refusing the value.
        error.ContentLengthTooLarge => return error.ContentLengthInvalid,
    };
    assert(content_length == null or seen.regular_seen);
    return content_length;
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

/// A response of `:status` 200 with one content-length line per value.
fn content_length_response(values: []const []const u8) !*const FieldSection {
    _ = try section_of(&.{line_of(":status", "200")});
    for (values) |value| try test_section.append("content-length", value);
    return &test_section;
}

fn expect_request(err: Error, section: *const FieldSection) !void {
    try testing.expectError(err, validate_request(section));
}

fn expect_response(err: Error, section: *const FieldSection, end_stream: bool) !void {
    try testing.expectError(err, validate_response(section, end_stream));
}

test "the simple GET request of RFC 9113 §8.8.1 is a request, and its fields read back" {
    const request = try validate_request(try section_of(&.{
        line_of(":method", "GET"),
        line_of(":scheme", "https"),
        line_of(":authority", "example.org"),
        line_of(":path", "/resource"),
        line_of("host", "example.org"),
        line_of("accept", "image/jpeg"),
    }));
    try testing.expectEqualStrings("GET", request.method);
    try testing.expectEqualStrings("https", request.scheme.?);
    try testing.expectEqualStrings("example.org", request.authority.?);
    try testing.expectEqualStrings("/resource", request.path.?);
    try testing.expectEqual(null, request.content_length);
    try testing.expect(!request.is_connect);
}

test "a response with :status 200 passes, and one with no :status is StatusMissing" {
    const ok = try validate_response(try section_of(&.{ line_of(":status", "200"), line_of("content-type", "text/plain") }), true);
    try testing.expectEqual(200, ok.status.code);
    try testing.expect(!ok.status.is_interim());
    try testing.expectEqual(null, ok.content_length);
    try expect_response(error.StatusMissing, try section_of(&.{line_of("content-type", "text/plain")}), false);
    try expect_response(error.StatusMissing, try section_of(&.{}), true);
}

test "a :status that is not three digits from 100 to 599 is StatusInvalid" {
    for ([_][]const u8{ "", "20", "2000", "2x0", "099", "600", "OK" }) |digits| {
        try expect_response(error.StatusInvalid, try section_of(&.{line_of(":status", digits)}), false);
    }
    const unrecognised = try validate_response(try section_of(&.{line_of(":status", "599")}), false);
    try testing.expectEqual(599, unrecognised.status.code);
}

test "a 100 response with END_STREAM is InterimWithEndStream, and without END_STREAM it is interim" {
    try expect_response(error.InterimWithEndStream, try section_of(&.{line_of(":status", "100")}), true);
    try expect_response(error.InterimWithEndStream, try section_of(&.{line_of(":status", "199")}), true);
    const interim = try validate_response(try section_of(&.{line_of(":status", "100")}), false);
    try testing.expect(interim.status.is_interim());
    _ = try validate_response(try section_of(&.{line_of(":status", "204")}), true);
}

test "a 101 response is returned as interim, for the connection to decide on (RFC 9113 §8.6)" {
    const switching = try validate_response(try section_of(&.{line_of(":status", "101")}), false);
    try testing.expectEqual(101, switching.status.code);
    try testing.expect(switching.status.is_interim());
}

test "content-length 4 reads back, 4 twice on two lines or one passes, 4 then 5 is refused, and x is not a DIGIT" {
    const four = try validate_response(try content_length_response(&.{"4"}), false);
    try testing.expectEqual(4, four.content_length.?);
    const twice = try validate_response(try content_length_response(&.{ "4", "4" }), false);
    try testing.expectEqual(4, twice.content_length.?);
    const listed = try validate_response(try content_length_response(&.{"4, 4"}), false);
    try testing.expectEqual(4, listed.content_length.?);
    try expect_response(error.ContentLengthInvalid, try content_length_response(&.{ "4", "5" }), false);
    try expect_response(error.ContentLengthInvalid, try content_length_response(&.{"4, 5"}), false);
    for ([_][]const u8{ "x", "", "+4", "-1", "4_0", "0x10", "4x", "4:", "/4", "4," }) |value| {
        try expect_response(error.ContentLengthInvalid, try content_length_response(&.{value}), false);
    }
    // Whitespace at an end breaks step 2, before step 4 reads the value.
    try expect_response(error.FieldValueInvalid, try content_length_response(&.{"4 "}), false);
}

test "a content-length past 2^64 - 1 is ContentLengthInvalid, and 2^64 - 1, 007 and a request's 12 read back" {
    const at_max = try validate_response(try content_length_response(&.{"18446744073709551615"}), false);
    try testing.expectEqual(std.math.maxInt(u64), at_max.content_length.?);
    try expect_response(error.ContentLengthInvalid, try content_length_response(&.{"18446744073709551616"}), false);
    const zeros = try validate_response(try content_length_response(&.{"007"}), false);
    try testing.expectEqual(7, zeros.content_length.?);
    const request = try validate_request(try section_of(&.{
        line_of(":method", "POST"),
        line_of(":scheme", "http"),
        line_of(":path", "/"),
        line_of("content-length", "12"),
    }));
    try testing.expectEqual(12, request.content_length.?);
}

test "the steps run in order for a response: a bad line, then a missing :status, then a bad content-length" {
    try expect_response(error.ConnectionSpecificField, try section_of(&.{line_of("connection", "close")}), false);
    try expect_response(error.StatusMissing, try section_of(&.{line_of("content-length", "x")}), false);
    try expect_response(error.StatusInvalid, try section_of(&.{ line_of(":status", "20"), line_of("content-length", "x") }), false);
    try expect_response(error.InterimWithEndStream, try section_of(&.{ line_of(":status", "100"), line_of("content-length", "x") }), true);
}

test "the steps run in order for a request: a bad line, then the request rules, then a bad content-length" {
    try expect_request(error.FieldNameInvalid, try section_of(&.{line_of("X-TEST", "ok")}));
    const no_method = [_]Field{ line_of(":scheme", "http"), line_of(":path", "/"), line_of("content-length", "4"), line_of("content-length", "5") };
    try expect_request(error.MethodMissing, try section_of(&no_method));
    // Step 3 before step 4: a missing :scheme is reported before a content-length that is not 1*DIGIT.
    try expect_request(error.SchemeMissing, try section_of(&.{ line_of(":method", "GET"), line_of(":path", "/"), line_of("content-length", "x") }));
    try expect_request(error.ConnectWithoutAuthority, try section_of(&.{ line_of(":method", "CONNECT"), line_of("content-length", "x") }));
    try expect_request(error.ContentLengthInvalid, try section_of(&.{ line_of(":method", "CONNECT"), line_of(":authority", "a:1"), line_of("content-length", "x") }));
}

test "plain trailers pass, a bad line in them is refused, and step 4 does not read their content-length" {
    try validate_trailers(try section_of(&.{line_of("x-checksum", "abc")}));
    try validate_trailers(try section_of(&.{line_of("content-length", "x")}));
    try testing.expectError(error.FieldNameInvalid, validate_trailers(try section_of(&.{line_of("X-Checksum", "abc")})));
    try testing.expectError(error.FieldValueInvalid, validate_trailers(try section_of(&.{line_of("x-checksum", "a\r")})));
    const chunked = try section_of(&.{line_of("transfer-encoding", "chunked")});
    try testing.expectError(error.ConnectionSpecificField, validate_trailers(chunked));
}

test "every error is a stream error of PROTOCOL_ERROR (RFC 9113 §8.1.1)" {
    // RFC 9113 §7: PROTOCOL_ERROR is 0x01. The literal is deliberate: a comparison against the
    // constant could not tell a wrong code or a connection error from a stream error
    // (invariants 27 and 28).
    try testing.expectEqual(stream.Verdict{ .stream_error = 0x01 }, verdict);
}

test {
    _ = message_lines;
    _ = message_request;
    _ = message_fuzz;
}
