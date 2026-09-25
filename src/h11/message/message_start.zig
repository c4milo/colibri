//! The start line of a head: a request line (RFC 9112 §3) or a status line (RFC 9112 §4), each
//! with the HTTP-version of §2.3. The line arrives without its CRLF, and `message_scan` has already
//! refused any CR or LF inside it.
//!
//! Both sections let a recipient split the line on any run of whitespace, SP, HTAB, VT, FF or a
//! bare CR. colibri takes the strict side of that choice and reads the grammar as written: one SP
//! between elements, and nothing before the first or after the last. §3 warns that the lenient
//! reading "can result in request smuggling security vulnerabilities", and §4 that it can result
//! in response splitting.
//!
//! The request-target is read as a run of visible octets here. Which of §3.2's four forms it
//! takes, and whether that form suits the method, is `message_target.zig`'s concern.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const http = @import("http");
const constants = @import("../constants.zig");

const Reader = core.reader.Reader;

pub const Error = error{
    /// A request line or status line that does not have the elements its grammar gives it, one
    /// SP apart (RFC 9112 §3, §4).
    StartLineInvalid,
    /// A method that is not a token (RFC 9112 §3.1, RFC 9110 §9.1).
    MethodInvalid,
    /// A request-target that is empty or holds an octet other than a visible one (RFC 9112 §3.2).
    TargetInvalid,
    /// An HTTP-version that is not `HTTP/` DIGIT `.` DIGIT, compared case-sensitively
    /// (RFC 9112 §2.3).
    VersionInvalid,
    /// An HTTP-version whose major version is not 1 (RFC 9110 §2.5).
    VersionUnsupported,
    /// A status code that is not three digits from 100 to 599 (RFC 9112 §4, RFC 9110 §15).
    StatusInvalid,
    /// A reason phrase holding an octet other than HTAB, SP, VCHAR or obs-text (RFC 9112 §4).
    ReasonInvalid,
};

/// An HTTP-version (RFC 9112 §2.3).
pub const Version = struct {
    major: u8,
    minor: u8,
};

/// A request line. The slices point into the caller's octets.
pub const RequestLine = struct {
    method: []const u8,
    target: []const u8,
    version: Version,
};

/// A status line. The reason phrase points into the caller's octets, and may be empty.
pub const StatusLine = struct {
    version: Version,
    status: http.status.Status,
    reason: []const u8,
};

/// The one octet between the elements of a start line (RFC 9112 §3, §4).
const separator = ' ';

/// The octet between the major and the minor version (RFC 9112 §2.3).
const version_dot = '.';

/// `request-line = method SP request-target SP HTTP-version` (RFC 9112 §3).
pub fn parse_request_line(line: []const u8) Error!RequestLine {
    assert(line.len <= constants.start_line_len_max);
    // RFC 9112 §3: the method ends at the first SP.
    const method, const rest = std.mem.cutScalar(u8, line, separator) orelse
        return error.StartLineInvalid;
    // RFC 9112 §3: the HTTP-version starts after the second SP, so a line with one SP has no
    // request-target. A request-target holds no SP, so the second SP is the last.
    const target, const version_octets = std.mem.cutScalarLast(u8, rest, separator) orelse
        return error.StartLineInvalid;
    // RFC 9112 §3.1 and RFC 9110 §9.1: method = token.
    http.method.validate(method) catch return error.MethodInvalid;
    try check_target(target);
    const version = try parse_version(version_octets);
    assert(method.len > 0 and target.len > 0);
    return .{ .method = method, .target = target, .version = version };
}

/// `status-line = HTTP-version SP status-code SP [ reason-phrase ]` (RFC 9112 §4).
pub fn parse_status_line(line: []const u8) Error!StatusLine {
    assert(line.len <= constants.start_line_len_max);
    var reader = Reader.init(line);
    // RFC 9112 §4: a status line starts with the HTTP-version.
    const version_octets = reader.take(constants.version_len) catch return error.StartLineInvalid;
    const version = try parse_version(version_octets);
    try expect_separator(&reader);
    // RFC 9112 §4: status-code = 3DIGIT, after the first SP.
    const digits = reader.take(http.constants.status_digits_len) catch return error.StartLineInvalid;
    // RFC 9112 §4: status-code = 3DIGIT; RFC 9110 §15: from 100 to 599.
    const status = http.status.Status.from_digits(digits) catch return error.StatusInvalid;
    // RFC 9112 §4: a server MUST send the SP after the status code even when the reason phrase
    // is absent.
    try expect_separator(&reader);
    const reason = reader.take_rest();
    try check_reason(reason);
    assert(reader.remaining_len() == 0);
    return .{ .version = version, .status = status, .reason = reason };
}

/// The one SP between two elements of a status line (RFC 9112 §4).
fn expect_separator(reader: *Reader) Error!void {
    // RFC 9112 §4: the version and the status code are each followed by an SP, so the line does
    // not end here.
    const octet = reader.read_byte() catch return error.StartLineInvalid;
    // RFC 9112 §4: status-line = HTTP-version SP status-code SP [ reason-phrase ].
    if (octet != separator) return error.StartLineInvalid;
}

/// `HTTP-version = HTTP-name "/" DIGIT "." DIGIT`, `HTTP-name = %s"HTTP"` (RFC 9112 §2.3).
fn parse_version(octets: []const u8) Error!Version {
    // RFC 9112 §2.3: exactly the name, a slash, a digit, a dot and a digit.
    if (octets.len != constants.version_len) return error.VersionInvalid;
    var reader = Reader.init(octets);
    const name = reader.take(constants.version_name.len) catch unreachable;
    // RFC 9112 §2.3: HTTP-version is case-sensitive, so "http/1.1" is not one.
    if (!std.mem.eql(u8, name, constants.version_name)) return error.VersionInvalid;
    const major = reader.read_byte() catch unreachable;
    const dot = reader.read_byte() catch unreachable;
    const minor = reader.read_byte() catch unreachable;
    assert(reader.remaining_len() == 0);
    const numbers_valid = std.ascii.isDigit(major) and dot == version_dot and std.ascii.isDigit(minor);
    // RFC 9112 §2.3: DIGIT "." DIGIT.
    if (!numbers_valid) return error.VersionInvalid;
    const version: Version = .{ .major = major - '0', .minor = minor - '0' };
    // RFC 9110 §2.5: a different major version is a different protocol, which this module does
    // not speak.
    if (version.major != constants.version_major) return error.VersionUnsupported;
    return version;
}

/// A request-target is one run of visible octets: RFC 9112 §3.2 allows no whitespace in it, and
/// each of its four forms is built from URI characters, none of them a control or obs-text.
fn check_target(target: []const u8) Error!void {
    // RFC 9112 §3.2: every form has at least one octet.
    if (target.len == 0) return error.TargetInvalid;
    for (target) |octet| {
        // RFC 9112 §3.2: no whitespace is allowed in the request-target.
        if (!is_visible(octet)) return error.TargetInvalid;
    }
}

/// `reason-phrase = 1*( HTAB / SP / VCHAR / obs-text )` (RFC 9112 §4). The phrase may be empty,
/// because the status line's grammar makes it optional.
fn check_reason(reason: []const u8) Error!void {
    for (reason) |octet| {
        const allowed = octet == '\t' or octet == ' ' or is_visible(octet) or is_obs_text(octet);
        // RFC 9112 §4: nothing but HTAB, SP, VCHAR and obs-text.
        if (!allowed) return error.ReasonInvalid;
    }
}

/// VCHAR: %x21-7E (RFC 5234 Appendix B.1, which RFC 9110 §2.1 includes).
fn is_visible(octet: u8) bool {
    return octet >= '!' and octet <= '~';
}

/// The first octet of obs-text, which runs %x80-FF (RFC 9110 §5.6.4).
const obs_text_first: u8 = 0x80;

/// obs-text: %x80-FF (RFC 9110 §5.6.4).
fn is_obs_text(octet: u8) bool {
    return octet >= obs_text_first;
}

const testing = std.testing;

test "a request line reads into its method, target and version" {
    const line = try parse_request_line("GET /where?q=now HTTP/1.1");
    try testing.expectEqualStrings("GET", line.method);
    try testing.expectEqualStrings("/where?q=now", line.target);
    try testing.expectEqual(Version{ .major = 1, .minor = 1 }, line.version);
    const connect = try parse_request_line("CONNECT www.example.com:80 HTTP/1.0");
    try testing.expectEqualStrings("www.example.com:80", connect.target);
    try testing.expectEqual(0, connect.version.minor);
}

test "RFC 9112 §3: a request line is three elements one SP apart, and nothing else" {
    const refused = [_][]const u8{ "GET", "GET /", "GET HTTP/1.1", " GET / HTTP/1.1", "GET / HTTP/1.1 " };
    for (refused) |line| {
        const result = parse_request_line(line);
        try testing.expect(std.meta.isError(result));
    }
    try testing.expectError(error.StartLineInvalid, parse_request_line("GET"));
    try testing.expectError(error.StartLineInvalid, parse_request_line("GET HTTP/1.1"));
    try testing.expectError(error.MethodInvalid, parse_request_line(" GET / HTTP/1.1"));
    // A trailing SP ends the target at the last SP, so the target holds the first one.
    try testing.expectError(error.TargetInvalid, parse_request_line("GET / HTTP/1.1 "));
    // Two SPs between elements put an SP inside the target.
    try testing.expectError(error.TargetInvalid, parse_request_line("GET  / HTTP/1.1"));
    try testing.expectError(error.TargetInvalid, parse_request_line("GET /a b HTTP/1.1"));
    try testing.expectError(error.TargetInvalid, parse_request_line("GET /\t HTTP/1.1"));
    try testing.expectError(error.MethodInvalid, parse_request_line("GE\tT / HTTP/1.1"));
}

test "RFC 9112 §3.2: a target holds visible octets only" {
    try testing.expectError(error.TargetInvalid, parse_request_line("GET /\x7f HTTP/1.1"));
    try testing.expectError(error.TargetInvalid, parse_request_line("GET /\x80 HTTP/1.1"));
    try testing.expectError(error.TargetInvalid, parse_request_line("GET /\x00 HTTP/1.1"));
    _ = try parse_request_line("GET /!~ HTTP/1.1");
}

test "RFC 9112 §2.3: the version is HTTP/ DIGIT . DIGIT, case-sensitively, and major version 1" {
    try testing.expectError(error.VersionInvalid, parse_request_line("GET / http/1.1"));
    try testing.expectError(error.VersionInvalid, parse_request_line("GET / HTTP/1.10"));
    try testing.expectError(error.VersionInvalid, parse_request_line("GET / HTTP/1"));
    try testing.expectError(error.VersionInvalid, parse_request_line("GET / HTTP/1,1"));
    try testing.expectError(error.VersionInvalid, parse_request_line("GET / HTTP/x.1"));
    try testing.expectError(error.VersionInvalid, parse_request_line("GET / HTTP/1.y"));
    try testing.expectError(error.VersionUnsupported, parse_request_line("GET / HTTP/2.0"));
    try testing.expectError(error.VersionUnsupported, parse_request_line("GET / HTTP/0.9"));
    const later = try parse_request_line("GET / HTTP/1.9");
    try testing.expectEqual(9, later.version.minor);
}

test "a status line reads into its version, status and reason, and the reason may be empty" {
    const line = try parse_status_line("HTTP/1.1 404 Not Found");
    try testing.expectEqual(404, line.status.code);
    try testing.expectEqualStrings("Not Found", line.reason);
    const bare = try parse_status_line("HTTP/1.0 204 ");
    try testing.expectEqualStrings("", bare.reason);
    try testing.expectEqual(0, bare.version.minor);
    const spaced = try parse_status_line("HTTP/1.1 200 \tOK \xff");
    try testing.expectEqualStrings("\tOK \xff", spaced.reason);
}

test "RFC 9112 §4: the SP after the status code is required, and the elements are one SP apart" {
    try testing.expectError(error.StartLineInvalid, parse_status_line("HTTP/1.1 200"));
    // A second SP is read as the first octet of the status code.
    try testing.expectError(error.StatusInvalid, parse_status_line("HTTP/1.1  200 OK"));
    try testing.expectError(error.StartLineInvalid, parse_status_line("HTTP/1.1 2000 OK"));
    try testing.expectError(error.StartLineInvalid, parse_status_line("HTTP/1.1x200 OK"));
    try testing.expectError(error.VersionInvalid, parse_status_line("HTTP/1.x 200 OK"));
    try testing.expectError(error.StartLineInvalid, parse_status_line("HTTP/1.1"));
}

test "RFC 9112 §4 and RFC 9110 §15: a status is three digits from 100 to 599" {
    try testing.expectError(error.StatusInvalid, parse_status_line("HTTP/1.1 099 X"));
    try testing.expectError(error.StatusInvalid, parse_status_line("HTTP/1.1 600 X"));
    try testing.expectError(error.StatusInvalid, parse_status_line("HTTP/1.1 2x0 X"));
    try testing.expectEqual(599, (try parse_status_line("HTTP/1.1 599 X")).status.code);
    try testing.expectEqual(100, (try parse_status_line("HTTP/1.1 100 X")).status.code);
}

test "RFC 9112 §4: a reason phrase refuses controls other than HTAB" {
    try testing.expectError(error.ReasonInvalid, parse_status_line("HTTP/1.1 200 O\x00K"));
    try testing.expectError(error.ReasonInvalid, parse_status_line("HTTP/1.1 200 O\x7fK"));
    try testing.expectError(error.ReasonInvalid, parse_status_line("HTTP/1.1 200 O\x0bK"));
    try testing.expectError(error.VersionUnsupported, parse_status_line("HTTP/2.0 200 OK"));
}
