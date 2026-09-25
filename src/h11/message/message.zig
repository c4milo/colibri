//! One head of an HTTP/1.1 message (RFC 9112 §2.1): the start line and the field section, read
//! from octets the caller has already read (design §4.1). A server reads request heads and a
//! client reads response heads.
//!
//! A head is read in two passes. `message_scan` finds where it ends, keeping its place between
//! calls, so a head that arrives in pieces is scanned once. Then, with the whole head in the
//! caller's octets, `message_start` reads the start line and `message_fields` the field lines,
//! the way h2 reads only a whole frame. Nothing is consumed until a head is whole.
//!
//! The start line's slices point into the caller's octets and stay valid while the caller keeps
//! them. The field lines are copied into the caller's `FieldSection`, because a client joins a
//! folded value (RFC 9112 §5.2) and the joined value exists nowhere in the input.
//!
//! What a refusal means on the wire is the connection's to say (design §8 step 15b): RFC 9112
//! §2.2 has a server answer a malformed request with 400 and close, and §3 names 414 for a
//! request-target it will not read.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const http = @import("http");
const constants = @import("../constants.zig");
const message_scan = @import("message_scan.zig");
const message_start = @import("message_start.zig");
const message_fields = @import("message_fields.zig");
const message_target = @import("message_target.zig");

const FieldSection = http.FieldSection;
const Reader = core.reader.Reader;

pub const Scanner = message_scan.Scanner;
pub const Role = message_scan.Role;
pub const Version = message_start.Version;
pub const RequestLine = message_start.RequestLine;
pub const StatusLine = message_start.StatusLine;
pub const Form = message_target.Form;

pub const Error = message_scan.Error || message_start.Error || message_fields.Error ||
    message_target.Error;

/// A request head read whole. `head_len` octets of the caller's input belong to it, a skipped
/// leading empty line and the empty line that ends it included.
pub const Request = struct {
    head_len: u32,
    line: RequestLine,
    /// The request-target's form (RFC 9112 §3.2).
    form: Form,
};

/// A response head read whole. `head_len` octets of the caller's input belong to it.
pub const Response = struct {
    head_len: u32,
    line: StatusLine,
};

/// The CR and LF that end every line (RFC 9112 §2.1).
const line_end = "\r\n";

/// Reads one request head from the start of `input` into `line` and `section`. Returns null while
/// `input` holds no whole head; the caller calls again with the same octets and more. Once a head
/// is returned, or an error, `scanner` is ready for the next head.
pub fn read_request(scanner: *Scanner, input: []const u8, section: *FieldSection) Error!?Request {
    const head, const head_len = try read_head(scanner, .request, input) orelse return null;
    const start_line, const fields = std.mem.cut(u8, head, line_end) orelse unreachable;
    const line = try message_start.parse_request_line(start_line);
    try message_fields.parse(.request, fields, section);
    const form = try message_target.check(line, section);
    return .{ .head_len = head_len, .line = line, .form = form };
}

/// Reads one response head from the start of `input`, as `read_request` reads a request head.
pub fn read_response(scanner: *Scanner, input: []const u8, section: *FieldSection) Error!?Response {
    const head, const head_len = try read_head(scanner, .response, input) orelse return null;
    const start_line, const fields = std.mem.cut(u8, head, line_end) orelse unreachable;
    const line = try message_start.parse_status_line(start_line);
    try message_fields.parse(.response, fields, section);
    return .{ .head_len = head_len, .line = line };
}

/// The octets of a whole head from its start line through the empty line that ends it, and the
/// octets of `input` the head takes; or null when the head is not whole yet.
fn read_head(scanner: *Scanner, role: Role, input: []const u8) Error!?struct { []const u8, u32 } {
    const span = scanner.scan(role, input) catch |failure| {
        scanner.reset();
        return failure;
    } orelse return null;
    scanner.reset();
    assert(span.start < span.end and span.end <= input.len);
    assert(span.end <= constants.head_len_max);
    var reader = Reader.init(input);
    _ = reader.take(span.start) catch unreachable;
    const head = reader.take(span.end - span.start) catch unreachable;
    return .{ head, span.end };
}

const testing = std.testing;

/// The section the tests fill, placed outside any stack frame.
var test_section: FieldSection = undefined;

test "a request head reads into its request line and field section, and says how long it was" {
    const input = "\r\nPOST /upload HTTP/1.1\r\nHost: example.org\r\nContent-Length: 2\r\n\r\nok";
    var scanner: Scanner = .{};
    const request = (try read_request(&scanner, input, &test_section)).?;
    try testing.expectEqual(input.len - 2, request.head_len);
    try testing.expectEqualStrings("POST", request.line.method);
    try testing.expectEqualStrings("/upload", request.line.target);
    try testing.expectEqual(.origin, request.form);
    try testing.expectEqual(2, test_section.len());
    try testing.expectEqualStrings("example.org", test_section.find("host").?.value);
    try testing.expectEqual(0, scanner.scanned);
}

test "a response head reads into its status line, and a folded value is joined" {
    const input = "HTTP/1.1 200 OK\r\nX: a\r\n b\r\n\r\n";
    var scanner: Scanner = .{};
    const response = (try read_response(&scanner, input, &test_section)).?;
    try testing.expectEqual(input.len, response.head_len);
    try testing.expectEqual(200, response.line.status.code);
    try testing.expectEqualStrings("a b", test_section.find("x").?.value);
}

test "a head in pieces is read once whole, and every split reads what the whole does" {
    const input = "GET / HTTP/1.1\r\nHost: a\r\nAccept: */*\r\n\r\n";
    for (1..input.len) |split| {
        var scanner: Scanner = .{};
        try testing.expectEqual(null, try read_request(&scanner, input[0..split], &test_section));
        const request = (try read_request(&scanner, input, &test_section)).?;
        try testing.expectEqual(input.len, request.head_len);
        try testing.expectEqualStrings("*/*", test_section.find("accept").?.value);
    }
}

test "a refused head resets the scanner, and each layer's refusal reaches the caller" {
    var scanner: Scanner = .{};
    try testing.expectError(error.BareLineFeed, read_request(&scanner, "GET / HTTP/1.1\n\n", &test_section));
    try testing.expectEqual(0, scanner.scanned);
    try testing.expectError(error.VersionInvalid, read_request(&scanner, "GET / http/1.1\r\n\r\n", &test_section));
    try testing.expectError(error.ObsFold, read_request(&scanner, "GET / HTTP/1.1\r\nX: a\r\n b\r\n\r\n", &test_section));
    try testing.expectError(error.StatusInvalid, read_response(&scanner, "HTTP/1.1 700 X\r\n\r\n", &test_section));
    try testing.expectError(error.StartLineEmpty, read_response(&scanner, "\r\nHTTP/1.1 200 X\r\n\r\n", &test_section));
    try testing.expectError(error.HostMissing, read_request(&scanner, "GET / HTTP/1.1\r\n\r\n", &test_section));
}
