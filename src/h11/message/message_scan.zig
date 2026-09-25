//! Finds where one head ends: the empty line after the start line and the field lines (RFC 9112
//! §2.1). The caller passes every unconsumed octet it holds on each call, and the scanner keeps its
//! place between calls, so each octet is scanned once however the head arrives. A peer that sends
//! a head one octet at a time costs linear work, not quadratic.
//!
//! The scanner also refuses, as it meets them, the octets RFC 9112 §2.2 says a line may not hold:
//!   - a bare CR, one not followed by LF, which a recipient MUST treat as invalid or replace with
//!     SP. colibri refuses it;
//!   - a lone LF, which §2.2 lets a recipient accept as a line end. colibri takes the strict side
//!     and refuses it, because §11.2 traces request smuggling to parsers that differ in what they
//!     forgive, and a lone LF is one such difference.
//!
//! A request may carry one empty line before its request line, which §2.2 says a server SHOULD
//! ignore. The scanner skips one and refuses a second. A response has no such allowance.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("../constants.zig");

const Reader = core.reader.Reader;

pub const Error = error{
    /// A CR not followed by LF (RFC 9112 §2.2).
    BareCarriageReturn,
    /// An LF not preceded by CR, which colibri does not accept as a line end (RFC 9112 §2.2).
    BareLineFeed,
    /// A start line longer than `start_line_len_max` (RFC 9112 §3).
    StartLineTooLong,
    /// A start line that is empty, where a request carries a second leading empty line or a
    /// response carries any (RFC 9112 §2.2).
    StartLineEmpty,
    /// No end within `head_len_max` octets (RFC 9110 §5.4).
    HeadTooLarge,
};

/// Which kind of head is read: a request, which a server reads, or a response, which a client
/// reads (RFC 9112 §2.1).
pub const Role = enum { request, response };

/// Where a whole head lies in the caller's octets: `start` is past the one leading empty line a
/// request may carry, and `end` is past the empty line that ends the head.
pub const Span = struct {
    start: u32,
    end: u32,
};

/// The CR and LF that end every line of a head (RFC 9112 §2.1).
const line_end = "\r\n";

/// Where the scan of one head stands. `scan` updates it and the caller keeps it between calls;
/// `reset` readies it for the next head.
pub const Scanner = struct {
    /// Octets of the caller's input already scanned.
    scanned: u32 = 0,
    /// Octets of the current line scanned so far, its CR not counted.
    line_len: u32 = 0,
    /// Lines ended so far, the skipped leading empty line not counted.
    lines: u32 = 0,
    /// Octets before the start line: 0, or `line_end.len` for the leading empty line skipped.
    skipped_len: u32 = 0,
    /// The last octet scanned was a CR, so the next must be LF.
    after_carriage_return: bool = false,

    pub fn reset(scanner: *Scanner) void {
        scanner.* = .{};
        assert(scanner.scanned == 0 and scanner.lines == 0);
    }

    /// Scans the octets of `input` not scanned before. Returns the head's span once its end is in
    /// `input`, or null when it needs more octets. `input` holds every octet the last call saw,
    /// then new ones: the caller consumes nothing from it until a head is returned.
    pub fn scan(scanner: *Scanner, role: Role, input: []const u8) Error!?Span {
        assert(scanner.scanned <= input.len);
        assert(scanner.scanned <= constants.head_len_max);
        const limit = @min(input.len, constants.head_len_max);
        var reader = Reader.init(input[0..limit]);
        _ = reader.take(scanner.scanned) catch unreachable;
        // Bounded by `head_len_max`, which `limit` never exceeds.
        for (0..constants.head_len_max) |_| {
            const octet = reader.read_byte() catch break;
            scanner.scanned += 1;
            if (try scanner.step(role, octet)) return scanner.span();
        }
        // RFC 9110 §5.4: no predefined limit, so colibri's applies and the head is refused.
        if (scanner.scanned == constants.head_len_max) return error.HeadTooLarge;
        assert(scanner.scanned == input.len);
        return null;
    }

    /// One octet. Returns true when it is the LF of the empty line that ends the head.
    fn step(scanner: *Scanner, role: Role, octet: u8) Error!bool {
        if (scanner.after_carriage_return) {
            scanner.after_carriage_return = false;
            // RFC 9112 §2.2: a CR not immediately followed by LF is a bare CR.
            if (octet != '\n') return error.BareCarriageReturn;
            return scanner.end_line(role);
        }
        if (octet == '\r') {
            scanner.after_carriage_return = true;
            return false;
        }
        // RFC 9112 §2.2: a recipient MAY recognize a lone LF as a line end; colibri does not.
        if (octet == '\n') return error.BareLineFeed;
        scanner.line_len += 1;
        const in_start_line = scanner.lines == 0;
        // RFC 9112 §3: no predefined limit on a request line, so colibri's applies. The limit
        // holds for a status line too, which has none either (RFC 9112 §4).
        if (in_start_line and scanner.line_len > constants.start_line_len_max) return error.StartLineTooLong;
        return false;
    }

    /// The CRLF of a line has been scanned. Returns true when the line was the empty line that
    /// ends the head.
    fn end_line(scanner: *Scanner, role: Role) Error!bool {
        assert(!scanner.after_carriage_return);
        const empty = scanner.line_len == 0;
        scanner.line_len = 0;
        if (!empty) {
            scanner.lines += 1;
            return false;
        }
        if (scanner.lines > 0) return true;
        // RFC 9112 §2.2: a server SHOULD ignore at least one empty line before a request line.
        // colibri ignores one; a response has no such allowance.
        if (role == .response or scanner.skipped_len > 0) return error.StartLineEmpty;
        scanner.skipped_len = line_end.len;
        return false;
    }

    fn span(scanner: *const Scanner) Span {
        assert(scanner.lines > 0);
        assert(scanner.skipped_len < scanner.scanned);
        return .{ .start = scanner.skipped_len, .end = scanner.scanned };
    }
};

const testing = std.testing;

fn expect_span(role: Role, input: []const u8, start: u32, end: u32) !void {
    var scanner: Scanner = .{};
    const span_found = (try scanner.scan(role, input)) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(start, span_found.start);
    try testing.expectEqual(end, span_found.end);
}

fn expect_error(role: Role, input: []const u8, err: Error) !void {
    var scanner: Scanner = .{};
    try testing.expectError(err, scanner.scan(role, input));
}

test "a head ends after the empty line, and the octets past it are not scanned" {
    const head = "GET / HTTP/1.1\r\nHost: a\r\n\r\n";
    try expect_span(.request, head, 0, head.len);
    try expect_span(.request, head ++ "body", 0, head.len);
    try expect_span(.response, "HTTP/1.1 204 \r\n\r\n", 0, 17);
}

test "RFC 9112 §2.2: a request may carry one leading empty line, never two, and a response none" {
    const head = "GET / HTTP/1.1\r\n\r\n";
    try expect_span(.request, "\r\n" ++ head, 2, 2 + head.len);
    try expect_error(.request, "\r\n\r\n" ++ head, error.StartLineEmpty);
    try expect_error(.response, "\r\nHTTP/1.1 200 \r\n\r\n", error.StartLineEmpty);
}

test "RFC 9112 §2.2: a bare CR and a lone LF are refused where they stand" {
    try expect_error(.request, "GET / HTTP/1.1\rHost: a\r\n\r\n", error.BareCarriageReturn);
    try expect_error(.request, "GET / HTTP/1.1\r\nHost: a\r\r\n\r\n", error.BareCarriageReturn);
    try expect_error(.request, "GET / HTTP/1.1\nHost: a\n\n", error.BareLineFeed);
    try expect_error(.request, "GET / HTTP/1.1\r\nHost: a\r\n\n", error.BareLineFeed);
    try expect_error(.response, "HTTP/1.1 200 \r\n\n", error.BareLineFeed);
}

test "a head that is not whole yet needs more octets, a CR at the end included" {
    var scanner: Scanner = .{};
    try testing.expectEqual(null, try scanner.scan(.request, "GET / HTTP/1.1\r\nHost: a\r"));
    try testing.expectEqual(null, try scanner.scan(.request, "GET / HTTP/1.1\r\nHost: a\r\n\r"));
    const found = (try scanner.scan(.request, "GET / HTTP/1.1\r\nHost: a\r\n\r\n")) orelse
        return error.TestUnexpectedResult;
    try testing.expectEqual(27, found.end);
}

test "every split of a head finds the span the whole head does, scanning each octet once" {
    const input = "\r\nPOST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\n\r\nok";
    const head_end = input.len - 2;
    for (1..input.len + 1) |split| {
        var scanner: Scanner = .{};
        const first = try scanner.scan(.request, input[0..split]);
        if (split >= head_end) {
            try testing.expectEqual(head_end, first.?.end);
            continue;
        }
        try testing.expectEqual(null, first);
        try testing.expectEqual(split, scanner.scanned);
        const found = (try scanner.scan(.request, input)) orelse return error.TestUnexpectedResult;
        try testing.expectEqual(Span{ .start = 2, .end = head_end }, found);
    }
}

/// Octets the limit tests fill a line with.
var test_octets: [constants.head_len_max + 1]u8 = @splat('a');

test "a start line of start_line_len_max octets is read, and one octet more is refused" {
    var scanner: Scanner = .{};
    try testing.expectEqual(null, try scanner.scan(.request, test_octets[0..constants.start_line_len_max]));
    try testing.expectError(error.StartLineTooLong, scanner.scan(.request, test_octets[0 .. constants.start_line_len_max + 1]));
}

test "a head with no end within head_len_max octets is refused, and one that ends at the limit is not" {
    const start = "GET / HTTP/1.1\r\n";
    const field = "a: ";
    var input: [constants.head_len_max + 1]u8 = @splat('v');
    @memcpy(input[0..start.len], start);
    @memcpy(input[start.len..][0..field.len], field);
    // Ends exactly at the limit: the value runs up to the last four octets, the two CRLFs.
    @memcpy(input[constants.head_len_max - 4 .. constants.head_len_max], "\r\n\r\n");
    try expect_span(.request, input[0..constants.head_len_max], 0, constants.head_len_max);
    // Ends one octet past the limit.
    @memcpy(input[constants.head_len_max - 4 .. constants.head_len_max], "vvvv");
    @memcpy(input[constants.head_len_max - 3 .. constants.head_len_max + 1], "\r\n\r\n");
    try expect_error(.request, &input, error.HeadTooLarge);
    var scanner: Scanner = .{};
    try testing.expectEqual(null, try scanner.scan(.request, input[0 .. constants.head_len_max - 1]));
}

test "reset readies the scanner for the next head" {
    var scanner: Scanner = .{};
    _ = try scanner.scan(.request, "GET / HTTP/1.1\r\n\r\n");
    scanner.reset();
    try testing.expectEqual(Span{ .start = 0, .end = 17 }, (try scanner.scan(.response, "HTTP/1.1 200 \r\n\r\n")).?);
}
