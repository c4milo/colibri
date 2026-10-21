//! The tests that hold `message_scan.zig`'s `Scanner.scan` to the scan it replaced (design §8 step
//! 17). That scan loaded and stored the scanner's fields through its pointer for each octet. It
//! stays here as the reference. `scan` must return what the reference returns and leave the same
//! fields, for each input and for each split of it into two calls.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const http = @import("http");
const constants = @import("../constants.zig");
const message_scan = @import("message_scan.zig");

const Reader = core.Reader;
const Scanner = message_scan.Scanner;
const Role = message_scan.Role;
const Span = message_scan.Span;
const Error = message_scan.Error;
const Smith = std.testing.Smith;

/// The CR and LF that end every line of a head (RFC 9112 §2.1).
const line_end = "\r\n";

/// The reference: `Scanner.scan` as it was, with each field read and written through `scanner`.
fn scan_by_pointer(scanner: *Scanner, role: Role, input: []const u8) Error!?Span {
    assert(scanner.scanned <= input.len);
    assert(scanner.scanned <= constants.head_len_max);
    const limit = @min(input.len, constants.head_len_max);
    var reader = Reader.init(input[0..limit]);
    _ = reader.take(scanner.scanned) catch unreachable;
    // Bounded by `head_len_max`, which `limit` never exceeds.
    for (0..constants.head_len_max) |_| {
        const octet = reader.read_byte() catch break;
        scanner.scanned += 1;
        if (try step_by_pointer(scanner, role, octet)) return span_by_pointer(scanner);
    }
    // RFC 9110 §5.4: no predefined limit, so colibri's applies and the head is refused.
    if (scanner.scanned == constants.head_len_max) return error.HeadTooLarge;
    assert(scanner.scanned == input.len);
    return null;
}

fn step_by_pointer(scanner: *Scanner, role: Role, octet: u8) Error!bool {
    if (scanner.after_carriage_return) {
        scanner.after_carriage_return = false;
        // RFC 9112 §2.2: a CR not immediately followed by LF is a bare CR.
        if (octet != '\n') return error.BareCarriageReturn;
        return end_line_by_pointer(scanner, role);
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
    if (role == .request and in_start_line and !scanner.method_ended) try check_method_by_pointer(scanner, octet);
    return false;
}

fn check_method_by_pointer(scanner: *Scanner, octet: u8) Error!void {
    if (octet == ' ') {
        // RFC 9110 §5.6.2: a token is one or more tchar, so a method is never empty.
        if (scanner.line_len == 1) return error.MethodInvalid;
        scanner.method_ended = true;
        return;
    }
    // RFC 9110 §9.1: method = token, so a method holds tchar alone.
    if (!http.field.is_tchar(octet)) return error.MethodInvalid;
}

fn end_line_by_pointer(scanner: *Scanner, role: Role) Error!bool {
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

fn span_by_pointer(scanner: *const Scanner) Span {
    assert(scanner.lines > 0);
    assert(scanner.skipped_len < scanner.scanned);
    return .{ .start = scanner.skipped_len, .end = scanner.scanned };
}

/// The roles each input is read in.
const roles = [_]Role{ .request, .response };

/// What a call of a scan returned. A test counts the outcomes it saw, to show that its inputs
/// make each one it names.
const Outcome = enum {
    span,
    more,
    bare_carriage_return,
    bare_line_feed,
    start_line_too_long,
    start_line_empty,
    head_too_large,
    method_invalid,
};

/// The outcomes a test saw.
const Seen = std.EnumSet(Outcome);

/// The outcomes each input shorter than `start_line_len_max` can make.
const short_outcomes: Seen = .initMany(&.{
    .span, .more, .bare_carriage_return, .bare_line_feed, .start_line_empty, .method_invalid,
});

/// The outcome that `result` names.
fn outcome_of(result: Error!?Span) Outcome {
    const found = result catch |failure| return switch (failure) {
        error.BareCarriageReturn => .bare_carriage_return,
        error.BareLineFeed => .bare_line_feed,
        error.StartLineTooLong => .start_line_too_long,
        error.StartLineEmpty => .start_line_empty,
        error.HeadTooLarge => .head_too_large,
        error.MethodInvalid => .method_invalid,
    };
    return if (found == null) .more else .span;
}

/// Fails when `scan` and the reference differ on `input` split at `split`, and prints both
/// outcomes. The first call reads `input[0..split]`. When it needs more octets, a second call
/// reads the whole input from where the first stopped. Each call must return the same span, the
/// same null or the same error, and leave the same fields. Returns the outcome of the last call.
fn expect_same(role: Role, input: []const u8, split: usize) !Outcome {
    var changed: Scanner = .{};
    var reference: Scanner = .{};
    const first = try expect_same_call(&changed, &reference, role, input[0..split]);
    if (first != .more) return first;
    return expect_same_call(&changed, &reference, role, input);
}

/// Most octets of an input that a difference prints.
const printed_len_max = 96;

/// One call of each scan, which must return the same outcome and leave the same fields.
fn expect_same_call(changed: *Scanner, reference: *Scanner, role: Role, input: []const u8) !Outcome {
    const changed_result = changed.scan(role, input);
    const reference_result = scan_by_pointer(reference, role, input);
    const same_result = std.meta.eql(changed_result, reference_result);
    if (same_result and std.meta.eql(changed.*, reference.*)) return outcome_of(reference_result);
    std.debug.print("first difference: {t} input {x} of {d} octets: scan {any} {any}, reference {any} {any}\n", .{
        role, input[0..@min(input.len, printed_len_max)], input.len, changed_result, changed.*, reference_result, reference.*,
    });
    return error.TestUnexpectedResult;
}

/// Runs `expect_same` on `input` in both roles, at each split from 0 to the whole input.
fn expect_same_at_each_split(input: []const u8, seen: *Seen) !void {
    for (roles) |role| {
        for (0..input.len + 1) |split| seen.insert(try expect_same(role, input, split));
    }
}

/// The kinds of octet the scan tells apart: CR, LF, SP, a tchar ('G'), and two octets that are
/// not tchar ('/' and NUL, RFC 9110 §5.6.2).
const letters = "\r\n G/\x00";

/// Writes the word numbered `number` among the words of `octets.len` letters.
fn write_word(number: usize, octets: []u8) void {
    var rest = number;
    for (octets) |*octet| {
        octet.* = letters[rest % letters.len];
        rest /= letters.len;
    }
}

/// The count of words of `len` letters.
fn word_count(len: usize) usize {
    return std.math.powi(usize, letters.len, len) catch unreachable;
}

test "scan does what the reference does on each word of up to six letters, at each split" {
    var seen: Seen = .initEmpty();
    var octets: [6]u8 = undefined;
    for (0..octets.len + 1) |len| {
        for (0..word_count(len)) |number| {
            write_word(number, octets[0..len]);
            try expect_same_at_each_split(octets[0..len], &seen);
        }
    }
    try std.testing.expect(seen.eql(short_outcomes));
}

test "scan does what the reference does on each short word inside a head, at each split" {
    // Each prefix leaves the scanner in another state: in the method, after it, after a line, or
    // in a field line.
    const prefix = "\r\nGET / HTTP/1.1\r\nX: ";
    const ends = [_][]const u8{ "", "\r\n\r\n", "x\r\n\r\n" };
    var seen: Seen = .initEmpty();
    var octets: [prefix.len + 3 + "x\r\n\r\n".len]u8 = undefined;
    for (0..prefix.len + 1) |prefix_len| {
        @memcpy(octets[0..prefix_len], prefix[0..prefix_len]);
        for (0..4) |word_len| {
            for (0..word_count(word_len)) |number| {
                write_word(number, octets[prefix_len..][0..word_len]);
                for (ends) |end| {
                    @memcpy(octets[prefix_len + word_len ..][0..end.len], end);
                    try expect_same_at_each_split(octets[0 .. prefix_len + word_len + end.len], &seen);
                }
            }
        }
    }
    try std.testing.expect(seen.eql(short_outcomes));
}

/// Octets on each side of a limit where `expect_same_near` splits an input.
const near_len = 2;

/// Runs `expect_same` on `input` in both roles, at each split within `near_len` octets of
/// `offset`, and at the whole input when `offset` is past it.
fn expect_same_near(input: []const u8, offset: usize, seen: *Seen) !void {
    const last = @min(offset + near_len, input.len);
    for (roles) |role| {
        for (@min(offset -| near_len, last)..last + 1) |split| seen.insert(try expect_same(role, input, split));
    }
}

test "scan does what the reference does at start_line_len_max and head_len_max, split near each" {
    const limits = [_]usize{ 1, constants.start_line_len_max, constants.head_len_max };
    var seen: Seen = .initEmpty();
    var input: [constants.head_len_max + 2]u8 = @splat('a');
    // A start line of start_line_len_max octets, then of one octet more.
    for (0..2) |extra| {
        const line_len = constants.start_line_len_max + extra;
        @memcpy(input[line_len..][0..4], "\r\n\r\n");
        for (limits) |limit| try expect_same_near(input[0 .. line_len + 4], limit, &seen);
        @memset(input[line_len..][0..4], 'a');
    }
    // A head that ends at head_len_max, then one octet later, then one with no end.
    const start = "GET / HTTP/1.1\r\nX: ";
    @memcpy(input[0..start.len], start);
    for (0..2) |extra| {
        const end = constants.head_len_max + extra;
        @memcpy(input[end - 4 .. end], "\r\n\r\n");
        for (limits) |limit| try expect_same_near(input[0..end], limit, &seen);
        @memset(input[end - 4 .. end], 'a');
    }
    for (limits) |limit| try expect_same_near(&input, limit, &seen);
    try std.testing.expect(seen.eql(.initMany(&.{ .span, .start_line_too_long, .head_too_large })));
}

/// Most octets one fuzz input carries: room for a start line and a few field lines.
const fuzz_input_len_max = 96;

/// Reads the input in both roles, at each split, through `scan` and through the reference.
fn fuzz_same(_: void, smith: *Smith) anyerror!void {
    var input: [fuzz_input_len_max]u8 = @splat(0);
    var seen: Seen = .initEmpty();
    try expect_same_at_each_split(input[0..smith.slice(&input)], &seen);
}

test "fuzz: scan does what the reference does, at each split" {
    try std.testing.fuzz({}, fuzz_same, .{
        .corpus = &.{
            core.fuzz.input("GET / HTTP/1.1\r\nHost: a\r\n\r\n"),
            core.fuzz.input("\r\nPOST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 2\r\n\r\nok"),
            core.fuzz.input("HTTP/1.1 200 OK\r\nX: a\r\n b\r\n\r\n"),
            core.fuzz.input("\x16\x03\x01\x02\x00"),
        },
    });
}

test "sweep: scan does what the reference does on every input of up to two octets" {
    try core.fuzz.sweep(fuzz_same, null);
}
