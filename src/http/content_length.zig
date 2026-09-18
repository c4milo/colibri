//! Content-Length as RFC 9110 §8.6 defines it, for both h2 and h3 (decision 15): the decimal
//! number of octets a message's content holds, read from every content-length line of a field
//! section.
//!
//! RFC 9110 §8.6 gives the grammar `Content-Length = 1*DIGIT`. It lets a recipient of a value that
//! repeats one decimal value as a comma-separated list, such as "42, 42", either reject the message
//! or read one instance of the value. RFC 9110 §5.3 lets a recipient combine two lines that share
//! a name into one line, separated by a comma and optional whitespace, without changing the
//! message's semantics. Two lines of "42" and one line of "42, 42" are therefore the same message,
//! and `from_section` gives both the same answer. It splits every line at its commas, trims SP and
//! HTAB from each member, and reads every member of every line as one list.
//!
//! The members are checked in arrival order, line by line and then left to right (invariant 7):
//!   1. a member that is not 1*DIGIT, an empty member included, is `error.ContentLengthNotDigits`;
//!   2. a member whose octets differ from the first member's is `error.ContentLengthDiffers`;
//!   3. once every member has passed, a first member that does not fit a u64 is
//!      `error.ContentLengthTooLarge`.
//!
//! Where RFC 9110 §8.6 leaves a choice, this file takes the strict side:
//!   - members compare by their octets, so "4" and "04" differ, and a message carrying both is
//!     refused. §8.6 lets a recipient reject any repeated value.
//!   - RFC 9110 §8.6 asks a recipient to prevent integer overflow on a large value. A value that
//!     does not fit a u64 is refused.
//!
//! Field validation refuses SP or HTAB at either end of a value before this file reads it
//! (RFC 9113 §8.2.1; decision 15 for h3). This file trims that whitespace from a member all the
//! same, so it does not depend on which protocol calls it.
//!
//! This file returns a reason, never a verdict. h2 and h3 each name the error a refused value is
//! (decision 15). Whether the value equals the content's length is the protocol module's check.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("constants.zig");
const field = @import("field.zig");
const field_section = @import("field_section.zig");

const FieldSection = field_section.FieldSection;

pub const Error = error{
    /// A member that is not 1*DIGIT (RFC 9110 §8.6).
    ContentLengthNotDigits,
    /// A member whose octets differ from the first member's (RFC 9110 §8.6).
    ContentLengthDiffers,
    /// A value that does not fit a u64 (RFC 9110 §8.6).
    ContentLengthTooLarge,
};

/// The field's name, as RFC 9110 §8.6 spells it. Names compare case-insensitively (RFC 9110 §5.1).
pub const name = "Content-Length";

/// The whitespace RFC 9110 §5.3 allows around the comma that combines two lines: OWS is SP or HTAB
/// (RFC 9110 §5.6.3).
const optional_whitespace = " \t";

/// Most calls `check_line` makes to its splitter. n octets hold at most n + 1 members, and one
/// more call finds the end, so the bound is never the reason the loop stops.
const member_split_calls_max = core.constants.field_value_len_max + member_split_calls_past_len;
const member_split_calls_past_len = 2;

/// The content length every content-length line of `section` declares, or null when the section
/// has no such line.
pub fn from_section(section: *const FieldSection) Error!?u64 {
    assert(section.len() <= core.constants.field_count_max);
    var first: ?[]const u8 = null;
    for (0..section.len()) |index| {
        const line = section.get(@intCast(index));
        if (!field.names_equal(line.name, name)) continue;
        try check_line(line.value, &first);
    }
    const digits = first orelse return null;
    assert(digits.len > 0);
    return try parse_digits(digits);
}

/// Steps 1 and 2 for every member of one line. `first` holds the first member of the section, once
/// one has been read.
fn check_line(value: []const u8, first: *?[]const u8) Error!void {
    assert(value.len <= core.constants.field_value_len_max);
    var members = std.mem.splitScalar(u8, value, ',');
    for (0..member_split_calls_max) |_| {
        const member = members.next() orelse return;
        // RFC 9110 §5.3: a comma and OWS separate members the way a line boundary does.
        const trimmed = std.mem.trim(u8, member, optional_whitespace);
        // RFC 9110 §8.6: Content-Length = 1*DIGIT, and the list it lets a recipient read holds
        // decimal values only.
        if (!is_digits(trimmed)) return error.ContentLengthNotDigits;
        const expected = first.* orelse {
            first.* = trimmed;
            continue;
        };
        // RFC 9110 §8.6: only the same decimal value repeated may be read as one instance.
        if (!std.mem.eql(u8, expected, trimmed)) return error.ContentLengthDiffers;
    }
    unreachable;
}

/// True when `member` is 1*DIGIT (RFC 9110 §8.6), where DIGIT is 0x30 to 0x39 (RFC 5234
/// Appendix B.1).
fn is_digits(member: []const u8) bool {
    if (member.len == 0) return false;
    for (member) |octet| {
        if (!std.ascii.isDigit(octet)) return false;
    }
    return true;
}

/// Step 3: `digits`, which `is_digits` accepted, as a u64.
fn parse_digits(digits: []const u8) Error!u64 {
    assert(digits.len > 0);
    assert(digits.len <= core.constants.field_value_len_max);
    var total: u64 = 0;
    for (digits) |octet| {
        // RFC 9110 §8.6: a recipient prevents parsing errors due to integer conversion overflows.
        const shifted = std.math.mul(u64, total, constants.content_length_radix) catch
            return error.ContentLengthTooLarge;
        // RFC 9110 §8.6: the same rule, on the digit added.
        total = std.math.add(u64, shifted, octet - '0') catch return error.ContentLengthTooLarge;
    }
    return total;
}

const testing = std.testing;

/// The section the tests fill, placed outside any stack frame.
var test_section: FieldSection = undefined;

/// `test_section` holding one content-length line per value, after one other line.
fn section_of(values: []const []const u8) !*const FieldSection {
    test_section.init();
    try test_section.append("x-other", "5");
    for (values) |value| try test_section.append("content-length", value);
    return &test_section;
}

fn expect_refused(err: Error, values: []const []const u8) !void {
    try testing.expectError(err, from_section(try section_of(values)));
}

fn expect_length(expected: ?u64, values: []const []const u8) !void {
    try testing.expectEqual(expected, try from_section(try section_of(values)));
}

test "a section without content-length has none, and one line of 4 reads back in any name case" {
    try expect_length(null, &.{});
    try expect_length(4, &.{"4"});
    test_section.init();
    try test_section.append("CONTENT-LENGTH", "12");
    try testing.expectEqual(12, (try from_section(&test_section)).?);
}

test "a member that is not 1*DIGIT is ContentLengthNotDigits, including the octets next to 0 and 9" {
    const refused = [_][]const u8{ "", "x", "+4", "-1", "4_0", "0x10", "4x", "/4", "4:", "4 4", "4;" };
    for (refused) |value| try expect_refused(error.ContentLengthNotDigits, &.{value});
    for ([_][]const u8{ "0", "9", "0123456789" }) |value| _ = try from_section(try section_of(&.{value}));
}

test "two lines of 4 and one line of 4, 4 read as 4, because RFC 9110 §5.3 makes them one message" {
    try expect_length(4, &.{ "4", "4" });
    try expect_length(4, &.{"4, 4"});
    try expect_length(4, &.{"4,4"});
    try expect_length(4, &.{"4 ,\t4"});
    try expect_length(4, &.{ "4, 4", "4" });
}

test "4 then 5 is ContentLengthDiffers on two lines or one, and so is 4 then 04" {
    try expect_refused(error.ContentLengthDiffers, &.{ "4", "5" });
    try expect_refused(error.ContentLengthDiffers, &.{"4, 5"});
    try expect_refused(error.ContentLengthDiffers, &.{ "4", "4, 5" });
    try expect_refused(error.ContentLengthDiffers, &.{ "4", "04" });
    try expect_refused(error.ContentLengthDiffers, &.{"44, 4"});
}

test "an empty member is ContentLengthNotDigits, on its own line or beside a comma" {
    try expect_refused(error.ContentLengthNotDigits, &.{ "4", "" });
    try expect_refused(error.ContentLengthNotDigits, &.{"4,"});
    try expect_refused(error.ContentLengthNotDigits, &.{",4"});
    try expect_refused(error.ContentLengthNotDigits, &.{"4,,4"});
    try expect_refused(error.ContentLengthNotDigits, &.{"4, "});
}

test "2^64 - 1 reads back, 2^64 is ContentLengthTooLarge, and leading zeros do not count" {
    try expect_length(std.math.maxInt(u64), &.{"18446744073709551615"});
    try expect_length(7, &.{"007"});
    try expect_length(std.math.maxInt(u64), &.{"000018446744073709551615"});
    try expect_refused(error.ContentLengthTooLarge, &.{"18446744073709551616"});
    try expect_refused(error.ContentLengthTooLarge, &.{"99999999999999999999"});
    try expect_refused(error.ContentLengthTooLarge, &.{"184467440737095516150"});
}

test "members are checked in arrival order, each for digits and then against the first, before parsing" {
    try expect_refused(error.ContentLengthNotDigits, &.{ "99999999999999999999", "x" });
    try expect_refused(error.ContentLengthDiffers, &.{ "99999999999999999999", "4" });
    try expect_refused(error.ContentLengthDiffers, &.{ "4", "5", "x" });
    try expect_refused(error.ContentLengthDiffers, &.{ "4", "5, x" });
    try expect_refused(error.ContentLengthNotDigits, &.{ "4", "x, 5" });
    try expect_refused(error.ContentLengthNotDigits, &.{"4, 5x"});
}

test "a value of field_value_len_max members ends the list rather than the loop" {
    var digits: [core.constants.field_value_len_max]u8 = @splat(',');
    for (0..digits.len) |index| {
        if (index % 2 == 0) digits[index] = '1';
    }
    test_section.init();
    try test_section.append("content-length", &digits);
    try testing.expectError(error.ContentLengthNotDigits, from_section(&test_section));
    test_section.init();
    try test_section.append("content-length", digits[0 .. digits.len - 1]);
    try testing.expectEqual(1, (try from_section(&test_section)).?);
}

/// Most octets a fuzz input carries. Test-only.
const fuzz_input_len_max = 32;

/// The base `std.fmt.parseUnsigned` reads a member in, independent of `parse_digits`. Test-only.
const fuzz_radix = 10;

fn fuzz_content_length(_: void, smith: *testing.Smith) anyerror!void {
    var input: [fuzz_input_len_max]u8 = @splat(0);
    const value = input[0..smith.slice(&input)];
    const length = from_section(try section_of(&.{value})) catch return;
    // A value this file accepts holds only digits, commas and OWS, and its first member reads back.
    for (value) |octet| try testing.expect(std.ascii.isDigit(octet) or std.mem.indexOfScalar(u8, ", \t", octet) != null);
    var members = std.mem.splitScalar(u8, value, ',');
    const first = std.mem.trim(u8, members.first(), optional_whitespace);
    try testing.expectEqual(try std.fmt.parseUnsigned(u64, first, fuzz_radix), length.?);
}

test "fuzz: a content-length this file accepts holds only digits and separators, and reads back" {
    try testing.fuzz({}, fuzz_content_length, .{ .corpus = &.{
        core.fuzz.input("4, 4"),
        core.fuzz.input("18446744073709551616"),
    } });
}

test "sweep: every content-length of up to two octets this file accepts reads back" {
    try core.fuzz.sweep(fuzz_content_length, null);
}
