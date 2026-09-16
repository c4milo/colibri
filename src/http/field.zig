//! Field names and field values as RFC 9110 §5 defines them, for both h2 and h3 (decision 15).
//!
//! Each validator returns the reason a field is invalid, never a protocol verdict: h2 and h3 turn
//! the same reason into different errors, so the protocol module names the error. Two rules stay
//! out of this file on purpose, and the protocol modules check both before they call here. The
//! lowercase rule is RFC 9113 §8.2 and RFC 9114 §4.2, not RFC 9110. A pseudo-header name starts
//! with a colon, which no token admits.
//!
//! A field name is checked in this order (invariant 7):
//!   1. not empty, or `error.FieldNameEmpty` (a token is one or more tchar, RFC 9110 §5.6.2);
//!   2. at most `field_name_len_max` octets, or `error.FieldNameTooLong`;
//!   3. every octet a tchar, or `error.FieldNameNotToken` (RFC 9110 §5.1, §5.6.2).
//!
//! A field value is checked in this order:
//!   1. at most `field_value_len_max` octets, or `error.FieldValueTooLong`;
//!   2. no NUL, CR or LF anywhere, or `error.FieldValueNulCarriageReturnOrLineFeed`;
//!   3. no other control octet anywhere, or `error.FieldValueControl`;
//!   4. no leading SP or HTAB, or `error.FieldValueLeadingWhitespace`;
//!   5. no trailing SP or HTAB, or `error.FieldValueTrailingWhitespace`.
//! Checks 2 and 3 are distinct because RFC 9110 §5.5 treats them differently: CR, LF and NUL must
//! be rejected or replaced, while a recipient may retain another control octet in a safe context.
//! h3 has no such choice: RFC 9114 §10.3 makes a value holding any character field-content does not
//! permit malformed, so the h3 module refuses check 3's reason and cites that section.
//!
//! Checks 4 and 5 come from two rules. RFC 9113 §8.2.1 makes a value that starts or ends with SP
//! or HTAB malformed in h2. RFC 9114 has no such rule, and the owner ruled on 2026-09-16 that h3
//! refuses it too, with one exception (decision 15). RFC 9110 §5.6.1.2 requires a recipient to
//! accept a list whose first or last member is empty, which puts whitespace at an end: `, gzip`
//! after leading OWS, or `gzip, ` with trailing OWS. `trim_empty_member_whitespace` removes exactly
//! that whitespace, and the h3 module calls it before `validate_value`; the h2 module does not.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");

const limits = core.constants;

pub const NameError = error{
    FieldNameEmpty,
    FieldNameTooLong,
    FieldNameNotToken,
};

pub const ValueError = error{
    FieldValueTooLong,
    FieldValueNulCarriageReturnOrLineFeed,
    FieldValueControl,
    FieldValueLeadingWhitespace,
    FieldValueTrailingWhitespace,
};

/// The octets RFC 9110 §5.6.2 lists as tchar: `!#$%&'*+-.^_`|~`, DIGIT and ALPHA.
const tchar_punctuation = "!#$%&'*+-.^_`|~";

/// One entry per octet value.
const TcharTable = [std.math.maxInt(u8) + 1]bool;

const tchar_table: TcharTable = build_tchar_table();

fn build_tchar_table() TcharTable {
    var table: TcharTable = @splat(false);
    for (tchar_punctuation) |octet| table[octet] = true;
    for ('0'..'9' + 1) |octet| table[octet] = true;
    for ('A'..'Z' + 1) |octet| table[octet] = true;
    for ('a'..'z' + 1) |octet| table[octet] = true;
    return table;
}

/// True for an octet RFC 9110 §5.6.2 admits in a token.
pub fn is_tchar(octet: u8) bool {
    return tchar_table[octet];
}

/// Checks that `name` is a field name: a token (RFC 9110 §5.1) no longer than colibri accepts.
pub fn validate_name(name: []const u8) NameError!void {
    // RFC 9110 §5.6.2: a token is one or more tchar, so an empty name is not a token.
    if (name.len == 0) return error.FieldNameEmpty;
    // RFC 9110 §5.4: no predefined limit, so colibri's limit applies and the peer is refused.
    if (name.len > limits.field_name_len_max) return error.FieldNameTooLong;
    for (name) |octet| {
        // RFC 9110 §5.1: field-name = token; RFC 9110 §5.6.2: token = 1*tchar.
        if (!is_tchar(octet)) return error.FieldNameNotToken;
    }
}

/// Checks that `value` is a field value (RFC 9110 §5.5) no longer than colibri accepts.
pub fn validate_value(value: []const u8) ValueError!void {
    // RFC 9110 §5.4: no predefined limit, so colibri's limit applies and the peer is refused.
    if (value.len > limits.field_value_len_max) return error.FieldValueTooLong;
    var control_seen = false;
    for (value) |octet| {
        const forbidden = octet == 0x00 or octet == '\r' or octet == '\n';
        // RFC 9110 §5.5: a recipient of CR, LF or NUL must reject the message or replace them.
        if (forbidden) return error.FieldValueNulCarriageReturnOrLineFeed;
        // RFC 9110 §5.5: field-vchar is VCHAR or obs-text, with SP and HTAB between them.
        if (is_control(octet)) control_seen = true;
    }
    // RFC 9110 §5.5: field values containing other CTL characters are also invalid.
    if (control_seen) return error.FieldValueControl;
    if (value.len == 0) return;
    // RFC 9113 §8.2.1: no leading SP or HTAB. h3 refuses it too (decision 15).
    if (is_whitespace(value[0])) return error.FieldValueLeadingWhitespace;
    // RFC 9113 §8.2.1: no trailing SP or HTAB. h3 refuses it too (decision 15).
    if (is_whitespace(value[value.len - 1])) return error.FieldValueTrailingWhitespace;
}

/// `value` without the whitespace RFC 9110 §5.6.1.2 requires a recipient to accept at either end
/// of a list: OWS before a leading comma, and OWS after a trailing comma, where the first or last
/// member is empty. Whitespace anywhere else stays, so `validate_value` still refuses a value that
/// starts or ends with it. The result is a slice of `value`.
///
/// It applies to every field, because a field value does not say whether its field is a list. A
/// singleton field that trims to a leading or trailing comma then fails its own grammar.
pub fn trim_empty_member_whitespace(value: []const u8) []const u8 {
    var trimmed = value;
    // RFC 9110 §5.6.1.2: `[ element ] *( OWS "," OWS [ element ] )` with an empty first element.
    const leading = std.mem.trimStart(u8, trimmed, list_whitespace);
    if (leading.len < trimmed.len and leading.len > 0 and leading[0] == ',') trimmed = leading;
    // RFC 9110 §5.6.1.2: the same syntax with an empty last element.
    const trailing = std.mem.trimEnd(u8, trimmed, list_whitespace);
    if (trailing.len < trimmed.len and trailing.len > 0 and trailing[trailing.len - 1] == ',') {
        trimmed = trailing;
    }
    return trimmed;
}

/// OWS: SP or HTAB (RFC 9110 §5.6.3).
const list_whitespace = " \t";

/// CTL is 0x00 to 0x1f and 0x7f (RFC 5234 Appendix B.1, which RFC 9110 §2.1 includes). HTAB is a
/// CTL, but RFC 9110 §5.5 admits it between field-vchars, so it is not reported here.
fn is_control(octet: u8) bool {
    return std.ascii.isControl(octet) and octet != '\t';
}

fn is_whitespace(octet: u8) bool {
    return octet == ' ' or octet == '\t';
}

/// Compares two field names the way RFC 9110 §5.1 says they compare: case-insensitively.
pub fn names_equal(first: []const u8, second: []const u8) bool {
    return std.ascii.eqlIgnoreCase(first, second);
}

const testing = std.testing;

test "every tchar RFC 9110 §5.6.2 lists is a tchar, and nothing else is" {
    var count: usize = 0;
    for (0..256) |octet| {
        if (is_tchar(@intCast(octet))) count += 1;
    }
    // Fifteen punctuation octets, ten digits and fifty-two letters.
    try testing.expectEqual(15 + 10 + 52, count);
    for ("\"(),/:;<=>?@[\\]{}") |delimiter| try testing.expect(!is_tchar(delimiter));
    for (" \t\x00\x7f\x80\xff") |octet| try testing.expect(!is_tchar(octet));
}

test "a field name is a non-empty token within the limit" {
    try validate_name("content-type");
    try validate_name("X-Custom_Header.1~");
    try testing.expectError(error.FieldNameEmpty, validate_name(""));
    try testing.expectError(error.FieldNameNotToken, validate_name(":path"));
    try testing.expectError(error.FieldNameNotToken, validate_name("bad name"));
    try testing.expectError(error.FieldNameNotToken, validate_name("caf\xc3\xa9"));
    const too_long: [limits.field_name_len_max + 1]u8 = @splat('a');
    try testing.expectError(error.FieldNameTooLong, validate_name(&too_long));
    try validate_name(too_long[0..limits.field_name_len_max]);
}

test "a field value admits VCHAR, obs-text and inner whitespace" {
    try validate_value("");
    try validate_value("text/html; charset=utf-8");
    try validate_value("a\tb c");
    try validate_value("\x80\xff");
    try validate_value("x");
    const at_limit: [limits.field_value_len_max]u8 = @splat('v');
    try validate_value(&at_limit);
}

test "a field value is refused in check order" {
    const too_long: [limits.field_value_len_max + 1]u8 = @splat(0);
    try testing.expectError(error.FieldValueTooLong, validate_value(&too_long));
    try testing.expectError(error.FieldValueNulCarriageReturnOrLineFeed, validate_value("a\x00b"));
    try testing.expectError(error.FieldValueNulCarriageReturnOrLineFeed, validate_value("a\rb"));
    try testing.expectError(error.FieldValueNulCarriageReturnOrLineFeed, validate_value("a\nb"));
    // A control octet seen before a NUL still reports the NUL first.
    const control_then_nul = validate_value("\x01\x00");
    try testing.expectError(error.FieldValueNulCarriageReturnOrLineFeed, control_then_nul);
    try testing.expectError(error.FieldValueControl, validate_value("a\x01b"));
    try testing.expectError(error.FieldValueControl, validate_value(" \x7f"));
    try testing.expectError(error.FieldValueLeadingWhitespace, validate_value(" a"));
    try testing.expectError(error.FieldValueLeadingWhitespace, validate_value("\ta"));
    try testing.expectError(error.FieldValueTrailingWhitespace, validate_value("a "));
    try testing.expectError(error.FieldValueTrailingWhitespace, validate_value("a\t"));
}

test "whitespace beside an empty first or last list member is trimmed, and nothing else is" {
    const trimmed = [_]struct { []const u8, []const u8 }{
        .{ " , gzip", ", gzip" },
        .{ "gzip, ", "gzip," },
        .{ "trailers,\t ", "trailers," },
        .{ " \t,x, \t", ",x," },
        .{ " , ", "," },
    };
    for (trimmed) |case| try testing.expectEqualStrings(case[1], trim_empty_member_whitespace(case[0]));
    const kept = [_][]const u8{ " gzip", "gzip ", " ", "\t", "", "a , b", "gzip ,", ",", " x ,y" };
    for (kept) |value| try testing.expectEqualStrings(value, trim_empty_member_whitespace(value));
}

test "a value h3 trims still fails validation when whitespace remains at an end" {
    try validate_value(trim_empty_member_whitespace("trailers, "));
    try validate_value(trim_empty_member_whitespace(" , trailers"));
    const leading = validate_value(trim_empty_member_whitespace(" trailers"));
    try testing.expectError(error.FieldValueLeadingWhitespace, leading);
    const trailing = validate_value(trim_empty_member_whitespace("trailers "));
    try testing.expectError(error.FieldValueTrailingWhitespace, trailing);
}

test "field names compare case-insensitively" {
    try testing.expect(names_equal("Content-Length", "content-length"));
    try testing.expect(!names_equal("content-length", "content-type"));
    try testing.expect(!names_equal("te", "tea"));
}

fn fuzz_validate(_: void, smith: *testing.Smith) anyerror!void {
    var input: [limits.field_name_len_max + 1]u8 = @splat(0);
    const input_len = smith.slice(&input);
    const bytes = input[0..input_len];
    if (validate_name(bytes)) {
        try testing.expect(bytes.len > 0);
        for (bytes) |octet| try testing.expect(is_tchar(octet));
    } else |_| {}
    if (validate_value(bytes)) {
        try testing.expect(std.mem.indexOfAny(u8, bytes, "\x00\r\n\x7f") == null);
        if (bytes.len == 0) return;
        try testing.expect(!is_whitespace(bytes[0]));
        try testing.expect(!is_whitespace(bytes[bytes.len - 1]));
    } else |_| {}
}

test "fuzz: a name or value that validates holds no forbidden octet" {
    try testing.fuzz({}, fuzz_validate, .{ .corpus = &.{
        core.fuzz.input("content-type"),
        core.fuzz.input(" a"),
        core.fuzz.input("a\x00"),
        core.fuzz.input("\x80"),
    } });
}

/// Most octets `fuzz_trim` reads. Test-only.
const fuzz_trim_input_len_max = 16;

fn fuzz_trim(_: void, smith: *testing.Smith) anyerror!void {
    var input: [fuzz_trim_input_len_max]u8 = @splat(0);
    const bytes = input[0..smith.slice(&input)];
    const trimmed = trim_empty_member_whitespace(bytes);
    const start = std.mem.indexOf(u8, bytes, trimmed) orelse return error.TestUnexpectedResult;
    // Only whitespace goes, and only beside a comma that stays.
    for (bytes[0..start]) |octet| try testing.expect(is_whitespace(octet));
    for (bytes[start + trimmed.len ..]) |octet| try testing.expect(is_whitespace(octet));
    if (start > 0) try testing.expectEqual(',', trimmed[0]);
    if (start + trimmed.len < bytes.len) try testing.expectEqual(',', trimmed[trimmed.len - 1]);
}

test "fuzz: trimming removes only whitespace beside a comma at an end" {
    try testing.fuzz({}, fuzz_trim, .{ .corpus = &.{
        core.fuzz.input(" , gzip"),
        core.fuzz.input("gzip, \t"),
        core.fuzz.input(" gzip "),
    } });
}

test "sweep: every value of up to two octets loses only whitespace beside an end comma" {
    try core.fuzz.sweep(fuzz_trim, null);
}

test "sweep: every name or value of up to two octets that validates holds no forbidden octet" {
    try core.fuzz.sweep(fuzz_validate, null);
}
