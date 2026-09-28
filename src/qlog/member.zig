//! One member of a JSON object (RFC 8259 §4), its name and its value, written with stdx's
//! `TextWriter` (decision 102 as amended). Every qlog record is objects of such members, so each
//! writer here writes the name and then the value.
const std = @import("std");
const assert = std.debug.assert;
const json = @import("json");
const constants = @import("constants.zig");

const TextWriter = json.TextWriter;

/// What a write fails with: stdx's refusal of a string that is not UTF-8, or a buffer the record
/// does not fit.
pub const Error = json.EncodeError || error{NoSpaceLeft};

/// A string: colibri's own ASCII, or a peer's field line that is printable ASCII. Any other octets
/// of a peer's are a hexstring (decision 102 as amended).
pub fn string(text: *TextWriter, name: []const u8, value: []const u8) Error!void {
    try text.name(name);
    try text.string(value);
}

/// Octets as lowercase hex digits, main schema §1.2's `hexstring`.
pub fn hex(text: *TextWriter, name: []const u8, octets: []const u8) Error!void {
    try text.name(name);
    try text.hex(octets);
}

/// A number with no sign, fraction or exponent (RFC 8259 §6).
pub fn unsigned(text: *TextWriter, name: []const u8, value: u64) Error!void {
    try text.name(name);
    try text.unsigned(value);
}

pub fn boolean(text: *TextWriter, name: []const u8, value: bool) Error!void {
    try text.name(name);
    try text.boolean(value);
}

/// A duration in nanoseconds, written as milliseconds with a three-digit fraction: main schema
/// §7.1 logs time in milliseconds, and RFC 8259 §6 allows a fraction's trailing zeros.
pub fn milliseconds(text: *TextWriter, name: []const u8, nanoseconds: u64) Error!void {
    const fraction = nanoseconds % constants.nanoseconds_per_millisecond / constants.nanoseconds_per_microsecond;
    assert(fraction < constants.nanoseconds_per_millisecond / constants.nanoseconds_per_microsecond);
    try text.name(name);
    try text.decimal(.{
        .integer = nanoseconds / constants.nanoseconds_per_millisecond,
        .fraction = fraction,
        .fraction_digits = constants.millisecond_fraction_digits,
    });
}

const testing = std.testing;

/// Room for the longest text a test writes. Test-only.
const test_buffer_len = 128;

test "each member is its name and its value, with commas between members" {
    var buffer: [test_buffer_len]u8 = undefined;
    var text = TextWriter.init(&buffer, .text);
    try text.begin_object();
    try unsigned(&text, "a", 1);
    try string(&text, "b", "x\"y");
    try hex(&text, "c", &.{ 0x00, 0xaf });
    try boolean(&text, "d", false);
    try text.end_object();
    try testing.expectEqualStrings("{\"a\":1,\"b\":\"x\\\"y\",\"c\":\"00af\",\"d\":false}", text.written());
}

test "milliseconds keep three digits of fraction" {
    var buffer: [test_buffer_len]u8 = undefined;
    var text = TextWriter.init(&buffer, .text);
    try text.begin_object();
    try milliseconds(&text, "a", 0);
    try milliseconds(&text, "b", 1_234_567_890);
    try milliseconds(&text, "c", 5_000);
    try milliseconds(&text, "d", 999);
    try text.end_object();
    try testing.expectEqualStrings("{\"a\":0.000,\"b\":1234.567,\"c\":0.005,\"d\":0.000}", text.written());
}
