//! A JSON text written into the caller's buffer (RFC 8259), for the records of a qlog log
//! (decision 102). It writes what qlog needs and nothing else: objects, arrays, strings of
//! colibri's own ASCII, hexstrings, unsigned integers, booleans and milliseconds.
//!
//! Every write goes through `core.Writer`, so a text that does not fit fails with
//! `error.NoSpaceLeft`, and the log drops the record whole. The writer tracks the open objects and
//! arrays to put a comma between members (RFC 8259 §4, §5) and none after a member's name.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("constants.zig");

pub const Error = core.writer.Error;

pub const Json = struct {
    writer: core.Writer,
    /// How many objects and arrays are open.
    depth: u8 = 0,
    /// For each open object or array, whether it has a member yet, which says whether the next
    /// member needs a comma before it.
    has_member: [constants.json_depth_max]bool = @splat(false),
    /// Whether the last write was a member's name, whose value follows it with no comma.
    after_key: bool = false,

    pub fn init(buffer: []u8) Json {
        return .{ .writer = core.Writer.init(buffer) };
    }

    pub fn begin_object(json: *Json) Error!void {
        try json.open('{');
    }

    pub fn end_object(json: *Json) Error!void {
        try json.close('}');
    }

    pub fn begin_array(json: *Json) Error!void {
        try json.open('[');
    }

    pub fn end_array(json: *Json) Error!void {
        try json.close(']');
    }

    /// An object member's name. qlog's names are lowercase ASCII (main schema §11.2).
    pub fn key(json: *Json, name: []const u8) Error!void {
        assert(json.depth > 0 and !json.after_key);
        assert(name.len > 0);
        try json.separate();
        try json.write_string(name);
        try json.writer.write_byte(':');
        json.after_key = true;
    }

    /// A string of colibri's own ASCII. A peer's octets are a hexstring (decision 102).
    pub fn string(json: *Json, text: []const u8) Error!void {
        try json.begin_value();
        try json.write_string(text);
    }

    /// Octets as lowercase hex digits between quotation marks, main schema §1.2's `hexstring`.
    pub fn hexstring(json: *Json, octets: []const u8) Error!void {
        try json.begin_value();
        try json.writer.write_byte('"');
        // Bounded by the octets.
        for (octets) |octet| {
            try json.writer.write_byte(constants.hex_digits[octet >> constants.nibble_bits]);
            try json.writer.write_byte(constants.hex_digits[octet & (constants.hex_digits.len - 1)]);
        }
        try json.writer.write_byte('"');
    }

    /// A number with no sign, fraction or exponent (RFC 8259 §6).
    pub fn unsigned(json: *Json, value: u64) Error!void {
        try json.begin_value();
        try json.writer.print("{d}", .{value});
    }

    pub fn boolean(json: *Json, value: bool) Error!void {
        try json.begin_value();
        try json.writer.write_bytes(if (value) "true" else "false");
    }

    /// A duration in nanoseconds, written as milliseconds with a three-digit fraction: main schema
    /// §7.1 logs time in milliseconds, and RFC 8259 §6 allows a fraction's trailing zeros.
    pub fn milliseconds(json: *Json, nanoseconds: u64) Error!void {
        const whole = nanoseconds / constants.nanoseconds_per_millisecond;
        const fraction = nanoseconds % constants.nanoseconds_per_millisecond / constants.nanoseconds_per_microsecond;
        assert(fraction < constants.nanoseconds_per_millisecond / constants.nanoseconds_per_microsecond);
        try json.begin_value();
        try json.writer.print("{d}.{d:0>3}", .{ whole, fraction });
    }

    pub fn field_string(json: *Json, name: []const u8, text: []const u8) Error!void {
        try json.key(name);
        try json.string(text);
    }

    pub fn field_hexstring(json: *Json, name: []const u8, octets: []const u8) Error!void {
        try json.key(name);
        try json.hexstring(octets);
    }

    pub fn field_unsigned(json: *Json, name: []const u8, value: u64) Error!void {
        try json.key(name);
        try json.unsigned(value);
    }

    pub fn field_boolean(json: *Json, name: []const u8, value: bool) Error!void {
        try json.key(name);
        try json.boolean(value);
    }

    pub fn field_milliseconds(json: *Json, name: []const u8, nanoseconds: u64) Error!void {
        try json.key(name);
        try json.milliseconds(nanoseconds);
    }

    /// The text written so far.
    pub fn written(json: *const Json) []const u8 {
        return json.writer.written();
    }

    fn open(json: *Json, bracket: u8) Error!void {
        assert(json.depth < constants.json_depth_max);
        try json.begin_value();
        try json.writer.write_byte(bracket);
        json.has_member[json.depth] = false;
        json.depth += 1;
    }

    fn close(json: *Json, bracket: u8) Error!void {
        assert(json.depth > 0);
        assert(!json.after_key);
        try json.writer.write_byte(bracket);
        json.depth -= 1;
    }

    /// Before any value: the comma an array member needs, and nothing after a member's name.
    fn begin_value(json: *Json) Error!void {
        if (json.after_key) {
            json.after_key = false;
            return;
        }
        try json.separate();
    }

    /// The comma between the members of the innermost object or array, and none before its first.
    fn separate(json: *Json) Error!void {
        if (json.depth == 0) return;
        const index = json.depth - 1;
        if (json.has_member[index]) try json.writer.write_byte(',');
        json.has_member[index] = true;
    }

    /// RFC 8259 §7: a string escapes the quotation mark, the reverse solidus and the control
    /// characters U+0000 through U+001F. colibri's text is ASCII, which the assert holds it to.
    fn write_string(json: *Json, text: []const u8) Error!void {
        try json.writer.write_byte('"');
        // Bounded by the text.
        for (text) |octet| {
            assert(octet < constants.ascii_end);
            if (octet == '"' or octet == '\\') {
                try json.writer.write_byte('\\');
                try json.writer.write_byte(octet);
            } else if (octet <= constants.control_character_last) {
                try json.writer.write_bytes("\\u00");
                try json.writer.write_byte(constants.hex_digits[octet >> constants.nibble_bits]);
                try json.writer.write_byte(constants.hex_digits[octet & (constants.hex_digits.len - 1)]);
            } else {
                try json.writer.write_byte(octet);
            }
        }
        try json.writer.write_byte('"');
    }
};

const testing = std.testing;

test "an object separates its members with commas and none after a name" {
    var buffer: [128]u8 = undefined;
    var json = Json.init(&buffer);
    try json.begin_object();
    try json.field_unsigned("a", 1);
    try json.field_string("b", "x");
    try json.key("c");
    try json.begin_array();
    try json.unsigned(2);
    try json.boolean(false);
    try json.begin_object();
    try json.end_object();
    try json.end_array();
    try json.end_object();
    try testing.expectEqualStrings("{\"a\":1,\"b\":\"x\",\"c\":[2,false,{}]}", json.written());
    try testing.expectEqual(0, json.depth);
}

test "a string escapes the quotation mark, the reverse solidus and control characters" {
    var buffer: [64]u8 = undefined;
    var json = Json.init(&buffer);
    try json.string("a\"b\\c\x00\x1f d");
    try testing.expectEqualStrings("\"a\\\"b\\\\c\\u0000\\u001f d\"", json.written());
}

test "a hexstring is lowercase hex digits of each octet" {
    var buffer: [32]u8 = undefined;
    var json = Json.init(&buffer);
    try json.hexstring(&.{ 0x00, 0x0f, 0xa5, 0xff });
    try testing.expectEqualStrings("\"000fa5ff\"", json.written());
}

test "milliseconds keep three digits of fraction" {
    var buffer: [64]u8 = undefined;
    var json = Json.init(&buffer);
    try json.begin_array();
    try json.milliseconds(0);
    try json.milliseconds(1_234_567_890);
    try json.milliseconds(5_000);
    try json.milliseconds(999);
    try json.end_array();
    try testing.expectEqualStrings("[0.000,1234.567,0.005,0.000]", json.written());
}

test "a text that does not fit fails without passing the buffer" {
    var buffer: [5]u8 = undefined;
    var json = Json.init(&buffer);
    try json.begin_object();
    try testing.expectError(error.NoSpaceLeft, json.field_string("key", "value"));
    try testing.expect(json.written().len <= buffer.len);
}
