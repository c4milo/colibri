//! The prefixed integer of RFC 7541 §5.1, which RFC 9204 §4.1.1 uses unmodified: HPACK and QPACK
//! read the same integers (decision 11).
//!
//! An integer starts inside an octet whose high `8 - N` bits belong to the field before it. A
//! value below `2^N - 1` fits in the N-bit prefix. A larger value fills the prefix with ones and
//! carries the remainder in continuation octets, seven bits each, least significant group first,
//! with the high bit set on every octet but the last.
//!
//! The codec is generic over N in 1..8, because QPACK uses prefix widths HPACK never does
//! (RFC 9204 §4.1.1), and it decodes up to 62 bits, which RFC 9204 §4.1.1 requires. Decoding
//! checks, in order (invariant 7):
//!   1. the prefix octet and every continuation octet are present, or `error.Truncated`;
//!   2. no more than `integer_len_max` octets, or `error.IntegerTooLong`;
//!   3. the value is at most `integer_value_max`, or `error.IntegerTooLarge`.
//! The high bits of the prefix octet are the caller's: the decoder masks them off and never reads
//! them. A failed decode consumes nothing.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("constants.zig");

const Reader = core.Reader;
const Writer = core.Writer;

pub const DecodeError = core.reader.Error || error{
    /// More continuation octets than `integer_len_max` allows.
    IntegerTooLong,
    /// A value above `integer_value_max`.
    IntegerTooLarge,
};

/// The continuation flag of RFC 7541 §5.1, and the seven value bits beside it.
const continuation_flag: u8 = 0x80;
const continuation_value_mask: u8 = 0x7f;

/// `2^N - 1`: the largest value the prefix holds, and the mask that selects it.
fn prefix_max(comptime prefix_size: u4) u8 {
    comptime assert(prefix_size >= constants.protocol.integer_prefix_bits_min);
    comptime assert(prefix_size <= constants.protocol.integer_prefix_bits_max);
    return @intCast((@as(u16, 1) << prefix_size) - 1);
}

/// Decodes one integer whose prefix is the low `prefix_size` bits of the next octet.
pub fn decode(comptime prefix_size: u4, reader: *Reader) DecodeError!u64 {
    const mask = prefix_max(prefix_size);
    var cursor = reader.*;
    const prefix = (try cursor.read_byte()) & mask;
    // RFC 7541 §5.1: a value strictly less than 2^N - 1 is encoded within the prefix.
    if (prefix < mask) {
        reader.* = cursor;
        return prefix;
    }
    var value: u64 = mask;
    for (0..constants.protocol.integer_len_max - 1) |group| {
        const octet = try cursor.read_byte();
        const shift: u6 = @intCast(group * constants.protocol.integer_continuation_bits);
        value += @as(u64, octet & continuation_value_mask) << shift;
        // RFC 7541 §5.1: the continuation flag is clear on the last octet of the list.
        if (octet & continuation_flag != 0) continue;
        // RFC 9204 §4.1.1 requires 62 bits; RFC 7541 §5.1 makes a value past the limit an error.
        if (value > constants.protocol.integer_value_max) return error.IntegerTooLarge;
        reader.* = cursor;
        return value;
    }
    // RFC 7541 §5.1: an encoding longer than the implementation's octet limit is a decoding error.
    return error.IntegerTooLong;
}

/// Encodes `value` with its prefix in the low `prefix_size` bits of the first octet, whose high
/// bits are `high_bits`. All of the octets are written, or none.
pub fn encode(
    comptime prefix_size: u4,
    writer: *Writer,
    high_bits: u8,
    value: u64,
) core.writer.Error!void {
    const mask = prefix_max(prefix_size);
    assert(high_bits & mask == 0);
    assert(value <= constants.protocol.integer_value_max);
    // RFC 7541 §5.1: a value below 2^N - 1 is encoded within the prefix.
    if (value < mask) return writer.write_byte(high_bits | @as(u8, @intCast(value)));
    const rest = value - mask;
    // RFC 7541 §5.1: a remainder of seven bits or fewer is one continuation octet, the last.
    if (rest <= continuation_value_mask) {
        return writer.write_int(u16, @as(u16, high_bits | mask) << @bitSizeOf(u8) | @as(u16, @intCast(rest)));
    }
    return encode_continued(writer, high_bits | mask, rest);
}

/// Writes `first`, the caller's high bits over a prefix of ones, then `remainder` in two
/// continuation octets or more. It takes no prefix size, so it is compiled once for every one.
fn encode_continued(writer: *Writer, first: u8, remainder: u64) core.writer.Error!void {
    assert(remainder > continuation_value_mask);
    var octets: [constants.protocol.integer_len_max]u8 = @splat(0);
    octets[0] = first;
    var rest = remainder;
    for (1..constants.protocol.integer_len_max) |index| {
        // RFC 7541 §5.1: the continuation flag is clear on the last octet of the list.
        if (rest <= continuation_value_mask) {
            octets[index] = @intCast(rest);
            return writer.write_bytes(octets[0 .. index + 1]);
        }
        octets[index] = @as(u8, @truncate(rest)) | continuation_flag;
        rest >>= constants.protocol.integer_continuation_bits;
    }
    unreachable; // integer_len_max carries integer_value_max past any prefix (constants.zig).
}

const testing = std.testing;

fn expect_round_trip(
    comptime prefix_size: u4,
    high_bits: u8,
    value: u64,
    expected: []const u8,
) !void {
    var buffer: [constants.protocol.integer_len_max]u8 = @splat(0);
    var writer = Writer.init(&buffer);
    try encode(prefix_size, &writer, high_bits, value);
    try testing.expectEqualSlices(u8, expected, writer.written());
    var reader = Reader.init(writer.written());
    try testing.expectEqual(value, try decode(prefix_size, &reader));
    try testing.expectEqual(expected.len, reader.offset);
}

test "RFC 7541 Appendix C.1's three examples" {
    try expect_round_trip(5, 0, 10, &.{0x0a});
    try expect_round_trip(5, 0, 1337, &.{ 0x1f, 0x9a, 0x0a });
    try expect_round_trip(8, 0, 42, &.{0x2a});
}

test "the high bits belong to the caller and never change the value" {
    try expect_round_trip(5, 0xe0, 1337, &.{ 0xff, 0x9a, 0x0a });
    try expect_round_trip(1, 0xfe, 0, &.{0xfe});
    try expect_round_trip(7, 0x80, 126, &.{0xfe});
    try expect_round_trip(7, 0x80, 127, &.{ 0xff, 0x00 });
}

test "continuation octets follow only while the remainder is 128 or more" {
    // RFC 7541 §5.1's encoder loops while I >= 128, so a remainder of 127 is one octet.
    try expect_round_trip(5, 0, 31 + 127, &.{ 0x1f, 0x7f });
    try expect_round_trip(5, 0, 31 + 128, &.{ 0x1f, 0x80, 0x01 });
}

test "every prefix size carries the 62-bit ceiling in ten octets or fewer" {
    inline for (1..9) |size| {
        const prefix_size: u4 = @intCast(size);
        var buffer: [constants.protocol.integer_len_max]u8 = @splat(0);
        var writer = Writer.init(&buffer);
        try encode(prefix_size, &writer, 0, constants.protocol.integer_value_max);
        try testing.expect(writer.offset <= constants.protocol.integer_len_max);
        var reader = Reader.init(writer.written());
        try testing.expectEqual(constants.protocol.integer_value_max, try decode(prefix_size, &reader));
    }
}

test "a value one past the ceiling is IntegerTooLarge" {
    // 2^62 with a 1-bit prefix: 1 in the prefix, then 2^62 - 1 in nine groups.
    const too_large = [_]u8{ 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f };
    var reader = Reader.init(&too_large);
    try testing.expectError(error.IntegerTooLarge, decode(1, &reader));
    try testing.expectEqual(0, reader.offset);
}

test "an eleventh octet is IntegerTooLong even when every group is zero" {
    const too_long = [_]u8{ 0x1f, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00 };
    var reader = Reader.init(&too_long);
    try testing.expectError(error.IntegerTooLong, decode(5, &reader));
    try testing.expectEqual(0, reader.offset);
    // Ten octets of zero-valued padding is still inside the limit.
    var inside = Reader.init(too_long[0..9] ++ [_]u8{0x00});
    try testing.expectEqual(31, try decode(5, &inside));
}

test "a truncated integer consumes nothing" {
    for ([_][]const u8{ &.{}, &.{0x1f}, &.{ 0x1f, 0x9a } }) |bytes| {
        var reader = Reader.init(bytes);
        try testing.expectError(error.Truncated, decode(5, &reader));
        try testing.expectEqual(0, reader.offset);
    }
}

/// Most octets a fuzz input carries: one more than the longest integer, so IntegerTooLong is
/// reachable.
const fuzz_input_len_max = constants.protocol.integer_len_max + 1;

fn fuzz_decode(_: void, smith: *testing.Smith) anyerror!void {
    const prefix_size: u4 = smith.valueRangeAtMost(
        u4,
        constants.protocol.integer_prefix_bits_min,
        constants.protocol.integer_prefix_bits_max,
    );
    var input: [fuzz_input_len_max]u8 = @splat(0);
    const input_len = smith.slice(&input);
    var reader = Reader.init(input[0..input_len]);
    const value = switch (prefix_size) {
        inline constants.protocol.integer_prefix_bits_min...constants.protocol.integer_prefix_bits_max,
        => |size| decode(size, &reader),
        else => unreachable,
    } catch {
        try testing.expectEqual(0, reader.offset);
        return;
    };
    try testing.expect(value <= constants.protocol.integer_value_max);
    try testing.expect(reader.offset >= 1 and reader.offset <= constants.protocol.integer_len_max);
}

test "fuzz: decode returns a bounded value or consumes nothing" {
    try testing.fuzz({}, fuzz_decode, .{ .corpus = &.{
        core.fuzz.input_with_value(5, "\x1f\x9a\x0a"),
        core.fuzz.input_with_value(8, "\x2a"),
        core.fuzz.input_with_value(1, "\x01\xff\xff\xff\xff\xff\xff\xff\xff\x3f"),
        core.fuzz.input_with_value(5, "\x1f\x80\x80\x80\x80\x80\x80\x80\x80\x80\x00"),
    } });
}

test "sweep: every input of up to two octets, at every prefix size, is bounded or consumes nothing" {
    try core.fuzz.sweep(fuzz_decode, .{ .min = 1, .max = 8 });
}

/// The octets of one vector line at most, the base its numbers are in, and the lines of each kind
/// `prefixed_integer_vectors.txt` holds. Test-only.
const vector_octets_max = constants.protocol.integer_len_max + 1;
const vector_radix = 10;
const vector_encode_lines = 191;
const vector_decode_lines = 355;

/// `decode` at a prefix size a vector line names at run time. Test-only.
fn decode_at(prefix_size: u4, reader: *Reader) DecodeError!u64 {
    return switch (prefix_size) {
        inline constants.protocol.integer_prefix_bits_min...constants.protocol.integer_prefix_bits_max => |size| decode(size, reader),
        else => unreachable,
    };
}

/// `encode` at a prefix size a vector line names at run time. Test-only.
fn encode_at(prefix_size: u4, writer: *Writer, high_bits: u8, value: u64) core.writer.Error!void {
    return switch (prefix_size) {
        inline constants.protocol.integer_prefix_bits_min...constants.protocol.integer_prefix_bits_max => |size| encode(size, writer, high_bits, value),
        else => unreachable,
    };
}

/// `encode n high value octets`: `encode` writes the octets, and `decode` reads the value back
/// from all of them.
fn expect_encode_line(fields: *std.mem.TokenIterator(u8, .scalar)) !void {
    const prefix_size = try std.fmt.parseUnsigned(u4, fields.next().?, vector_radix);
    const high_bits = try std.fmt.parseUnsigned(u8, fields.next().?, vector_radix);
    const value = try std.fmt.parseUnsigned(u64, fields.next().?, vector_radix);
    var expected: [vector_octets_max]u8 = undefined;
    const octets = try std.fmt.hexToBytes(&expected, fields.next().?);
    var buffer: [vector_octets_max]u8 = undefined;
    var writer = Writer.init(&buffer);
    try encode_at(prefix_size, &writer, high_bits, value);
    try testing.expectEqualSlices(u8, octets, writer.written());
    var reader = Reader.init(octets);
    try testing.expectEqual(value, try decode_at(prefix_size, &reader));
    try testing.expectEqual(octets.len, reader.offset);
}

/// `decode n octets outcome`: `decode` answers the value and its length, or the error, and a
/// refusal consumes nothing.
fn expect_decode_line(fields: *std.mem.TokenIterator(u8, .scalar)) !void {
    const prefix_size = try std.fmt.parseUnsigned(u4, fields.next().?, vector_radix);
    var storage: [vector_octets_max]u8 = undefined;
    const octets = try std.fmt.hexToBytes(&storage, fields.next().?);
    var reader = Reader.init(octets);
    const answer = fields.next().?;
    const expected_error: ?DecodeError = if (std.mem.eql(u8, answer, "truncated"))
        error.Truncated
    else if (std.mem.eql(u8, answer, "too_long"))
        error.IntegerTooLong
    else if (std.mem.eql(u8, answer, "too_large"))
        error.IntegerTooLarge
    else
        null;
    if (expected_error) |failure| {
        try testing.expectError(failure, decode_at(prefix_size, &reader));
        try testing.expectEqual(0, reader.offset);
        return;
    }
    try testing.expectEqual(try std.fmt.parseUnsigned(u64, answer, vector_radix), try decode_at(prefix_size, &reader));
    try testing.expectEqual(try std.fmt.parseUnsigned(usize, fields.next().?, vector_radix), reader.offset);
}

test "the codec gives what the proved definitions give (spec/lean/Colibri/Wire/PrefixedInteger.lean)" {
    var lines = std.mem.splitScalar(u8, @embedFile("prefixed_integer_vectors.txt"), '\n');
    var encoded: usize = 0;
    var decoded: usize = 0;
    // Bounded by the file, which spec/lean/Vectors.lean writes.
    while (lines.next()) |line| {
        if (line.len == 0 or line[0] == '#') continue;
        var fields = std.mem.tokenizeScalar(u8, line, ' ');
        const kind = fields.next().?;
        if (std.mem.eql(u8, kind, "encode")) {
            try expect_encode_line(&fields);
            encoded += 1;
        } else {
            try testing.expectEqualStrings("decode", kind);
            try expect_decode_line(&fields);
            decoded += 1;
        }
    }
    try testing.expectEqual(vector_encode_lines, encoded);
    try testing.expectEqual(vector_decode_lines, decoded);
}

// The tests below hold `encode` to the encoder it replaced, which built every encoding in an array
// and wrote it with one call. It stays here as the reference: `encode` must return what it
// returns and leave the same octets written, at every prefix size and in every room.

/// The reference: `encode` as it was.
fn encode_by_array(comptime prefix_size: u4, writer: *Writer, high_bits: u8, value: u64) core.writer.Error!void {
    const mask = prefix_max(prefix_size);
    var octets: [constants.protocol.integer_len_max]u8 = @splat(0);
    if (value < mask) {
        octets[0] = high_bits | @as(u8, @intCast(value));
        return writer.write_bytes(octets[0..1]);
    }
    octets[0] = high_bits | mask;
    var rest = value - mask;
    for (1..constants.protocol.integer_len_max) |index| {
        // RFC 7541 §5.1: the continuation flag is clear on the last octet of the list.
        if (rest <= continuation_value_mask) {
            octets[index] = @intCast(rest);
            return writer.write_bytes(octets[0 .. index + 1]);
        }
        octets[index] = @as(u8, @truncate(rest)) | continuation_flag;
        rest >>= constants.protocol.integer_continuation_bits;
    }
    unreachable;
}

/// What a buffer holds before a call.
const untouched: u8 = 0xee;
/// The values the tests walk through one by one: every value of up to `walked_bits` bits, which
/// takes every prefix size through its one-octet, two-octet and three-octet encodings.
const walked_bits = 15;
const walked_values = 1 << walked_bits;
/// The rooms a value is encoded in: none, each up to the longest encoding, and one octet past.
const rooms = constants.protocol.integer_len_max + room_past_longest + 1;
/// The octets of room past the longest encoding the tests give.
const room_past_longest = 1;

/// Fails, printing both outcomes, when `encode` and the reference differ on `value` with `room`
/// octets of output: in whether they fail, or in the octets they leave written.
fn expect_same_encoding(comptime prefix_size: u4, high_bits: u8, value: u64, room: usize) !void {
    var changed_buffer: [constants.protocol.integer_len_max + 1]u8 = @splat(untouched);
    var reference_buffer: [constants.protocol.integer_len_max + 1]u8 = @splat(untouched);
    var changed = Writer.init(changed_buffer[0..room]);
    var reference = Writer.init(reference_buffer[0..room]);
    const changed_failed = if (encode(prefix_size, &changed, high_bits, value)) false else |_| true;
    const reference_failed = if (encode_by_array(prefix_size, &reference, high_bits, value)) false else |_| true;
    const same_octets = std.mem.eql(u8, &changed_buffer, &reference_buffer);
    if (changed_failed == reference_failed and changed.offset == reference.offset and same_octets) return;
    std.debug.print("first difference: prefix {d}, high bits {x}, value {d}, room {d}: encode {} {x}, reference {} {x}\n", .{
        prefix_size, high_bits, value, room, changed_failed, changed.written(), reference_failed, reference.written(),
    });
    return error.TestUnexpectedResult;
}

/// Compares on `value` in each room from none to one octet past what its encoding needs.
fn expect_same_in_every_room(comptime prefix_size: u4, high_bits: u8, value: u64) !void {
    for (0..rooms) |room| try expect_same_encoding(prefix_size, high_bits, value, room);
}

/// Compares at each value past the walked ones where an encoding gains an octet,
/// `2^N - 1 + 2^(7k)`, and at the values beside it, up to the ceiling.
fn expect_same_at_boundaries(comptime prefix_size: u4, high_bits: u8) !void {
    var group: u64 = 1;
    for (0..constants.protocol.integer_len_max) |_| {
        const boundary = prefix_max(prefix_size) + group;
        if (boundary > constants.protocol.integer_value_max) return;
        if (boundary >= walked_values) {
            for ([_]u64{ boundary - 1, boundary, boundary + 1 }) |value| try expect_same_in_every_room(prefix_size, high_bits, value);
        }
        if (group > constants.protocol.integer_value_max >> constants.protocol.integer_continuation_bits) return;
        group <<= constants.protocol.integer_continuation_bits;
    }
}

/// Compares at `prefix_size` with the caller's bits clear and with every one of them set.
fn expect_same_at_prefix(comptime prefix_size: u4) !void {
    const caller_bits: u8 = ~prefix_max(prefix_size);
    for ([_]u8{ 0, caller_bits }) |high_bits| {
        for (0..walked_values) |value| try expect_same_in_every_room(prefix_size, high_bits, value);
        try expect_same_at_boundaries(prefix_size, high_bits);
        try expect_same_in_every_room(prefix_size, high_bits, constants.protocol.integer_value_max);
    }
}

test "encode writes what the reference writes, at every prefix size, value and room" {
    inline for (constants.protocol.integer_prefix_bits_min..constants.protocol.integer_prefix_bits_max + 1) |prefix_size| {
        try expect_same_at_prefix(prefix_size);
    }
}
