//! The QUIC variable-length integer of RFC 9000 §16, used by the QUIC and h3 framing layers and
//! never by a field-section representation (decision 11).
//!
//! The two most significant bits of the first octet give the encoding length: 1, 2, 4 or 8
//! octets, carrying 6, 14, 30 or 62 bits in network byte order. The decoder reports how many
//! octets it consumed (invariant 9), because RFC 9000 §16 permits a non-minimal encoding
//! everywhere except the Frame Type field (§12.4), and only the caller knows which field it is
//! reading.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("constants.zig");

const Reader = core.Reader;
const Writer = core.Writer;

/// The first octet's two most significant bits encode the base-2 logarithm of the length
/// (RFC 9000 §16).
const length_shift: u3 = 6;
const value_mask: u8 = 0x3f;

pub const Decoded = struct {
    value: u64,
    /// Octets the encoding occupied: 1, 2, 4 or 8.
    encoded_len: u8,
};

/// Decodes one integer, consuming all of its octets or none.
pub fn decode(reader: *Reader) core.reader.Error!Decoded {
    const first = try reader.peek_byte();
    // RFC 9000 §16: the two most significant bits give the length as a power of two.
    const encoded_len: u8 = @as(u8, 1) << @intCast(first >> length_shift);
    // RFC 9000 §16: the value occupies the rest of the encoding, so a short read is a truncation.
    const octets = try reader.take(encoded_len);
    var value: u64 = octets[0] & value_mask;
    for (octets[1..]) |octet| value = (value << 8) | octet;
    assert(value <= constants.varint_value_max);
    return .{ .value = value, .encoded_len = encoded_len };
}

/// The fewest octets that carry `value`.
pub fn encoded_len_minimal(value: u64) u8 {
    assert(value <= constants.varint_value_max);
    if (value < 1 << 6) return 1;
    if (value < 1 << 14) return 2;
    if (value < 1 << 30) return 4;
    return constants.varint_len_max;
}

/// Encodes `value` in the fewest octets.
pub fn encode(writer: *Writer, value: u64) core.writer.Error!void {
    return encode_with_len(writer, value, encoded_len_minimal(value));
}

/// Encodes `value` in exactly `encoded_len` octets, all of them or none. RFC 9000 §16 permits a
/// longer encoding than the minimum outside the Frame Type field.
pub fn encode_with_len(writer: *Writer, value: u64, encoded_len: u8) core.writer.Error!void {
    assert(encoded_len == 1 or encoded_len == 2 or encoded_len == 4 or encoded_len == 8);
    assert(encoded_len >= encoded_len_minimal(value));
    var octets: [constants.varint_len_max]u8 = @splat(0);
    var rest = value;
    for (0..encoded_len) |index| {
        octets[encoded_len - 1 - index] = @truncate(rest);
        rest >>= 8;
    }
    assert(rest == 0);
    octets[0] |= @as(u8, std.math.log2_int(u8, encoded_len)) << length_shift;
    try writer.write_bytes(octets[0..encoded_len]);
}

const testing = std.testing;

fn expect_decodes(bytes: []const u8, value: u64) !void {
    var reader = Reader.init(bytes);
    const decoded = try decode(&reader);
    try testing.expectEqual(value, decoded.value);
    try testing.expectEqual(bytes.len, decoded.encoded_len);
    try testing.expectEqual(bytes.len, reader.offset);
}

test "RFC 9000 Appendix A.1's sample decodings" {
    const eight_octets = [_]u8{ 0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c };
    try expect_decodes(&eight_octets, 151_288_809_941_952_652);
    try expect_decodes(&.{ 0x9d, 0x7f, 0x3e, 0x7d }, 494_878_333);
    try expect_decodes(&.{ 0x7b, 0xbd }, 15_293);
    try expect_decodes(&.{0x25}, 37);
    try expect_decodes(&.{ 0x40, 0x25 }, 37);
}

test "each length's largest value round-trips and one more needs the next length" {
    const limits = [_]struct { u64, u8 }{ .{ 63, 1 }, .{ 16_383, 2 }, .{ 1_073_741_823, 4 } };
    for (limits) |limit| {
        try testing.expectEqual(limit[1], encoded_len_minimal(limit[0]));
        try testing.expectEqual(limit[1] * 2, encoded_len_minimal(limit[0] + 1));
    }
    try testing.expectEqual(8, encoded_len_minimal(constants.varint_value_max));
    var buffer: [8]u8 = @splat(0);
    var writer = Writer.init(&buffer);
    try encode(&writer, constants.varint_value_max);
    try expect_decodes(writer.written(), constants.varint_value_max);
    try testing.expectEqualSlices(u8, &(.{0xff} ** 8), writer.written());
}

test "a non-minimal encoding decodes and re-encodes at its own length" {
    var buffer: [8]u8 = @splat(0);
    var writer = Writer.init(&buffer);
    try encode_with_len(&writer, 37, 8);
    try testing.expectEqualSlices(u8, &.{ 0xc0, 0, 0, 0, 0, 0, 0, 0x25 }, writer.written());
    try expect_decodes(writer.written(), 37);
}

test "a truncated encoding consumes nothing, at every length" {
    const encodings = [_][]const u8{
        &.{},
        &.{0x40},
        &.{ 0x9d, 0x7f, 0x3e },
        &.{ 0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8 },
    };
    for (encodings) |bytes| {
        var reader = Reader.init(bytes);
        try testing.expectError(error.Truncated, decode(&reader));
        try testing.expectEqual(0, reader.offset);
    }
}

test "an encoding that does not fit writes nothing" {
    var buffer: [3]u8 = @splat(0xee);
    var writer = Writer.init(&buffer);
    try testing.expectError(error.NoSpaceLeft, encode(&writer, 494_878_333));
    try testing.expectEqual(0, writer.offset);
    try testing.expectEqualSlices(u8, &.{ 0xee, 0xee, 0xee }, &buffer);
}

/// Most octets a fuzz input carries. Test-only: a varint needs at most eight.
const fuzz_input_len_max = 16;

fn fuzz_decode(_: void, smith: *testing.Smith) anyerror!void {
    var input: [fuzz_input_len_max]u8 = @splat(0);
    const input_len = smith.slice(&input);
    var reader = Reader.init(input[0..input_len]);
    const decoded = decode(&reader) catch |err| {
        try testing.expectEqual(error.Truncated, err);
        try testing.expectEqual(0, reader.offset);
        return;
    };
    // Re-encoding at the decoded length reproduces the octets consumed, bit for bit.
    var output: [constants.varint_len_max]u8 = @splat(0);
    var writer = Writer.init(&output);
    try encode_with_len(&writer, decoded.value, decoded.encoded_len);
    try testing.expectEqualSlices(u8, reader.consumed(), writer.written());
}

test "fuzz: decode consumes an encoding exactly or nothing" {
    try testing.fuzz({}, fuzz_decode, .{ .corpus = &.{
        core.fuzz.input("\xc2\x19\x7c\x5e\xff\x14\xe8\x8c"),
        core.fuzz.input("\x9d\x7f\x3e\x7d"),
        core.fuzz.input("\x7b\xbd"),
        core.fuzz.input("\x25"),
        core.fuzz.input("\x40\x25"),
        core.fuzz.input("\xc0"),
    } });
}

test "sweep: every input of up to two octets decodes exactly or consumes nothing" {
    try core.fuzz.sweep(fuzz_decode, null);
}
