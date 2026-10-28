//! The fuzz property of the varint encoder (decision 29), and the sweep that runs it over every
//! input of up to two octets. The encoder writes each octet in place since 399469ac, so the
//! property checks it against an independent build of the octets, against the decoder, and
//! against a buffer too short for it. Everything in this file is test-only.
const std = @import("std");
const core = @import("core");
const constants = @import("constants.zig");
const varint = @import("varint.zig");

const Reader = core.Reader;
const Writer = core.Writer;
const Smith = std.testing.Smith;
const testing = std.testing;

/// An input: 8 octets of the value, then one octet that picks the length and one for the room.
const value_octets = @sizeOf(u64);
const fuzz_input_len = value_octets + @sizeOf(u8) + @sizeOf(u8);
/// What the buffer holds where the encoder must not write.
const untouched: u8 = 0x5a;

fn fuzz_encode(_: void, smith: *Smith) anyerror!void {
    var input: [fuzz_input_len]u8 = @splat(0);
    _ = smith.slice(&input);
    const value = std.mem.readInt(u64, input[0..value_octets], .little);
    try check(value, input[value_octets], input[value_octets + 1]);
}

/// Encodes `value`, cut to 62 bits, at the length `picked` names or the shortest that holds it,
/// into a buffer of the room `room` names.
fn check(value_input: u64, picked_input: u8, room_input: u8) !void {
    const value = value_input & constants.varint_value_max;
    const picked = constants.varint_lens[picked_input % constants.varint_lens.len];
    const len = @max(picked, varint.encoded_len_minimal(value));
    var buffer: [constants.varint_len_max + 1]u8 = @splat(untouched);
    const room = room_input % buffer.len;
    var writer = Writer.init(buffer[0..room]);
    varint.encode_with_len(&writer, value, len) catch |failure| {
        // All of the octets or none: a buffer too short holds nothing.
        try testing.expectEqual(error.NoSpaceLeft, failure);
        try testing.expect(room < len);
        try testing.expectEqual(0, writer.offset);
        try testing.expect(std.mem.allEqual(u8, &buffer, untouched));
        return;
    };
    try testing.expect(room >= len);
    try testing.expectEqualSlices(u8, expected(value, len)[0..len], writer.written());
    try testing.expect(std.mem.allEqual(u8, buffer[len..], untouched));
    var reader = Reader.init(writer.written());
    try testing.expectEqual(varint.Decoded{ .value = value, .encoded_len = len }, try varint.decode(&reader));
}

/// RFC 9000 §16, built another way: the value in network byte order over all eight octets, its
/// last `len` moved to the front, with the length's base-2 logarithm in the first octet's two most
/// significant bits.
fn expected(value: u64, len: u8) [constants.varint_len_max]u8 {
    var big: [constants.varint_len_max]u8 = undefined;
    std.mem.writeInt(u64, &big, value, .big);
    var octets: [constants.varint_len_max]u8 = @splat(untouched);
    @memcpy(octets[0..len], big[constants.varint_len_max - len ..]);
    octets[0] |= @as(u8, std.math.log2_int(u8, len)) << (@bitSizeOf(u8) - constants.varint_length_bits);
    return octets;
}

test "fuzz: the varint encoder writes RFC 9000 §16's octets in place, all of them or none" {
    try testing.fuzz({}, fuzz_encode, .{
        .corpus = &.{
            // The largest value in eight octets with room for all, and with room for seven.
            core.fuzz.input("\xff\xff\xff\xff\xff\xff\xff\x3f\x03\x08"),
            core.fuzz.input("\xff\xff\xff\xff\xff\xff\xff\x3f\x03\x07"),
            // 37 in one octet, and in a longer encoding than it needs.
            core.fuzz.input("\x25\x00\x00\x00\x00\x00\x00\x00\x00\x01"),
            core.fuzz.input("\x25\x00\x00\x00\x00\x00\x00\x00\x02\x05"),
        },
    });
    try core.fuzz.sweep(fuzz_encode, null);
}

test "the varint property holds at each edge of each length, with every room" {
    // The sweep reaches values of two octets alone, so this pass takes each power of two, one
    // less and one more, up to the largest value, at each length and each room.
    for (0..@bitSizeOf(u64) - constants.varint_length_bits + 1) |bit| {
        const power = @as(u64, 1) << @intCast(bit);
        for ([_]u64{ power -% 1, power, power +% 1 }) |value| {
            for (0..constants.varint_lens.len) |picked| {
                for (0..constants.varint_len_max + 1) |room| try check(value, @intCast(picked), @intCast(room));
            }
        }
    }
}
