//! The tests that hold `huffman_decode.zig`'s machine to `huffman.decode_by_bits`, the decoder it
//! replaced: for each input and each room, both return the same error, or both write the same
//! octets.
const std = @import("std");
const core = @import("core");
const huffman = @import("huffman.zig");
const huffman_decode = @import("huffman_decode.zig");

const Writer = core.Writer;
const testing = std.testing;

/// Room for what the longest input decodes to, and a room too small for most. Test-only.
const room_max: usize = 64;
const room_small: usize = 2;

/// Decodes `encoded` both ways into `room` octets, and requires the same result. Test-only.
fn expect_same(encoded: []const u8, room: usize) !void {
    var by_bits: [room_max]u8 = undefined;
    var by_steps: [room_max]u8 = undefined;
    var bits_writer = Writer.init(by_bits[0..room]);
    var steps_writer = Writer.init(by_steps[0..room]);
    const bits_result = huffman.decode_by_bits(encoded, &bits_writer);
    const steps_result = huffman_decode.decode(encoded, &steps_writer);
    if (bits_result) |_| {
        _ = try steps_result;
        try testing.expectEqualSlices(u8, bits_writer.written(), steps_writer.written());
    } else |failure| {
        try testing.expectError(failure, steps_result);
        // Neither moves its cursor on an error.
        try testing.expectEqual(0, steps_writer.written().len);
    }
}

test "decision 11: the machine decodes every input of one and two octets as the bit decoder does" {
    for (0..1 << @bitSizeOf(u8)) |first| {
        const one = [_]u8{@intCast(first)};
        try expect_same(&one, room_max);
        for (0..1 << @bitSizeOf(u8)) |second| {
            const two = [_]u8{ @intCast(first), @intCast(second) };
            try expect_same(&two, room_max);
            try expect_same(&two, room_small);
        }
    }
}

/// Inputs of up to `long_len_max` octets from a fixed sequence, and the encodings of strings, which
/// reach the end with valid padding. Test-only.
const long_inputs: usize = 4096;
const long_len_max: usize = 24;
const sequence_multiplier: u64 = 6364136223846793005;
const sequence_increment: u64 = 1442695040888963407;

test "decision 11: the machine decodes longer inputs, and encoded strings, as the bit decoder does" {
    var state: u64 = 0;
    var input: [long_len_max]u8 = undefined;
    var encoded: [huffman.encoded_len_max(long_len_max)]u8 = undefined;
    for (0..long_inputs) |index| {
        const len = index % long_len_max + 1;
        for (input[0..len]) |*octet| {
            state = state *% sequence_multiplier +% sequence_increment;
            octet.* = @truncate(state >> (@bitSizeOf(u64) - @bitSizeOf(u8)));
        }
        try expect_same(input[0..len], room_max);
        try expect_same(input[0..len], room_small);
        var writer = Writer.init(&encoded);
        try huffman.encode(input[0..len], &writer);
        try expect_same(writer.written(), room_max);
        try expect_same(writer.written(), room_small);
    }
}
