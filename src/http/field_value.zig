//! The scan `field.validate_value` makes of a value of `word_len` octets or more, split off
//! field.zig for length: it reads eight octets a step and says whether any of them is a control
//! octet (RFC 5234 Appendix B.1's CTL, 0x00 to 0x1f and 0x7f, which RFC 9110 §2.1 includes). HTAB
//! is one, though RFC 9110 §5.5 admits it, so a value that holds one is read again an octet at a
//! time, which also names the reason.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");

/// The octets one step reads.
pub const word_len = @sizeOf(u64);

/// One in the low bit of each octet of a word.
const lane_ones: u64 = std.math.maxInt(u64) / std.math.maxInt(u8);
/// The high bit of an octet, and the seven bits below it.
const octet_high_bit: u8 = 1 << (@bitSizeOf(u8) - 1);
const octet_low_bits: u8 = octet_high_bit - 1;
/// DEL, the one control octet above SP (RFC 5234 Appendix B.1).
const delete: u8 = 0x7f;
/// Added to the low seven bits of an octet moved up by one, so that every octet from SP to 0x7e
/// carries into the high bit and no control octet does.
const past_space: u8 = octet_high_bit - (' ' + 1);

comptime {
    // Moving 0x7f up by one wraps to 0 in seven bits, which is how DEL counts as a control octet.
    assert(delete == octet_low_bits);
}

/// Whether `value`, of `word_len` octets or more, holds a control octet, HTAB included.
pub fn has_control(value: []const u8) bool {
    assert(value.len >= word_len);
    assert(value.len <= core.constants.field_value_len_max);
    var lanes: u64 = 0;
    var rest = value;
    for (0..value.len / word_len) |_| {
        lanes |= control_lanes(std.mem.readInt(u64, rest[0..word_len], .little));
        rest = rest[word_len..];
    }
    // The last word ends at the value's last octet, over octets a step has read, so that the
    // octets past the last whole step are read too.
    lanes |= control_lanes(std.mem.readInt(u64, value[value.len - word_len ..][0..word_len], .little));
    return lanes != 0;
}

/// The high bit of each octet of `word` that is a control octet, and no other bit. Each octet is
/// worked on alone: no sum carries out of an octet.
fn control_lanes(word: u64) u64 {
    const low = word & (lane_ones * octet_low_bits);
    // Each octet's low seven bits moved up by one, DEL to 0, and then up past SP: the high bit is
    // set for SP to 0x7e and clear for every control octet.
    const moved = ((low + lane_ones) & (lane_ones * octet_low_bits)) + lane_ones * past_space;
    // An octet whose own high bit is set is obs-text (RFC 9110 §5.5), never a control octet.
    return ~(moved | word) & (lane_ones * octet_high_bit);
}

const testing = std.testing;

/// Whether `octet` is a control octet, HTAB included, by its definition (RFC 5234 Appendix B.1).
fn is_control_octet(octet: u8) bool {
    return octet < ' ' or octet == delete;
}

/// The octet values, 0 to 255.
const octet_values = std.math.maxInt(u8) + 1;
/// What the rest of a word holds: a field-vchar, the highest octet, SP, and NUL.
const backgrounds = [_]u8{ 'a', std.math.maxInt(u8), ' ', 0 };

test "control_lanes marks each control octet in every lane, and no other octet" {
    for (backgrounds) |background| {
        for (0..word_len) |lane| {
            for (0..octet_values) |octet| {
                var octets: [word_len]u8 = @splat(background);
                octets[lane] = @intCast(octet);
                var expected: u64 = 0;
                for (octets, 0..) |each, index| {
                    if (is_control_octet(each)) expected |= @as(u64, octet_high_bit) << @intCast(index * @bitSizeOf(u8));
                }
                try testing.expectEqual(expected, control_lanes(std.mem.readInt(u64, &octets, .little)));
            }
        }
    }
}

/// The longest value the tests vary one octet of.
const varied_len_max = 40;

test "has_control finds a control octet at every position of every length, and none where none is" {
    var value: [varied_len_max]u8 = @splat('a');
    for (word_len..value.len + 1) |len| {
        try testing.expect(!has_control(value[0..len]));
        for (0..len) |position| {
            for (0..octet_values) |octet| {
                value[position] = @intCast(octet);
                try testing.expectEqual(is_control_octet(@intCast(octet)), has_control(value[0..len]));
            }
            value[position] = 'a';
        }
    }
}
