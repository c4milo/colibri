//! How the input checks draw the values colibri's writers are given: often at a bound or a few
//! inside it, where an edit that moves one octet takes the value past (`input_edit.zig`).
//! `quic_input_check.zig` and `h2_input_check.zig` share it.
const std = @import("std");
const assert = std.debug.assert;
const Random = @import("random.zig").Random;

pub const Draw = struct {
    /// One choice in this many takes the rarer branch.
    one_in: u64,
    /// How far inside a bound a value drawn near it lies, at most.
    near_bound: u64,
    /// The bit length of the widest value drawn.
    bits_max: u6,

    /// True once in `one_in` draws.
    pub fn chosen(draw: Draw, random: *Random) bool {
        return random.below(draw.one_in) == 0;
    }

    /// A value of up to `bits_max` bits, drawn by bit length first so small values come up as
    /// often as large ones.
    pub fn by_bits(draw: Draw, random: *Random) u64 {
        const bits = random.between(0, draw.bits_max);
        return random.below(@as(u64, 1) << @intCast(bits));
    }

    /// A value in `[min, max]`. Once in `one_in` it is at a bound or a few inside it; otherwise it
    /// is drawn by bit length and held to the bounds.
    pub fn bounded(draw: Draw, random: *Random, min: u64, max: u64) u64 {
        assert(min <= max);
        if (!draw.chosen(random)) return @max(min, @min(max, draw.by_bits(random)));
        const inside = @min(max - min, random.below(draw.near_bound));
        return if (draw.chosen(random)) min + inside else max - inside;
    }
};

/// A slice of `material` of `min` to `max` octets.
pub fn octets(random: *Random, material: []const u8, min: u64, max: u64) []const u8 {
    assert(min <= max and max <= material.len);
    const len = random.between(min, max);
    const start = random.below(material.len - len + 1);
    return material[start..][0..len];
}

const testing = std.testing;

/// The draw the test uses, and how many values it draws. Test-only.
const test_one_in = 2;
const test_near_bound = 4;
const test_bits_max = 20;
const test_draw: Draw = .{ .one_in = test_one_in, .near_bound = test_near_bound, .bits_max = test_bits_max };
const test_draws = 1024;

test "a bounded value stays inside its bounds, and lands on each of them" {
    var random = Random.init(7);
    var at_min = false;
    var at_max = false;
    for (0..test_draws) |_| {
        const value = test_draw.bounded(&random, 3, 700);
        try testing.expect(value >= 3 and value <= 700);
        at_min = at_min or value == 3;
        at_max = at_max or value == 700;
    }
    try testing.expect(at_min and at_max);
}
