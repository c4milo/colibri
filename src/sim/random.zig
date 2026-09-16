//! `Random`, the one source of choices in the simulator (design §10). Every chunk boundary, every
//! delay and every generated value of a run comes from one `Random` seeded with the run's seed.
//!
//! The generator is SplitMix64, written out here rather than taken from `std.Random` for two
//! reasons. `tools/lint/determinism.zig` refuses `std.Random` under `src/`, so no protocol file can
//! reach a generator by accident. And a seed must replay the same run after a Zig upgrade, which
//! holds only while the sequence a seed produces is this file's and not the standard library's.
//!
//! This is a schedule, not a secret: nothing here is unpredictable, and nothing a protocol needs
//! to be unpredictable comes from it (invariant 5).
const std = @import("std");
const assert = std.debug.assert;

/// The increment SplitMix64 adds to its state on every draw.
const state_increment: u64 = 0x9e3779b97f4a7c15;

/// The two multipliers and three shifts of SplitMix64's output mix.
const mix_multiplier_first: u64 = 0xbf58476d1ce4e5b9;
const mix_multiplier_second: u64 = 0x94d049bb133111eb;
const mix_shift_first: u6 = 30;
const mix_shift_second: u6 = 27;
const mix_shift_third: u6 = 31;

pub const Random = struct {
    state: u64,
    /// How many values this generator has produced. Two runs of one seed that drew a different
    /// number of values made different choices, even when their traces agree.
    draws: u64,

    pub fn init(seed: u64) Random {
        const random: Random = .{ .state = seed, .draws = 0 };
        assert(random.draws == 0);
        return random;
    }

    /// The next 64-bit value.
    pub fn next(random: *Random) u64 {
        random.state +%= state_increment;
        random.draws += 1;
        var mixed = random.state;
        mixed = (mixed ^ (mixed >> mix_shift_first)) *% mix_multiplier_first;
        mixed = (mixed ^ (mixed >> mix_shift_second)) *% mix_multiplier_second;
        return mixed ^ (mixed >> mix_shift_third);
    }

    /// A value in `[0, bound)`, from one draw: the high 64 bits of the draw times `bound`. The
    /// small bias this leaves toward low values is the same for every host, which is the property
    /// a schedule needs.
    pub fn below(random: *Random, bound: u64) u64 {
        assert(bound > 0);
        const product = @as(u128, random.next()) * bound;
        const value: u64 = @intCast(product >> @bitSizeOf(u64));
        assert(value < bound);
        return value;
    }

    /// A value in `[min, max]`.
    pub fn between(random: *Random, min: u64, max: u64) u64 {
        assert(min <= max);
        if (max - min == std.math.maxInt(u64)) return random.next();
        const value = min + random.below(max - min + 1);
        assert(value >= min and value <= max);
        return value;
    }
};

const testing = std.testing;

test "seed 0 produces SplitMix64's published first three values" {
    var random = Random.init(0);
    try testing.expectEqual(0xe220a8397b1dcdaf, random.next());
    try testing.expectEqual(0x6e789e6aa1b965f4, random.next());
    try testing.expectEqual(0x06c45d188009454f, random.next());
    try testing.expectEqual(3, random.draws);
}

test "one seed replays and another diverges" {
    var first = Random.init(0xc0ffee);
    var second = Random.init(0xc0ffee);
    var other = Random.init(0xc0ffef);
    for (0..64) |_| {
        const value = first.next();
        try testing.expectEqual(value, second.next());
        try testing.expect(value != other.next());
    }
}

test "below stays under its bound and reaches both ends of a small range" {
    var random = Random.init(1);
    var seen: [4]bool = @splat(false);
    for (0..256) |_| {
        const value = random.below(seen.len);
        seen[value] = true;
    }
    for (seen) |reached| try testing.expect(reached);
    try testing.expectEqual(0, random.below(1));
}

test "between includes both ends, and the whole range takes one draw" {
    var random = Random.init(2);
    var seen_min = false;
    var seen_max = false;
    for (0..256) |_| {
        const value = random.between(5, 7);
        try testing.expect(value >= 5 and value <= 7);
        seen_min = seen_min or value == 5;
        seen_max = seen_max or value == 7;
    }
    try testing.expect(seen_min and seen_max);
    const draws = random.draws;
    _ = random.between(0, std.math.maxInt(u64));
    try testing.expectEqual(draws + 1, random.draws);
}
