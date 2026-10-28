//! The fuzz property of `bit_runs.zig` (decision 29), and the sweep that runs it over every input
//! of up to two octets. Each scan is checked against a loop over single bits, which is what the
//! callers did before the scans read 64 bits at a time. Everything in this file is test-only.
const std = @import("std");
const core = @import("core");
const bit_runs = @import("bit_runs.zig");

const Smith = std.testing.Smith;
const testing = std.testing;

/// A set of three words, so that a scan or a shift crosses a word's edge.
const set_bits = 192;
const Set = std.StaticBitSet(set_bits);
const set_octets = set_bits / @bitSizeOf(u8);
/// An input: one octet each for `from`, `limit` and the shift, then the set's octets.
const header_octets = 3;
const at_from = 0;
const at_limit = 1;
const at_shift = 2;
const fuzz_input_len = header_octets + set_octets;

fn fuzz_scans(_: void, smith: *Smith) anyerror!void {
    var input: [fuzz_input_len]u8 = @splat(0);
    _ = smith.slice(&input);
    var set: Set = .initEmpty();
    for (input[header_octets..], 0..) |octet, index| {
        for (0..@bitSizeOf(u8)) |bit| set.setValue(index * @bitSizeOf(u8) + bit, octet >> @intCast(bit) & 1 == 1);
    }
    const ends = [_]usize{ input[at_from] % (set_bits + 1), input[at_limit] % (set_bits + 1) };
    const from = @min(ends[0], ends[1]);
    const limit = @max(ends[0], ends[1]);
    try testing.expectEqual(first_unset_by_bit(&set, from, limit), bit_runs.first_unset(&set, from, limit));
    try testing.expectEqual(end_of_set_by_bit(&set, from), bit_runs.end_of_set(&set, from));
    const by = input[at_shift] % (set_bits + 1);
    var shifted = set;
    bit_runs.shift_down(&shifted, by);
    for (0..set_bits) |index| {
        const moved = index + by < set_bits and set.isSet(index + by);
        try testing.expectEqual(moved, shifted.isSet(index));
    }
}

fn first_unset_by_bit(set: *const Set, from: usize, limit: usize) usize {
    for (from..limit) |index| {
        if (!set.isSet(index)) return index;
    }
    return limit;
}

fn end_of_set_by_bit(set: *const Set, from: usize) usize {
    var end = from;
    for (from..set_bits) |index| {
        if (set.isSet(index)) end = index + 1;
    }
    return end;
}

test "fuzz: each word-at-a-time scan gives what a scan of single bits gives" {
    try testing.fuzz({}, fuzz_scans, .{
        .corpus = &.{
            // A run across the first word's edge, scanned from inside it, and shifted by 3.
            core.fuzz.input("\x05\xc0\x03" ++ "\x00" ** 7 ++ "\xe0\xff\x01" ++ "\x00" ** 13),
            // Every bit set, scanned to the end, and shifted by a whole word.
            core.fuzz.input("\x00\xc0\x40" ++ "\xff" ** 24),
            // The last bit alone, which `end_of_set` must find from below it.
            core.fuzz.input("\x10\x20\xbf" ++ "\x00" ** 23 ++ "\x80"),
        },
    });
    try core.fuzz.sweep(fuzz_scans, null);
}
