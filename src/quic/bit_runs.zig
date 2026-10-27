//! Word-at-a-time scans of a `std.StaticBitSet` that marks which octets of a buffer arrived: the
//! CRYPTO window (`crypto_stream.zig`) and each block of a stream's unread octets
//! (`stream/stream_incoming.zig`).
//!
//! `std.StaticBitSet.isSet` takes the set by value. In a loop over a set of 4,096 bits it copied
//! 512 octets for each octet it tested, which was 19% of the server's CPU on the judge's h3-one
//! input (design §8 step 13h). These functions take the set by pointer and read 64 bits at a time.
const std = @import("std");
const assert = std.debug.assert;

/// The first index at or above `from` whose bit is unset, or `limit` when every bit of
/// `[from, limit)` is set.
pub fn first_unset(set: anytype, from: usize, limit: usize) usize {
    const Mask = MaskOf(@TypeOf(set));
    const mask_bits = @bitSizeOf(Mask);
    assert(from <= limit and limit <= set.masks.len * mask_bits);
    if (from == limit) return limit;
    var word = from / mask_bits;
    // Bits below `from` count as set, so that the scan starts at `from`.
    var holes = ~set.masks[word] & (~@as(Mask, 0) << @intCast(from % mask_bits));
    // Bounded by the words of the set.
    while (holes == 0) {
        word += 1;
        if (word * mask_bits >= limit) return limit;
        holes = ~set.masks[word];
    }
    return @min(word * mask_bits + @ctz(holes), limit);
}

/// One past the highest set bit at or above `from`, or `from` when none is set there.
pub fn end_of_set(set: anytype, from: usize) usize {
    const Mask = MaskOf(@TypeOf(set));
    const mask_bits = @bitSizeOf(Mask);
    assert(from <= set.masks.len * mask_bits);
    var word = set.masks.len;
    // Bounded by the words of the set, from the top down to the word that holds `from`.
    while (word > 0 and (word - 1) * mask_bits + mask_bits > from) {
        word -= 1;
        if (set.masks[word] != 0) {
            const end = word * mask_bits + mask_bits - @clz(set.masks[word]);
            return @max(end, from);
        }
    }
    return from;
}

/// Moves every bit down by `by`: bit `by + index` becomes bit `index`, and the top `by` bits are
/// unset.
pub fn shift_down(set: anytype, by: usize) void {
    const Mask = MaskOf(@TypeOf(set));
    const mask_bits = @bitSizeOf(Mask);
    const count = set.masks.len;
    assert(by <= count * mask_bits);
    const words = by / mask_bits;
    const bits = by % mask_bits;
    // Each word reads only words at or above its own index, so the shift runs in place.
    for (0..count) |index| {
        const low: Mask = if (index + words < count) set.masks[index + words] >> @intCast(bits) else 0;
        const high: Mask = if (bits != 0 and index + words + 1 < count)
            set.masks[index + words + 1] << @intCast(mask_bits - bits)
        else
            0;
        set.masks[index] = low | high;
    }
}

fn MaskOf(comptime Pointer: type) type {
    const Set = @typeInfo(Pointer).pointer.child;
    // An `ArrayBitSet` holds its bits in `masks`; a set of 64 bits or fewer is one integer.
    comptime assert(@hasField(Set, "masks"));
    // Every bit of each word is a bit of the set, so no scan meets padding.
    comptime assert(Set.bit_length % @bitSizeOf(Set.MaskInt) == 0);
    return Set.MaskInt;
}

const testing = std.testing;

/// A set of three words, so that a scan or a shift crosses a word's edge. Test-only.
const test_bits = 192;
const TestSet = std.StaticBitSet(test_bits);

/// The first and the one-past-last index of a run of set bits. Test-only.
const Span = struct { usize, usize };

fn set_of(spans: []const Span) TestSet {
    var set: TestSet = .initEmpty();
    for (spans) |span| set.setRangeValue(.{ .start = span[0], .end = span[1] }, true);
    return set;
}

test "first_unset finds the first gap, across a word's edge, and stops at the limit" {
    var set = set_of(&.{.{ 3, 130 }});
    try testing.expectEqual(0, first_unset(&set, 0, test_bits));
    try testing.expectEqual(130, first_unset(&set, 3, test_bits));
    try testing.expectEqual(130, first_unset(&set, 70, test_bits));
    try testing.expectEqual(100, first_unset(&set, 3, 100));
    try testing.expectEqual(140, first_unset(&set, 140, test_bits));
    set = .initFull();
    try testing.expectEqual(test_bits, first_unset(&set, 5, test_bits));
    try testing.expectEqual(test_bits, first_unset(&set, test_bits, test_bits));
}

test "end_of_set finds one past the highest bit, and no bit below from counts" {
    var set = set_of(&.{ .{ 2, 5 }, .{ 64, 65 } });
    try testing.expectEqual(65, end_of_set(&set, 0));
    try testing.expectEqual(65, end_of_set(&set, 64));
    try testing.expectEqual(70, end_of_set(&set, 70));
    set = .initEmpty();
    try testing.expectEqual(10, end_of_set(&set, 10));
    set = set_of(&.{.{ 2, 5 }});
    try testing.expectEqual(65, end_of_set(&set, 65));
}

test "shift_down moves each bit down by any distance, and empties the top" {
    var set = set_of(&.{ .{ 3, 5 }, .{ 70, 72 }, .{ 191, 192 } });
    shift_down(&set, 3);
    try testing.expect(set.eql(set_of(&.{ .{ 0, 2 }, .{ 67, 69 }, .{ 188, 189 } })));
    shift_down(&set, 64);
    try testing.expect(set.eql(set_of(&.{ .{ 3, 5 }, .{ 124, 125 } })));
    shift_down(&set, 0);
    try testing.expect(set.eql(set_of(&.{ .{ 3, 5 }, .{ 124, 125 } })));
    shift_down(&set, test_bits);
    try testing.expect(set.eql(TestSet.initEmpty()));
}
