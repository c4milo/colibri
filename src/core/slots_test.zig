//! The tests of `slots.zig`, split off it for length. They open, find and close entries in a pool
//! of four slots, in h2's two identifier classes and in QUIC's four, and they hold `get` to a scan
//! of the slots from the first, whichever slot the pool read last.
const std = @import("std");
const assert = std.debug.assert;
const slots = @import("slots.zig");

const Pool = slots.Pool;
const testing = std.testing;

/// An entry with one field beside the identifier, to show a fresh entry is written whole.
/// Test-only.
const TestEntry = struct {
    id: u64,
    mark: u8 = 0,
};

/// Slots in the test pool. Test-only.
const test_capacity: u32 = 4;

/// Identifier classes in the test pool: even and odd, as h2's stream identifiers are. Test-only.
const test_class_count: u32 = 2;

/// The class of an identifier in the tests: its low bit, as h2 reads parity. Test-only.
fn test_class_of(id: u64) u32 {
    return @intCast(id & 1);
}

const TestPool = Pool(TestEntry, test_capacity, test_class_count, test_class_of);

/// Identifier classes in a pool shaped like QUIC's: the four stream types of RFC 9000 §2.1.
/// Test-only.
const test_quic_class_count: u32 = 4;

/// The class of an identifier in a pool shaped like QUIC's: its two low bits, which RFC 9000 §2.1
/// reads as initiator and directionality. Test-only.
fn test_quic_class_of(id: u64) u32 {
    const low_bits: u2 = @truncate(id);
    return low_bits;
}

const TestQuicPool = Pool(TestEntry, test_capacity, test_quic_class_count, test_quic_class_of);

/// The identifiers `iterator` yields, in order, with 0 in every position past the last.
/// Test-only.
fn visited_ids(pool: *TestPool) [test_capacity]u64 {
    var ids: [test_capacity]u64 = @splat(0);
    var visited: u32 = 0;
    var iterator = pool.iterator();
    while (iterator.next()) |entry| : (visited += 1) {
        assert(visited < test_capacity);
        ids[visited] = entry.id;
    }
    return ids;
}

// The assertions on programmer error — opening an identifier at or below its watermark, closing one
// with no live entry, moving a watermark down, a `class_of` result at or above `class_count` — are
// not tested: a panic is not a test outcome. Invariant 24 keeps peer input from being passed to
// them, and the protocol modules' tests prove that.

/// The slot a scan from the first slot finds a live entry holding `id` in, or null: what `get`
/// found before the pool read the slot it found last first. Test-only.
fn scanned_slot(pool: *const TestPool, id: u64) ?usize {
    for (pool.entries, pool.live, 0..) |entry, is_live, slot| {
        if (is_live and entry.id == id) return slot;
    }
    return null;
}

/// Requires `get` to find, for each identifier the tests use, the entry a scan finds, and names
/// the first that differs. Each `get` moves the slot the pool reads first, so the walk also asks
/// with that slot on every entry in turn. Test-only.
fn expect_gets_as_scanned(pool: *TestPool) !void {
    for (0..compared_ids) |id| {
        const scanned: ?*TestEntry = if (scanned_slot(pool, id)) |slot| &pool.entries[slot] else null;
        const found = pool.get(id);
        if (found == scanned) continue;
        std.debug.print("first difference: identifier {d}: get {any}, scan {any}, last slot {d}\n", .{ id, found, scanned, pool.last_slot });
        return error.TestUnexpectedResult;
    }
}

/// The identifiers the comparison asks for: every one the test opens, and some never opened.
/// Test-only.
const compared_ids: u64 = 24;

test "get finds what a scan from the first slot finds, whichever slot it read last, as entries open and close" {
    var pool: TestPool = undefined;
    pool.init();
    try expect_gets_as_scanned(&pool);
    // Fill the pool, then close and open so that identifiers move between slots.
    for ([_]u64{ 1, 2, 3, 4 }) |id| {
        _ = try pool.open(id);
        try expect_gets_as_scanned(&pool);
    }
    // The slot read last now holds 4. Closing it leaves that slot dead, and nothing finds 4.
    try testing.expectEqual(4, pool.get(4).?.id);
    pool.close(4);
    try testing.expectEqual(null, pool.get(4));
    try expect_gets_as_scanned(&pool);
    // 6 takes the dead slot, 2 closes, and 8 takes the slot 2 held.
    _ = try pool.open(6);
    try expect_gets_as_scanned(&pool);
    pool.close(2);
    try expect_gets_as_scanned(&pool);
    _ = try pool.open(8);
    try expect_gets_as_scanned(&pool);
    for ([_]u64{ 1, 3, 6, 8 }) |id| {
        pool.close(id);
        try expect_gets_as_scanned(&pool);
    }
    try testing.expectEqual(0, pool.len());
}

test "the slot read first is the one get last found or open last wrote" {
    var pool: TestPool = undefined;
    pool.init();
    _ = try pool.open(1);
    _ = try pool.open(3);
    try testing.expectEqual(1, pool.last_slot);
    _ = pool.get(1);
    try testing.expectEqual(0, pool.last_slot);
    // A get that finds nothing leaves it.
    try testing.expectEqual(null, pool.get(5));
    try testing.expectEqual(0, pool.last_slot);
}

test "open, get and close round-trip one entry" {
    var pool: TestPool = undefined;
    pool.init();
    try testing.expectEqual(0, pool.len());
    try testing.expectEqual(null, pool.get(1));
    const entry = try pool.open(1);
    try testing.expectEqual(1, entry.id);
    try testing.expectEqual(0, entry.mark);
    entry.mark = 7;
    try testing.expectEqual(1, pool.len());
    try testing.expectEqual(entry, pool.get(1).?);
    try testing.expectEqual(7, pool.get(1).?.mark);
    pool.close(1);
    try testing.expectEqual(0, pool.len());
    try testing.expectEqual(null, pool.get(1));
}

test "get finds each live entry by its identifier and nothing else" {
    var pool: TestPool = undefined;
    pool.init();
    for ([_]u64{ 1, 2, 3 }) |id| _ = try pool.open(id);
    try testing.expectEqual(2, pool.get(2).?.id);
    try testing.expectEqual(3, pool.get(3).?.id);
    try testing.expect(pool.get(2).? != pool.get(3).?);
    try testing.expectEqual(null, pool.get(4));
    try testing.expectEqual(null, pool.get(0));
    pool.close(2);
    try testing.expectEqual(null, pool.get(2));
    try testing.expectEqual(3, pool.get(3).?.id);
}

test "the pool refuses a fifth entry, changes nothing, and takes one again after a close" {
    var pool: TestPool = undefined;
    pool.init();
    for ([_]u64{ 1, 3, 5, 7 }) |id| _ = try pool.open(id);
    try testing.expectEqual(test_capacity, pool.len());
    try testing.expectError(error.Full, pool.open(9));
    try testing.expectEqual(test_capacity, pool.len());
    try testing.expectEqual(null, pool.get(9));
    try testing.expectEqual(7, pool.watermark[1]);
    try testing.expect(pool.is_above_watermark(9));
    pool.close(3);
    try testing.expectEqual(test_capacity - 1, pool.len());
    const entry = try pool.open(9);
    try testing.expectEqual(9, entry.id);
    try testing.expectEqual(test_capacity, pool.len());
    try testing.expectError(error.Full, pool.open(11));
}

test "a watermark advances for its class alone" {
    var pool: TestPool = undefined;
    pool.init();
    try testing.expectEqualSlices(?u64, &.{ null, null }, &pool.watermark);
    _ = try pool.open(1);
    try testing.expectEqualSlices(?u64, &.{ null, 1 }, &pool.watermark);
    _ = try pool.open(2);
    try testing.expectEqualSlices(?u64, &.{ 2, 1 }, &pool.watermark);
    _ = try pool.open(5);
    try testing.expectEqualSlices(?u64, &.{ 2, 5 }, &pool.watermark);
    _ = try pool.open(4);
    try testing.expectEqualSlices(?u64, &.{ 4, 5 }, &pool.watermark);
}

test "every identifier of a class with no watermark is above it, 0 included" {
    var pool: TestPool = undefined;
    pool.init();
    try testing.expect(pool.is_above_watermark(0));
    try testing.expect(pool.is_above_watermark(1));
    try testing.expect(pool.is_above_watermark(2));
    _ = try pool.open(5);
    try testing.expect(pool.is_above_watermark(0));
    try testing.expect(pool.is_above_watermark(2));
    pool.advance_watermark(0, 0);
    try testing.expect(!pool.is_above_watermark(0));
    try testing.expect(pool.is_above_watermark(2));
}

test "is_above_watermark is false at the watermark and true just above it" {
    var pool: TestPool = undefined;
    pool.init();
    _ = try pool.open(5);
    try testing.expect(!pool.is_above_watermark(5));
    try testing.expect(!pool.is_above_watermark(3));
    try testing.expect(!pool.is_above_watermark(1));
    try testing.expect(pool.is_above_watermark(7));
    try testing.expect(pool.is_above_watermark(9));
}

test "the iterator visits exactly the live entries in slot order" {
    var pool: TestPool = undefined;
    pool.init();
    var empty = pool.iterator();
    try testing.expectEqual(null, empty.next());
    for ([_]u64{ 1, 2, 3, 4 }) |id| _ = try pool.open(id);
    try testing.expectEqualSlices(u64, &.{ 1, 2, 3, 4 }, &visited_ids(&pool));
    pool.close(2);
    try testing.expectEqualSlices(u64, &.{ 1, 3, 4, 0 }, &visited_ids(&pool));
    _ = try pool.open(6);
    try testing.expectEqualSlices(u64, &.{ 1, 6, 3, 4 }, &visited_ids(&pool));
    pool.close(1);
    pool.close(4);
    try testing.expectEqualSlices(u64, &.{ 6, 3, 0, 0 }, &visited_ids(&pool));
    pool.close(6);
    pool.close(3);
    try testing.expectEqualSlices(u64, &.{ 0, 0, 0, 0 }, &visited_ids(&pool));
}

test "an iterator stops for good once it has passed the last slot" {
    var pool: TestPool = undefined;
    pool.init();
    _ = try pool.open(2);
    var iterator = pool.iterator();
    try testing.expectEqual(2, iterator.next().?.id);
    try testing.expectEqual(null, iterator.next());
    try testing.expectEqual(null, iterator.next());
    try testing.expectEqual(test_capacity, iterator.slot);
}

test "a closed identifier's slot takes a higher identifier of the same class, written whole" {
    var pool: TestPool = undefined;
    pool.init();
    const first = try pool.open(1);
    first.mark = 9;
    pool.close(1);
    const second = try pool.open(3);
    try testing.expectEqual(first, second);
    try testing.expectEqual(3, second.id);
    try testing.expectEqual(0, second.mark);
    try testing.expectEqual(null, pool.get(1));
    try testing.expect(!pool.is_above_watermark(1));
    try testing.expectEqual(3, pool.watermark[1]);
    try testing.expectEqual(1, pool.len());
}

test "advance_watermark moves one class's watermark without opening an entry" {
    var pool: TestPool = undefined;
    pool.init();
    pool.advance_watermark(1, 9);
    try testing.expectEqualSlices(?u64, &.{ null, 9 }, &pool.watermark);
    try testing.expectEqual(0, pool.len());
    try testing.expectEqual(null, pool.get(9));
    try testing.expect(!pool.is_above_watermark(9));
    try testing.expect(!pool.is_above_watermark(7));
    try testing.expect(pool.is_above_watermark(11));
    try testing.expect(pool.is_above_watermark(2));
    _ = try pool.open(11);
    pool.advance_watermark(1, 11);
    try testing.expectEqualSlices(?u64, &.{ null, 11 }, &pool.watermark);
    pool.advance_watermark(0, 4);
    try testing.expectEqualSlices(?u64, &.{ 4, 11 }, &pool.watermark);
    try testing.expectEqual(1, pool.len());
}

test "init empties a pool that held entries and clears its watermarks" {
    var pool: TestPool = undefined;
    pool.init();
    _ = try pool.open(1);
    _ = try pool.open(2);
    pool.advance_watermark(1, 5);
    pool.init();
    try testing.expectEqual(0, pool.len());
    try testing.expectEqualSlices(?u64, &.{ null, null }, &pool.watermark);
    // The slot read first is the first one again, not the one the entries before left.
    try testing.expectEqual(0, pool.last_slot);
    try testing.expectEqual(null, pool.get(1));
    try testing.expect(pool.is_above_watermark(1));
    try testing.expectEqual(1, (try pool.open(1)).id);
}

test "QUIC stream 0 opens on a fresh pool, and each class's first identifier is its own" {
    var pool: TestQuicPool = undefined;
    pool.init();
    try testing.expect(pool.is_above_watermark(0));
    try testing.expectEqual(0, (try pool.open(0)).id);
    try testing.expectEqualSlices(?u64, &.{ 0, null, null, null }, &pool.watermark);
    try testing.expect(!pool.is_above_watermark(0));
    try testing.expect(pool.is_above_watermark(4));
    try testing.expectEqual(0, pool.get(0).?.id);
    for ([_]u64{ 1, 2, 3 }) |id| _ = try pool.open(id);
    try testing.expectEqualSlices(?u64, &.{ 0, 1, 2, 3 }, &pool.watermark);
    try testing.expectEqual(test_capacity, pool.len());
    pool.close(0);
    try testing.expect(!pool.is_above_watermark(0));
    try testing.expectEqual(null, pool.get(0));
}

test "the pool holds its storage inline, with no pointer" {
    inline for (@typeInfo(TestPool).@"struct".fields) |field| {
        try testing.expect(@typeInfo(field.type) != .pointer);
    }
    var pool: TestPool = undefined;
    pool.init();
    try testing.expectEqual(test_capacity, pool.entries.len);
    try testing.expectEqual(test_capacity, pool.live.len);
    try testing.expectEqual(test_class_count, pool.watermark.len);
}

test "the watermark of a class is the highest identifier it ever opened" {
    const Entry = struct { id: u64 };
    const two_classes = struct {
        fn class_of(id: u64) u32 {
            return @intCast(id & 1);
        }
    };
    var pool: Pool(Entry, 4, 2, two_classes.class_of) = undefined;
    pool.init();
    try std.testing.expectEqual(null, pool.watermark_of(0));
    try std.testing.expectEqual(null, pool.watermark_of(1));
    _ = try pool.open(2);
    try std.testing.expectEqual(2, pool.watermark_of(0).?);
    // The other class is untouched, and closing does not lower a watermark.
    try std.testing.expectEqual(null, pool.watermark_of(1));
    pool.close(2);
    try std.testing.expectEqual(2, pool.watermark_of(0).?);
}
