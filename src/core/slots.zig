//! The bounded slot pool with a per-class watermark of decision 14 and invariant 13.
//!
//! h2 and QUIC both keep a table of streams whose identifiers are never reused, and in both one
//! frame can implicitly close or open every lower identifier of its class (RFC 9113 §5.1.1,
//! RFC 9000 §3.2), so a map keyed by identifier can grow by the whole identifier space from one
//! frame. The pool stores what is live and nothing else: a fixed array of `capacity` entries, a
//! live flag per slot, and one watermark per identifier class, which is the highest identifier
//! ever opened in that class, or none. An identifier at or below its class's watermark with no
//! live entry is closed, and nothing records it. An identifier above the watermark, or in a class
//! with none, is new.
//!
//! The pool owns no memory (decision 35): the caller places it, and its storage is inside it.
//! `get` scans the live entries in slot order, because `capacity` is small and
//! named, and a scan is deterministic (non-negotiable 5). `iterator` visits the live entries in
//! the same order, which the settings sweep of invariant 15 requires. The three scans are
//! in file-scope functions over the flag and entry slices, so each is scored on its own.
//!
//! Nothing here is a protocol rule. Which class an identifier is in, which identifiers a peer
//! may open, and when a stream closes are h2's and QUIC's (decision 14). The protocol module
//! refuses a peer's identifier at or below the watermark and returns its own error before the
//! identifier is passed to `open`, so every assertion here is on colibri's own bookkeeping
//! (invariant 24).
const std = @import("std");
const assert = std.debug.assert;

pub const Error = error{
    /// Every slot holds a live entry. The pool is unchanged.
    Full,
};

/// A pool of at most `capacity` live entries of the caller's `Entry`, whose identifiers fall into
/// `class_count` classes, with `class_of(id)` naming the class of an identifier. `Entry` must
/// have a field `id: u64`, and every other field must have a default value: `open` writes a fresh
/// entry whole, so no field of a live entry is ever unwritten (invariant 5).
///
/// A watermark is optional because 0 is an identifier: h2 stream identifiers start at 1
/// (RFC 9113 §5.1.1), but QUIC's start at 0 (RFC 9000 §2.1), and the client-initiated
/// bidirectional QUIC stream 0 must open on a fresh pool. `null` alone means no identifier in
/// that class was ever opened.
pub fn Pool(
    comptime Entry: type,
    comptime capacity: u32,
    comptime class_count: u32,
    comptime class_of: fn (u64) u32,
) type {
    comptime assert(capacity > 0);
    comptime assert(class_count > 0);
    comptime assert(@hasField(Entry, "id"));
    comptime assert(@FieldType(Entry, "id") == u64);
    return struct {
        const Self = @This();

        /// The live entries in slot order. Valid until the next `open` or `close`.
        pub const Iterator = struct {
            pool: *Self,
            /// The next slot to look at. Never exceeds `capacity`.
            slot: u32 = 0,

            /// The next live entry in slot order, or null once every slot has been passed.
            pub fn next(self: *Iterator) ?*Entry {
                assert(self.slot <= capacity);
                const slot = first_slot_with_flag(&self.pool.live, self.slot, true) orelse {
                    self.slot = capacity;
                    return null;
                };
                self.slot = slot + 1;
                assert(self.pool.live[slot]);
                return &self.pool.entries[slot];
            }
        };

        /// Slot storage. `open` writes `entries[slot]` before it sets `live[slot]`, and nothing
        /// reads a slot whose flag is clear, so a slot never opened is never read.
        entries: [capacity]Entry,
        live: [capacity]bool,
        /// Live entries: the number of set flags in `live`. Never exceeds `capacity`.
        count: u32,
        /// `watermark[class]` is the highest identifier ever opened in that class, or null when
        /// none was. It never decreases (invariant 13).
        watermark: [class_count]?u64,

        /// Empties the pool and clears every watermark. `entries` is not written: see its
        /// comment.
        pub fn init(pool: *Self) void {
            pool.live = @splat(false);
            pool.count = 0;
            pool.watermark = @splat(null);
            assert(pool.len() == 0);
            assert(pool.free_slot() == 0);
        }

        /// Live entries.
        pub fn len(pool: *const Self) u32 {
            assert(pool.count <= capacity);
            return pool.count;
        }

        /// The live entry with `id`, or null when none is live. The pointer is valid until the
        /// entry is closed.
        pub fn get(pool: *Self, id: u64) ?*Entry {
            const slot = pool.slot_of(id) orelse return null;
            assert(pool.live[slot]);
            assert(pool.entries[slot].id == id);
            return &pool.entries[slot];
        }

        /// Whether `id` is above its class's watermark: neither it nor any identifier above it in
        /// its class was ever opened. An identifier at or below the watermark is open or closed,
        /// never new. Every identifier of a class with no watermark is new, 0 included.
        pub fn is_above_watermark(pool: *const Self, id: u64) bool {
            return is_above(id, pool.watermark[class_index(id)]);
        }

        /// Opens `id`: writes a fresh entry holding it into the lowest free slot, marks the slot
        /// live, and moves its class's watermark up to `id`. A full pool returns `error.Full`
        /// and changes nothing, so the protocol module decides whether the refused identifier
        /// still moves the watermark, through `advance_watermark`.
        pub fn open(pool: *Self, id: u64) Error!*Entry {
            const class = class_index(id);
            const previous = pool.watermark[class];
            // The protocol module refused a peer identifier at or below the watermark before
            // this call (invariant 24); calling `open` with one is programmer error.
            assert(is_above(id, previous));
            assert(pool.count <= capacity);
            // A full pool is a limit reached, which CLAUDE.md calls operational: `capacity` is a
            // comptime parameter, not a rule of any RFC, and the protocol module maps
            // `error.Full` to its own error.
            if (pool.count == capacity) return error.Full;
            const slot = pool.free_slot();
            pool.entries[slot] = .{ .id = id };
            pool.live[slot] = true;
            pool.count += 1;
            pool.watermark[class] = id;
            // Invariant 13's runtime assertion: a watermark never decreases.
            assert(is_above(pool.watermark[class].?, previous));
            assert(pool.count <= capacity);
            assert(!pool.is_above_watermark(id));
            return &pool.entries[slot];
        }

        /// Closes `id`: frees its slot. The identifier stays at or below its class's watermark,
        /// so from now on it is closed without a record.
        pub fn close(pool: *Self, id: u64) void {
            const slot = pool.slot_of(id);
            // Closing an identifier with no live entry is programmer error: the protocol module
            // holds the entry it closes.
            assert(slot != null);
            assert(pool.count > 0);
            pool.live[slot.?] = false;
            pool.count -= 1;
            assert(!pool.is_above_watermark(id));
            assert(pool.slot_of(id) == null);
        }

        /// The live entries in slot order, for a sweep over every one of them (invariant 15).
        pub fn iterator(pool: *Self) Iterator {
            assert(pool.count <= capacity);
            return .{ .pool = pool };
        }

        /// Moves `class`'s watermark up to `id` without opening an entry, for a protocol that
        /// closes every identifier up to `id` without opening it (RFC 9113 §5.1.1's implicit
        /// close). `id` must be in `class`, and the watermark never decreases (invariant 13): an
        /// `id` below it is programmer error, and an `id` equal to it changes nothing.
        pub fn advance_watermark(pool: *Self, class: u32, id: u64) void {
            assert(class < class_count);
            assert(class_index(id) == class);
            const previous = pool.watermark[class];
            // Invariant 13's runtime assertion: a watermark never decreases.
            assert(previous == null or id >= previous.?);
            pool.watermark[class] = id;
            assert(!pool.is_above_watermark(id));
        }

        /// The highest identifier ever opened in `class`, or null when it has opened none. A
        /// caller that must create every identifier below one, as RFC 9000 §3.2 requires of QUIC
        /// streams, reads this to know where to start.
        pub fn watermark_of(pool: *const Self, class: u32) ?u64 {
            assert(class < class_count);
            return pool.watermark[class];
        }

        /// The slot holding the live entry with `id`, or null when none is live.
        fn slot_of(pool: *const Self, id: u64) ?u32 {
            assert(pool.count <= capacity);
            return live_slot_holding(Entry, &pool.entries, &pool.live, id);
        }

        /// The lowest free slot. The caller has checked that one exists.
        fn free_slot(pool: *const Self) u32 {
            assert(pool.count < capacity);
            const slot = first_slot_with_flag(&pool.live, 0, false);
            // `count` counts the set flags and is below `capacity`, so a clear flag exists.
            assert(slot != null);
            return slot.?;
        }

        /// `class_of(id)`, checked against `class_count`. A class at or above it is programmer
        /// error in the caller's `class_of`, whatever the identifier.
        fn class_index(id: u64) u32 {
            const class = class_of(id);
            assert(class < class_count);
            return class;
        }
    };
}

/// Whether `id` is above `watermark`. A class with no watermark has opened nothing, so every
/// identifier in it is above, 0 included.
fn is_above(id: u64, watermark: ?u64) bool {
    return id > (watermark orelse return true);
}

/// The first slot at or after `from` whose live flag equals `flag`, or null when none does. The
/// scan is bounded by `live.len`, the pool's capacity.
fn first_slot_with_flag(live: []const bool, from: u32, flag: bool) ?u32 {
    assert(from <= live.len);
    for (live[from..], from..) |is_live, slot| {
        if (is_live == flag) return @intCast(slot);
    }
    return null;
}

/// The slot whose live flag is set and whose entry holds `id`, or null when none is. The scan is
/// bounded by `live.len`, the pool's capacity.
fn live_slot_holding(comptime Entry: type, entries: []const Entry, live: []const bool, id: u64) ?u32 {
    assert(entries.len == live.len);
    for (entries, live, 0..) |*entry, is_live, slot| {
        if (is_live and entry.id == id) return @intCast(slot);
    }
    return null;
}

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
