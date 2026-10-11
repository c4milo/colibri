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
        /// The slot `get` last found an entry in, or `open` last wrote. `get` reads it before it
        /// scans, because a frame and its answer look one stream up several times in a row.
        last_slot: u32,

        /// Empties the pool and clears every watermark. `entries` is not written: see its
        /// comment.
        pub fn init(pool: *Self) void {
            pool.live = @splat(false);
            pool.count = 0;
            pool.watermark = @splat(null);
            pool.last_slot = 0;
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
            pool.last_slot = slot;
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
            pool.last_slot = slot;
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
            assert(pool.last_slot < capacity);
            // No two live entries hold one identifier, so the slot the scan would find is this
            // one whenever this one holds `id`.
            if (pool.live[pool.last_slot] and pool.entries[pool.last_slot].id == id) return pool.last_slot;
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

test {
    _ = @import("slots_test.zig");
}
