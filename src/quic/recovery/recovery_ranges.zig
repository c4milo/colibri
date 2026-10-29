//! The stream ranges of each application-level packet after its first (decision 131, INV-33).
//! Part of design §8 step 26.
//!
//! A packet's record keeps its first STREAM frame's range in place (decision 56). The ring holds
//! the others, in the order the packets went out, and each record names the head's position
//! before its ranges and how many it has. Positions only grow, and wrap in 32 bits.
//!
//! **The ring keeps no liveness of its own.** Records leave the sent table in send order at its
//! oldest end, so the oldest record the table holds is where the live ranges start: the caller
//! passes that record's position as the tail. Every position from the tail to the head is in use,
//! and a packet whose ranges would pass the tail carries one STREAM frame.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");

/// One STREAM frame's range after a packet's first, as `recovery_sent.Record` holds the first:
/// the stream's 62-bit identifier (RFC 9000 §2.1), where the octets sat in it (§19.8), how many
/// there were, and whether the frame carried the FIN.
pub const Extra = struct {
    stream_id: u64,
    offset: u64,
    /// Octets, which one packet bounds, so 16 bits carry them, as `Record.data_len`.
    len: u16,
    fin: bool,
};

pub const Ring = struct {
    entries: [constants.stream_ranges_max]Extra,
    /// The position the next range takes.
    head: u32,

    pub fn init(ring: *Ring) void {
        ring.head = 0;
    }

    /// How many ranges fit before the head would pass `tail`, the position of the oldest record
    /// the sent table holds, or the head itself when it holds none.
    pub fn room(ring: *const Ring, tail: u32) usize {
        const used = ring.head -% tail;
        // INV-33: no record the table holds is older than the oldest one.
        assert(used <= constants.stream_ranges_max);
        return constants.stream_ranges_max - used;
    }

    /// Writes `extra` at the head. The caller asked `room` first.
    pub fn push(ring: *Ring, tail: u32, extra: Extra) void {
        // INV-33: the head never passes a range a live record names.
        assert(ring.room(tail) > 0);
        assert(extra.len > 0 or extra.fin);
        ring.entries[ring.head % constants.stream_ranges_max] = extra;
        ring.head +%= 1;
    }

    /// The `index`th of the ranges a record names from `from`. A record that left the sent table
    /// is read before the next packet is framed, so its ranges are still in place.
    pub fn at(ring: *const Ring, from: u32, len: u8, index: usize) Extra {
        assert(index < len);
        // INV-33: the record's ranges were written, and none has been written over since.
        assert(ring.head -% from <= constants.stream_ranges_max);
        assert(len <= ring.head -% from);
        return ring.entries[(from +% @as(u32, @intCast(index))) % constants.stream_ranges_max];
    }
};

const testing = std.testing;

/// The stream every range of these tests is on: the client's second bidirectional one. Test-only.
const test_stream_id: u64 = 4;

/// A range of `len` octets at `offset` on `test_stream_id`. Test-only.
fn extra_of(offset: u64, len: u16) Extra {
    return .{ .stream_id = test_stream_id, .offset = offset, .len = len, .fin = false };
}

test "decision 131: a record reads back the ranges written after its position" {
    var ring: Ring = undefined;
    ring.init();
    const from = ring.head;
    ring.push(from, extra_of(0, 10));
    ring.push(from, extra_of(10, 20));
    try testing.expectEqual(constants.stream_ranges_max - 2, ring.room(from));
    try testing.expectEqual(10, ring.at(from, 2, 1).offset);
    try testing.expectEqual(20, ring.at(from, 2, 1).len);
    // With no record held, the tail is the head, and the whole ring is free.
    try testing.expectEqual(constants.stream_ranges_max, ring.room(ring.head));
}

test "INV-33: the ring fills up to the oldest record, and frees as the tail moves" {
    var ring: Ring = undefined;
    ring.init();
    const oldest = ring.head;
    for (0..constants.stream_ranges_max) |index| ring.push(oldest, extra_of(index, 1));
    try testing.expectEqual(0, ring.room(oldest));
    // The oldest record left: the next one's position is the tail, and its ranges stay readable.
    const next = oldest +% 1;
    try testing.expectEqual(1, ring.room(next));
    ring.push(next, extra_of(constants.stream_ranges_max, 1));
    try testing.expectEqual(1, ring.at(next, 1, 0).offset);
    const last = next +% @as(u32, constants.stream_ranges_max - 1);
    try testing.expectEqual(constants.stream_ranges_max, ring.at(last, 1, 0).offset);
}

test "INV-33: positions wrap past 32 bits and still name their ranges" {
    var ring: Ring = undefined;
    ring.init();
    ring.head = std.math.maxInt(u32);
    const from = ring.head;
    ring.push(from, extra_of(7, 1));
    ring.push(from, extra_of(8, 1));
    try testing.expectEqual(0, ring.head -% 1);
    try testing.expectEqual(8, ring.at(from, 2, 1).offset);
    try testing.expectEqual(constants.stream_ranges_max - 2, ring.room(from));
}
