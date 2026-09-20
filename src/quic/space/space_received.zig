//! What an endpoint has received in one packet number space, kept as the ACK ranges it will
//! report (RFC 9000 §19.3.1) rather than as a set of numbers. Two jobs share the structure,
//! because both ask the same question of it: which packet numbers have been processed.
//!
//!   1. Duplicate suppression. RFC 9000 §12.3 has a receiver discard a newly unprotected packet
//!      unless it is certain it has not processed another with the same number in the same
//!      space.
//!   2. Acknowledgment. §19.3.1's ranges are exactly the runs this structure holds, in the
//!      descending order the frame wants them in.
//!
//! The storage is fixed, which §13.2.3 asks for: a receiver limits the ranges it remembers,
//! both to bound an ACK frame and to avoid resource exhaustion. When the ranges are full the
//! oldest is dropped, which §13.2.3 also names — "older ranges (those with the smallest packet
//! numbers) are omitted".
//!
//! Dropping a range costs certainty, and the cost is paid openly. Below `floor` this endpoint no
//! longer knows what it processed, so §12.3's "unless it is certain" is not met and a packet
//! there is discarded rather than processed. That refuses some packets a larger structure would
//! have accepted; it never accepts one twice.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");

/// One run of packet numbers received, smallest and largest inclusive.
pub const Range = struct {
    smallest: u64,
    largest: u64,

    fn contains(range: Range, packet_number: u64) bool {
        return packet_number >= range.smallest and packet_number <= range.largest;
    }
};

/// What receiving one packet number means.
pub const Verdict = enum {
    /// The number is new: the caller processes the packet.
    new,
    /// RFC 9000 §12.3: this number was processed before, and a receiver must not process it
    /// twice.
    duplicate,
    /// The number is below what this endpoint still remembers, so §12.3's certainty is gone and
    /// the packet is discarded. A peer that sends a packet this old has lost nothing a
    /// retransmission cannot replace.
    forgotten,
};

/// The ranges received in one packet number space, largest first.
pub const Received = struct {
    /// Descending by `largest`, with no two touching: a run that would touch the next is merged
    /// into it, so the ranges are the fewest that describe what was received.
    ranges: [constants.ack_ranges_max]Range,
    len: usize,

    pub const empty: Received = .{ .ranges = @splat(.{ .smallest = 0, .largest = 0 }), .len = 0 };

    pub fn reset(received: *Received) void {
        received.* = .empty;
    }

    pub fn is_empty(received: *const Received) bool {
        return received.len == 0;
    }

    /// The largest number received, which an ACK frame names first (RFC 9000 §19.3).
    pub fn largest(received: *const Received) ?u64 {
        if (received.len == 0) return null;
        return received.ranges[0].largest;
    }

    /// The smallest number this endpoint still remembers receiving. Anything below it is
    /// `forgotten`, because the range that held it was dropped.
    pub fn floor(received: *const Received) ?u64 {
        if (received.len == 0) return null;
        return received.ranges[received.len - 1].smallest;
    }

    /// Records that `packet_number` was received, and says what it was.
    pub fn receive(received: *Received, packet_number: u64) Verdict {
        assert(packet_number <= constants.packet_number_max);
        for (received.ranges[0..received.len]) |range| {
            // RFC 9000 §12.3: a number inside a range was processed before.
            if (range.contains(packet_number)) return .duplicate;
        }
        // The ranges below the floor were dropped, so nothing here can be certain about them.
        // A number one below the floor is refused too, though it would merely extend the lowest
        // range: the range that held it could have been dropped before its neighbour arrived, so
        // extending downward could take a number this endpoint had already processed.
        if (received.floor()) |smallest| {
            if (packet_number < smallest and received.len == received.ranges.len) return .forgotten;
        }
        received.insert(packet_number);
        return .new;
    }

    /// Puts `packet_number` in, extending or merging a range where it touches one.
    fn insert(received: *Received, packet_number: u64) void {
        const at = received.position_of(packet_number);
        if (received.extend(at, packet_number)) return;
        received.open_slot(at);
        received.ranges[at] = .{ .smallest = packet_number, .largest = packet_number };
    }

    /// Where a range holding `packet_number` belongs, keeping the array descending.
    fn position_of(received: *const Received, packet_number: u64) usize {
        for (received.ranges[0..received.len], 0..) |range, index| {
            if (packet_number > range.largest) return index;
        }
        return received.len;
    }

    /// Grows the range before or after `at` to cover `packet_number`, and merges the two when
    /// the number closes the gap between them. False when it touches neither.
    fn extend(received: *Received, at: usize, packet_number: u64) bool {
        const above = if (at > 0) &received.ranges[at - 1] else null;
        const below = if (at < received.len) &received.ranges[at] else null;
        const joins_above = above != null and above.?.smallest == packet_number + 1;
        const joins_below = below != null and below.?.largest + 1 == packet_number;
        if (joins_above and joins_below) {
            // The number closes the gap, so one range covers both and the lower one goes.
            above.?.smallest = below.?.smallest;
            received.remove(at);
            return true;
        }
        if (joins_above) {
            above.?.smallest = packet_number;
            return true;
        }
        if (joins_below) {
            below.?.largest = packet_number;
            return true;
        }
        return false;
    }

    /// Makes room at `at`, dropping the oldest range when every slot is taken. RFC 9000 §13.2.3:
    /// the ranges with the smallest packet numbers are the ones omitted.
    fn open_slot(received: *Received, at: usize) void {
        assert(at <= received.len);
        if (received.len < received.ranges.len) {
            received.len += 1;
        } else {
            // Nothing is inserted at the end when the array is full: `receive` answered
            // `forgotten` for a number that low.
            assert(at < received.len);
        }
        // The ranges below `at` move down one. The array's length bounds the walk
        // (non-negotiable 4).
        var index = received.len - 1;
        for (0..received.len) |_| {
            if (index == at) return;
            received.ranges[index] = received.ranges[index - 1];
            index -= 1;
        }
    }

    fn remove(received: *Received, at: usize) void {
        assert(at < received.len);
        for (at + 1..received.len) |index| received.ranges[index - 1] = received.ranges[index];
        received.len -= 1;
    }

    /// The range at `index`, counting from the largest. A caller walks these to write an ACK
    /// frame's ranges (RFC 9000 §19.3.1).
    pub fn range_at(received: *const Received, index: usize) Range {
        assert(index < received.len);
        return received.ranges[index];
    }
};

const testing = std.testing;

/// The set the tests drive. Test-only.
var test_received: Received = .empty;

/// Feeds each number and requires the verdict. Test-only.
fn receive_all(numbers: []const u64, expected: Verdict) !void {
    for (numbers) |number| try testing.expectEqual(expected, test_received.receive(number));
}

/// The ranges as they stand, largest first. Test-only.
fn ranges() []const Range {
    return test_received.ranges[0..test_received.len];
}

test "§19.3.1: numbers in order become one range, and the ranges stay descending" {
    test_received.reset();
    try testing.expect(test_received.is_empty());
    try testing.expectEqual(null, test_received.largest());
    try receive_all(&.{ 0, 1, 2, 3 }, .new);
    try testing.expectEqualSlices(Range, &.{.{ .smallest = 0, .largest = 3 }}, ranges());
    // A number past a gap opens a range above, and the array stays descending.
    try receive_all(&.{ 10, 11 }, .new);
    try testing.expectEqualSlices(Range, &.{
        .{ .smallest = 10, .largest = 11 },
        .{ .smallest = 0, .largest = 3 },
    }, ranges());
    try testing.expectEqual(11, test_received.largest().?);
    try testing.expectEqual(0, test_received.floor().?);
}

test "§19.3.1: a number that closes a gap merges the two ranges around it" {
    test_received.reset();
    try receive_all(&.{ 0, 2 }, .new);
    try testing.expectEqual(2, test_received.len);
    // 1 joins both sides, so one range covers all three.
    try receive_all(&.{1}, .new);
    try testing.expectEqualSlices(Range, &.{.{ .smallest = 0, .largest = 2 }}, ranges());
    // A number that joins only below extends that range, and only above extends the other.
    try receive_all(&.{ 3, 9, 8 }, .new);
    try testing.expectEqualSlices(Range, &.{
        .{ .smallest = 8, .largest = 9 },
        .{ .smallest = 0, .largest = 3 },
    }, ranges());
}

test "§12.3: a number received before is a duplicate, wherever it sits" {
    test_received.reset();
    try receive_all(&.{ 5, 6, 7, 20 }, .new);
    // Inside a range, at either end of one, and the lone number of another.
    try receive_all(&.{ 5, 6, 7, 20 }, .duplicate);
    // The numbers in the gap are new, and are duplicates once received.
    try receive_all(&.{ 8, 19 }, .new);
    try receive_all(&.{ 8, 19 }, .duplicate);
}

test "§13.2.3: past the limit the oldest range is dropped, and what it held is forgotten" {
    test_received.reset();
    // Every other number, so each is a range of its own: 0, 2, 4, ... in ascending order, which
    // fills the array from the bottom.
    for (0..constants.ack_ranges_max) |index| {
        try testing.expectEqual(Verdict.new, test_received.receive(index * 2));
    }
    try testing.expectEqual(constants.ack_ranges_max, test_received.len);
    try testing.expectEqual(0, test_received.floor().?);
    // One more range at the top drops the range holding 0.
    const above = constants.ack_ranges_max * 2;
    try testing.expectEqual(Verdict.new, test_received.receive(above));
    try testing.expectEqual(constants.ack_ranges_max, test_received.len);
    try testing.expectEqual(2, test_received.floor().?);
    // RFC 9000 §12.3: 0 is below what is remembered, so it is discarded and not processed twice.
    try testing.expectEqual(Verdict.forgotten, test_received.receive(0));
    // 1 is below the floor too, though it would merely extend the range holding 2. Accepting it
    // would be unsound: a range holding 1 could have been dropped before 2 ever arrived, and
    // extending downward would then take a number this endpoint had already processed.
    try testing.expectEqual(Verdict.forgotten, test_received.receive(1));
    try testing.expectEqual(2, test_received.floor().?);
    try testing.expectEqual(constants.ack_ranges_max, test_received.len);
    // A number above the floor is still new, and merging there drops no certainty.
    try testing.expectEqual(Verdict.new, test_received.receive(3));
    try testing.expectEqual(Range{ .smallest = 2, .largest = 4 }, test_received.range_at(test_received.len - 1));
}

test "§12.3: the largest packet number is received like any other" {
    test_received.reset();
    const max = constants.packet_number_max;
    try receive_all(&.{ max, max - 1 }, .new);
    try testing.expectEqualSlices(Range, &.{.{ .smallest = max - 1, .largest = max }}, ranges());
    try receive_all(&.{max}, .duplicate);
}

test "the ranges are the fewest that describe what was received, in any order" {
    test_received.reset();
    // Descending, ascending and interleaved all end in one range.
    try receive_all(&.{ 9, 8, 7, 6 }, .new);
    try testing.expectEqual(1, test_received.len);
    test_received.reset();
    try receive_all(&.{ 6, 8, 7, 9 }, .new);
    try testing.expectEqualSlices(Range, &.{.{ .smallest = 6, .largest = 9 }}, ranges());
    try testing.expectEqual(Range{ .smallest = 6, .largest = 9 }, test_received.range_at(0));
}
