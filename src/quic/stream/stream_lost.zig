//! The stream octets lost in transit and not yet framed again (RFC 9000 §13.3). Part of design §8
//! step 9e.
//!
//! §13.3: "Application data sent in STREAM frames is retransmitted in new STREAM frames unless the
//! endpoint has sent a RESET_STREAM for that stream." colibri sends again exactly what was lost
//! ([decision 57](../../../docs/decisions.md)), so a lost packet's range comes here, and `send`
//! frames the oldest range here before any new octets.
//!
//! **Adjacent ranges of one stream merge.** A range split to fit a smaller packet (§13.3) lies
//! next to its remainder, so losing the piece again while the remainder waits leaves one entry and
//! not two. A table that fills anyway is a named limit reached, and the caller ends the
//! connection.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");

pub const Error = error{
    /// Every entry holds a range, and the new one lies next to none of its stream's. Nothing
    /// changed; the connection cannot send the octets again, so it ends with INTERNAL_ERROR
    /// (RFC 9000 §20.1).
    Full,
};

/// A run of one stream's octets, and the FIN when it ends the stream (RFC 9000 §19.8).
pub const Range = struct {
    stream_id: u64,
    offset: u64,
    len: u64,
    fin: bool,

    pub fn end(range: Range) u64 {
        return range.offset + range.len;
    }
};

pub const LostRanges = struct {
    /// The ranges in the order they were lost, as a ring: `count` of them from `head`.
    entries: [constants.stream_lost_ranges_max]Range,
    head: usize,
    count: usize,

    pub fn init(lost: *LostRanges) void {
        lost.head = 0;
        lost.count = 0;
    }

    /// Keeps a range the peer did not receive, joined to one of its stream's ranges it lies next
    /// to when there is one.
    pub fn add(lost: *LostRanges, range: Range) Error!void {
        // A range carries octets or the FIN (RFC 9000 §19.8), or it is not a range.
        assert(range.len > 0 or range.fin);
        if (lost.merge(range)) return;
        if (lost.count == lost.entries.len) return Error.Full;
        lost.entries[slot_at(lost.head, lost.count)] = range;
        lost.count += 1;
    }

    /// Joins `range` to a range of its stream it lies next to. False when there is none.
    fn merge(lost: *LostRanges, range: Range) bool {
        // Bounded by the entries, whose number is a named limit.
        for (0..lost.count) |from| {
            const held = &lost.entries[slot_at(lost.head, from)];
            if (held.stream_id != range.stream_id) continue;
            if (held.end() == range.offset) {
                // RFC 9000 §4.5: nothing of a stream lies past its FIN.
                assert(!held.fin);
                held.len += range.len;
                held.fin = range.fin;
                return true;
            }
            if (range.end() == held.offset) {
                assert(!range.fin);
                held.offset = range.offset;
                held.len += range.len;
                return true;
            }
        }
        return false;
    }

    /// The range lost longest ago, which RFC 9000 §13.3 puts first: "Endpoints SHOULD prioritize
    /// retransmission of data over sending new data". Null when nothing is owed.
    pub fn oldest(lost: *const LostRanges) ?Range {
        if (lost.count == 0) return null;
        return lost.entries[lost.head];
    }

    /// Takes the first `len` octets of the oldest range, and its FIN when `fin` is set, once a
    /// STREAM frame has carried them again. A range left with neither leaves the table.
    pub fn take_oldest(lost: *LostRanges, len: u64, fin: bool) void {
        assert(lost.count > 0);
        const held = &lost.entries[lost.head];
        assert(len <= held.len);
        // The FIN goes out with the range's last octet or after it (RFC 9000 §4.5).
        assert(!fin or (held.fin and len == held.len));
        held.offset += len;
        held.len -= len;
        if (fin) held.fin = false;
        if (held.len == 0 and !held.fin) lost.drop_oldest();
    }

    /// The lowest offset a range of `stream_id` holds, or null when none is owed on it. Octets
    /// there are not acknowledged, which decision 78's acknowledged end reads.
    pub fn lowest_offset(lost: *const LostRanges, stream_id: u64) ?u64 {
        var lowest: ?u64 = null;
        // Bounded by the entries, whose number is a named limit.
        for (0..lost.count) |from| {
            const held = lost.entries[slot_at(lost.head, from)];
            if (held.stream_id != stream_id) continue;
            if (lowest == null or held.offset < lowest.?) lowest = held.offset;
        }
        return lowest;
    }

    /// Removes the oldest range without framing it, which RFC 9000 §13.3 permits once a
    /// RESET_STREAM has gone out for its stream: "no further STREAM frames are needed".
    pub fn drop_oldest(lost: *LostRanges) void {
        assert(lost.count > 0);
        lost.head = slot_at(lost.head, 1);
        lost.count -= 1;
    }
};

/// The slot `from` places past `head`.
fn slot_at(head: usize, from: usize) usize {
    assert(from <= constants.stream_lost_ranges_max);
    return (head + from) % constants.stream_lost_ranges_max;
}

const testing = std.testing;

var test_lost: LostRanges = undefined;
/// A packet's worth of octets, and two streams to tell apart. Test-only.
const test_len: u64 = 1_000;
const test_stream: u64 = 0;
const test_other_stream: u64 = 4;

fn range_of(stream_id: u64, offset: u64, len: u64, fin: bool) Range {
    return .{ .stream_id = stream_id, .offset = offset, .len = len, .fin = fin };
}

test "§13.3: the range lost longest ago is framed again first" {
    test_lost.init();
    try testing.expectEqual(null, test_lost.oldest());
    try test_lost.add(range_of(test_stream, 0, test_len, false));
    try test_lost.add(range_of(test_other_stream, 0, test_len, true));
    try testing.expectEqual(test_stream, test_lost.oldest().?.stream_id);
    // A smaller packet carries part of it, and the rest stays first in line (§13.3).
    test_lost.take_oldest(test_len / 2, false);
    try testing.expectEqual(test_len / 2, test_lost.oldest().?.offset);
    test_lost.take_oldest(test_len / 2, false);
    try testing.expectEqual(test_other_stream, test_lost.oldest().?.stream_id);
    // The FIN leaves with the last octet, and the range with it.
    test_lost.take_oldest(test_len, true);
    try testing.expectEqual(0, test_lost.count);
}

test "§13.3: a FIN lost on its own is kept until it goes out again" {
    test_lost.init();
    try test_lost.add(range_of(test_stream, test_len, 0, true));
    const held = test_lost.oldest().?;
    try testing.expectEqual(test_len, held.offset);
    try testing.expect(held.fin);
    test_lost.take_oldest(0, true);
    try testing.expectEqual(0, test_lost.count);
    // A range whose octets go out in one frame and its FIN in another stays for the FIN.
    try test_lost.add(range_of(test_stream, 0, test_len, true));
    test_lost.take_oldest(test_len, false);
    try testing.expectEqual(1, test_lost.count);
    try testing.expect(test_lost.oldest().?.fin);
    test_lost.take_oldest(0, true);
    try testing.expectEqual(0, test_lost.count);
}

test "§13.3: ranges of one stream that meet become one, on either side" {
    test_lost.init();
    try test_lost.add(range_of(test_stream, test_len, test_len, false));
    // The piece before it, and the piece after it with the FIN.
    try test_lost.add(range_of(test_stream, 0, test_len, false));
    try test_lost.add(range_of(test_stream, 2 * test_len, test_len, true));
    try testing.expectEqual(1, test_lost.count);
    const held = test_lost.oldest().?;
    try testing.expectEqual(0, held.offset);
    try testing.expectEqual(3 * test_len, held.len);
    try testing.expect(held.fin);
    // Another stream's range at the same offsets joins nothing.
    try test_lost.add(range_of(test_other_stream, 3 * test_len, test_len, false));
    try testing.expectEqual(2, test_lost.count);
    // Nor does a range of the same stream with a gap before it.
    test_lost.init();
    try test_lost.add(range_of(test_stream, 0, test_len, false));
    try test_lost.add(range_of(test_stream, 2 * test_len, test_len, false));
    try testing.expectEqual(2, test_lost.count);
}

test "§13.3: a full table refuses a range it cannot join, and joins one it can" {
    test_lost.init();
    for (0..constants.stream_lost_ranges_max) |index| {
        // Each range a gap apart, so none of them joins another.
        try test_lost.add(range_of(test_stream, 2 * test_len * index, test_len, false));
    }
    const past = range_of(test_stream, 2 * test_len * constants.stream_lost_ranges_max, test_len, false);
    try testing.expectError(Error.Full, test_lost.add(past));
    try testing.expectEqual(constants.stream_lost_ranges_max, test_lost.count);
    // A range filling the first gap joins the first entry, so a full table still takes it.
    try test_lost.add(range_of(test_stream, test_len, test_len, false));
    try testing.expectEqual(2 * test_len, test_lost.oldest().?.len);
    // Dropping the oldest frees a slot, and the ring goes on past its end.
    test_lost.drop_oldest();
    try test_lost.add(past);
    try testing.expectEqual(constants.stream_lost_ranges_max, test_lost.count);
}

test "decision 78: the lowest lost offset is per stream, whatever order the ranges came in" {
    test_lost.init();
    try testing.expectEqual(null, test_lost.lowest_offset(test_stream));
    try test_lost.add(range_of(test_stream, 3 * test_len, test_len, false));
    try test_lost.add(range_of(test_other_stream, 0, test_len, false));
    try test_lost.add(range_of(test_stream, test_len, test_len, false));
    // The later range sits lower, and the other stream's lower still.
    try testing.expectEqual(test_len, test_lost.lowest_offset(test_stream).?);
    try testing.expectEqual(0, test_lost.lowest_offset(test_other_stream).?);
    test_lost.drop_oldest();
    try testing.expectEqual(test_len, test_lost.lowest_offset(test_stream).?);
}
