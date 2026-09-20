//! ACK frames (RFC 9000 §19.3), with their ranges (§19.3.1) and ECN counts (§19.3.2). Split off
//! `frame.zig` because the ranges are the one frame field that is a sequence and the one that
//! can be refused for its arithmetic rather than its length.
//!
//! The ranges are read but not expanded. A frame names the largest packet number acknowledged
//! and then walks downward in alternating gaps and runs, and expanding that into a set would
//! need storage proportional to what a peer claims. `AckRanges` keeps the octets and hands them
//! out one range at a time, so a frame of any size costs the same to hold and colibri decides
//! what to keep.
//!
//! What is checked here is the one rule §19.3.1 states: if any computed packet number is
//! negative, the frame is a connection error of FRAME_ENCODING_ERROR. The walk is done once when
//! the frame is read, so a range that would go below zero is refused before any caller sees a
//! number, and `AckRanges` can then be walked again without failing.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const constants = @import("../constants.zig");

const Reader = core.Reader;
const Writer = core.Writer;
const frame = @import("frame.zig");

/// The three counts of RFC 9000 §19.3.2, present when the frame's type is 0x03.
pub const EcnCounts = struct {
    ect_0: u64,
    ect_1: u64,
    ecn_ce: u64,
};

/// One contiguous run of acknowledged packet numbers, smallest and largest inclusive.
pub const Range = struct {
    smallest: u64,
    largest: u64,
};

/// The ranges of one ACK frame, walked from the largest number downward. It holds the octets the
/// ranges were read from, so walking it again yields the same ranges and costs no storage.
pub const AckRanges = struct {
    largest_acknowledged: u64,
    first_range: u64,
    /// The Gap and ACK Range Length pairs after the first range, as they were on the wire.
    octets: []const u8,
    count: u64,

    /// Walks the ranges in descending order. The first is always present.
    pub const Iterator = struct {
        ranges: *const AckRanges,
        reader: Reader,
        /// The smallest number of the range just returned, which the next gap counts down from.
        previous_smallest: u64,
        yielded: u64,

        /// The next range, or null after the last. It cannot fail: `read` walked every range
        /// once and refused the frame if any went below zero.
        pub fn next(walk: *Iterator) ?Range {
            if (walk.yielded > walk.ranges.count) return null;
            defer walk.yielded += 1;
            if (walk.yielded == 0) {
                const largest = walk.ranges.largest_acknowledged;
                const smallest = largest - walk.ranges.first_range;
                walk.previous_smallest = smallest;
                return .{ .smallest = smallest, .largest = largest };
            }
            const gap = (wire.varint.decode(&walk.reader) catch unreachable).value;
            const length = (wire.varint.decode(&walk.reader) catch unreachable).value;
            // RFC 9000 §19.3.1: largest = previous_smallest - gap - 2, and the range reaches
            // `length` packets below it.
            const largest = walk.previous_smallest - gap - gap_step;
            const smallest = largest - length;
            walk.previous_smallest = smallest;
            return .{ .smallest = smallest, .largest = largest };
        }
    };

    pub fn iterator(ranges: *const AckRanges) Iterator {
        return .{
            .ranges = ranges,
            .reader = Reader.init(ranges.octets),
            .previous_smallest = 0,
            .yielded = 0,
        };
    }

    /// The smallest packet number any range acknowledges.
    pub fn smallest_acknowledged(ranges: *const AckRanges) u64 {
        var walk = ranges.iterator();
        var smallest = ranges.largest_acknowledged;
        // The count is the frame's own, read before the walk, so it bounds the loop.
        for (0..ranges.count + 1) |_| {
            const range = walk.next() orelse break;
            smallest = range.smallest;
        }
        return smallest;
    }
};

/// RFC 9000 §19.3.1: the gap between two ranges is one more than the encoded value, and the
/// range below it starts one lower again, so the largest of the next range is two below the
/// smallest of the last, less the gap.
const gap_step: u64 = 2;

pub const Ack = struct {
    ranges: AckRanges,
    /// Microseconds, before the ack_delay_exponent of RFC 9000 §18.2 is applied. The exponent is
    /// a transport parameter, which the connection holds and this layer does not.
    delay: u64,
    /// Present when the frame's type is 0x03 (RFC 9000 §19.3.2).
    ecn: ?EcnCounts,
};

/// Reads an ACK frame whose type has been consumed.
pub fn read(reader: *Reader, frame_type: u64) frame.Error!Ack {
    const largest_acknowledged = try frame.read_varint(reader);
    const delay = try frame.read_varint(reader);
    const count = try frame.read_varint(reader);
    const first_range = try frame.read_varint(reader);
    // RFC 9000 §19.3.1: the first range reaches `first_range` packets below the largest, and a
    // computed packet number below zero is a connection error.
    if (first_range > largest_acknowledged) return error.AckRangeBelowZero;
    const start = reader.offset;
    const smallest = try walk_ranges(reader, count, largest_acknowledged - first_range);
    _ = smallest;
    const ranges: AckRanges = .{
        .largest_acknowledged = largest_acknowledged,
        .first_range = first_range,
        .octets = reader.consumed_since(start),
        .count = count,
    };
    // RFC 9000 §19.3.2: the low bit of the type says the three counts follow.
    const ecn = if (frame_type & constants.frame_low_bit != 0) try read_ecn(reader) else null;
    return .{ .ranges = ranges, .delay = delay, .ecn = ecn };
}

/// Walks every range once, refusing the frame if any computed number goes below zero, and
/// returns the smallest acknowledged. The count is a peer's value, so the loop is bounded by the
/// octets present: each range takes at least two, so a count past that many is a truncation.
fn walk_ranges(reader: *Reader, count: u64, first_smallest: u64) frame.Error!u64 {
    var previous_smallest = first_smallest;
    var walked: u64 = 0;
    const bound = reader.remaining_len() / octets_per_range_min + 1;
    for (0..bound) |_| {
        if (walked == count) return previous_smallest;
        const gap = try frame.read_varint(reader);
        const length = try frame.read_varint(reader);
        // RFC 9000 §19.3.1: largest = previous_smallest - gap - 2, then the range reaches
        // `length` below it, and a number below zero is a connection error.
        if (previous_smallest < gap + gap_step) return error.AckRangeBelowZero;
        const largest = previous_smallest - gap - gap_step;
        // RFC 9000 §19.3.1: the range reaches `length` packets below the largest, and a computed
        // packet number below zero is a connection error of FRAME_ENCODING_ERROR.
        if (length > largest) return error.AckRangeBelowZero;
        previous_smallest = largest - length;
        walked += 1;
    }
    // The count names more ranges than the octets can hold.
    return error.Truncated;
}

/// Fewest octets one Gap and ACK Range Length pair occupies (RFC 9000 §16, §19.3.1).
const octets_per_range_min: usize = 2;

fn read_ecn(reader: *Reader) frame.Error!EcnCounts {
    return .{
        .ect_0 = try frame.read_varint(reader),
        .ect_1 = try frame.read_varint(reader),
        .ecn_ce = try frame.read_varint(reader),
    };
}

/// Writes an ACK frame, all of it or none.
pub fn write(writer: *Writer, ack: Ack) core.writer.Error!void {
    // RFC 9000 §19.3: the type is 0x02, or 0x03 when the ECN counts follow (§19.3.2).
    const frame_type = if (ack.ecn == null) constants.frame_ack else constants.frame_ack_ecn;
    try frame.write_type(writer, frame_type);
    try wire.varint.encode(writer, ack.ranges.largest_acknowledged);
    try wire.varint.encode(writer, ack.delay);
    try wire.varint.encode(writer, ack.ranges.count);
    try wire.varint.encode(writer, ack.ranges.first_range);
    try writer.write_bytes(ack.ranges.octets);
    const ecn = ack.ecn orelse return;
    try wire.varint.encode(writer, ecn.ect_0);
    try wire.varint.encode(writer, ecn.ect_1);
    try wire.varint.encode(writer, ecn.ecn_ce);
}
