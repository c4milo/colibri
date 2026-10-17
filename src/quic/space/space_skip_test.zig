//! The tests of the packet numbers a space skips (`space.zig`, RFC 9000 §21.4): one number after
//! each interval, the intervals in turn from the caller's draw, and an ACK frame that covers a
//! skipped number refused as one for a packet never sent.
const std = @import("std");
const constants = @import("../constants.zig");
const frame = @import("../frame/frame.zig");
const space_module = @import("space.zig");

const Space = space_module.Space;
const testing = std.testing;

var test_space: Space align(@alignOf(Space)) = undefined;

/// A draw whose first two octets are 0 and 1, so the first skip comes after the fewest packets and
/// the second after one more. Test-only.
const intervals: u64 = 0x0100;
const first_interval: u64 = constants.packet_number_skip_interval_min;
const second_interval: u64 = constants.packet_number_skip_interval_min + 1;
/// Packets sent after the first skip, and how far above it `ack_below`'s first range ends.
/// Test-only.
const after_skip: u64 = 8;
const below_largest: u64 = 3;

/// Sends `count` packets and returns the number the last one took. Test-only.
fn send(count: u64) !u64 {
    var number: u64 = 0;
    for (0..count) |_| number = try test_space.next_number();
    return number;
}

/// An ACK frame of one range, from `smallest` to `largest`. Test-only.
fn ack_of(smallest: u64, largest: u64) frame.Ack {
    return .{
        .ranges = .{ .largest_acknowledged = largest, .first_range = largest - smallest, .octets = "", .count = 0 },
        .delay = 0,
        .ecn = null,
    };
}

/// The octets of one Gap and ACK Range Length pair, each a one-octet varint. Test-only.
var pair: [pair_len]u8 = undefined;
const pair_len: usize = 2;

/// An ACK frame of two ranges with one number missing between them, `missing`. Each varint of the
/// pair is one octet, so the lower range holds fewer than 64 numbers. Test-only.
fn ack_around(smallest: u64, missing: u64, largest: u64) frame.Ack {
    // RFC 9000 §19.3.1: the gap is one less than the numbers missing, and a range's length is one
    // less than the numbers it holds.
    pair = .{ 0, @intCast(missing - 1 - smallest) };
    return .{
        .ranges = .{ .largest_acknowledged = largest, .first_range = largest - (missing + 1), .octets = &pair, .count = 1 },
        .delay = 0,
        .ecn = null,
    };
}

test "RFC 9000 §21.4: a space skips one number after each interval, the intervals in turn from the draw" {
    test_space.init(.application);
    test_space.skips = .init(intervals);
    const before_skip = try send(first_interval);
    try testing.expectEqual(first_interval - 1, before_skip);
    // The number after the interval's last packet is skipped.
    try testing.expectEqual(first_interval, test_space.skips.?.skipped.?);
    try testing.expectEqual(first_interval + 1, try test_space.next_number());
    // The next interval is one packet longer, from the draw's second octet.
    const next_skip = try send(second_interval - 1);
    try testing.expectEqual(first_interval + second_interval, next_skip);
    try testing.expectEqual(first_interval + second_interval + 1, test_space.skips.?.skipped.?);
}

test "RFC 9000 §21.4: an ACK frame that covers a skipped number is one for a packet never sent" {
    test_space.init(.application);
    test_space.skips = .init(intervals);
    // Packets past the skipped number, so each frame below names only numbers that went out.
    _ = try send(first_interval + after_skip);
    const skipped = test_space.skips.?.skipped.?;
    try testing.expect(skipped + below_largest < test_space.next_packet_number);
    // An honest peer leaves the skipped number out.
    _ = try test_space.on_ack(ack_around(skipped - 2, skipped, skipped + 2));
    // One that acknowledges every number up to the largest covers it.
    try testing.expectError(error.AcknowledgedUnsentPacket, test_space.on_ack(ack_of(0, skipped + 2)));
    // A range that ends just below it, or starts just above it, does not.
    _ = try test_space.on_ack(ack_of(0, skipped - 1));
    _ = try test_space.on_ack(ack_of(skipped + 1, skipped + 2));
    // A range that starts at it, or ends at it, covers it.
    try testing.expectError(error.AcknowledgedUnsentPacket, test_space.on_ack(ack_of(skipped, skipped + 1)));
    try testing.expectError(error.AcknowledgedUnsentPacket, test_space.on_ack(ack_of(skipped - 1, skipped)));
    // A range below the first covers it too.
    try testing.expectError(error.AcknowledgedUnsentPacket, test_space.on_ack(ack_below(skipped)));
}

/// An ACK frame of two ranges: `covered + 2` and `covered + 3`, then a gap of one number, then
/// `covered - 1` and `covered`, so the second range holds `covered`. Test-only.
fn ack_below(covered: u64) frame.Ack {
    // RFC 9000 §19.3.1: the next range's largest is the first's smallest less the gap less 2,
    // and its length is one less than the numbers it holds.
    pair = .{ 0, 1 };
    return .{
        .ranges = .{ .largest_acknowledged = covered + below_largest, .first_range = 1, .octets = &pair, .count = 1 },
        .delay = 0,
        .ecn = null,
    };
}

test "RFC 9000 §21.4: a space given no draw skips no number" {
    test_space.init(.application);
    try testing.expectEqual(null, test_space.skips);
    const last = try send(first_interval * 4);
    try testing.expectEqual(first_interval * 4 - 1, last);
}
