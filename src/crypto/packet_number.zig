//! Recovering a packet number (RFC 9000 §17.1, Appendix A.3). A header carries the 1 to 4 least
//! significant octets of a number that is 0 to 2^62-1 (§12.3), and the receiver rebuilds the rest
//! from the largest number it has processed.
//!
//! This is here and not in `quic` because decision 48 makes it the suite's step: RFC 9001 §9.5
//! asks that a receiver recover the packet number together with removing header and packet
//! protection, with no side channel between the three, so whichever code holds the keys calls
//! `decode`. `quic` picks the length a sender uses, which is its `packet_number.encode`.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("constants.zig");

const Reader = core.Reader;

/// The octets of a packet number as a header carries them.
pub const Truncated = struct {
    /// The `len` least significant octets of the full packet number.
    value: u32,
    /// Octets of the Packet Number field, 1 to 4 (RFC 9000 §17.1).
    len: u8,
};

/// Rebuilds the full packet number (RFC 9000 Appendix A.3). `largest` is the largest packet
/// number successfully processed in this packet number space, or null before any.
pub fn decode(largest: ?u64, truncated: Truncated) u64 {
    assert(truncated.len >= 1 and truncated.len <= constants.packet_number_len_max);
    assert(largest == null or largest.? <= constants.packet_number_max);
    const window = window_of(truncated.len);
    const half_window = window / constants.packet_number_range_factor;
    const mask = window - 1;
    assert(truncated.value <= mask);
    // RFC 9000 §17.1: the next expected packet is the highest received packet number plus one.
    const expected = if (largest) |number| number + 1 else 0;
    const candidate = (expected & ~mask) | truncated.value;
    // RFC 9000 §12.3: a packet number is at most 2^62-1. Appendix A.3's sample leaves out the one
    // case that goes past it: the number expected is 2^62, so every candidate is a window too high.
    if (candidate > constants.packet_number_max) return candidate - window;
    // RFC 9000 Appendix A.3: the number is the one closest to `expected`, so a candidate half a
    // window or more below it is one window too low, unless the next window is past 2^62-1. The
    // comparison adds to the candidate because `expected - half_window` would go below zero.
    if (candidate + half_window <= expected and candidate + window <= constants.packet_number_max) {
        return candidate + window;
    }
    // And a candidate more than half a window above it is one window too high, unless that is
    // the first window.
    if (candidate > expected + half_window and candidate >= window) return candidate - window;
    return candidate;
}

/// The count of values `len` octets carry.
pub fn window_of(len: u8) u64 {
    assert(len >= 1 and len <= constants.packet_number_len_max);
    return @as(u64, 1) << @intCast(@as(u8, @bitSizeOf(u8)) * len);
}

/// Reads a Packet Number field of `len` octets, which header protection has been removed from.
pub fn read(reader: *Reader, len: u8) core.reader.Error!Truncated {
    assert(len >= 1 and len <= constants.packet_number_len_max);
    const octets = try reader.take(len);
    var value: u32 = 0;
    for (octets) |octet| value = (value << @bitSizeOf(u8)) | octet;
    return .{ .value = value, .len = len };
}

const testing = std.testing;

test "Appendix A.3: the sample decoding" {
    try testing.expectEqual(0xa82f9b32, decode(0xa82f30ea, .{ .value = 0x9b32, .len = 2 }));
}

test "Appendix A.3: the closest number wins, above and below what is expected" {
    // Expected 0x100: 0xff is one below it, and not 0x1ff.
    try testing.expectEqual(0xff, decode(0xff, .{ .value = 0xff, .len = 1 }));
    // Expected 0x1ff: a field of 0x00 is 0x200, one above, and not 0x100.
    try testing.expectEqual(0x200, decode(0x1fe, .{ .value = 0x00, .len = 1 }));
    // Expected 0x200. The window reaches half a window above it and stops there.
    try testing.expectEqual(0x280, decode(0x1ff, .{ .value = 0x80, .len = 1 }));
    try testing.expectEqual(0x181, decode(0x1ff, .{ .value = 0x81, .len = 1 }));
    // Expected 0x2ff. Half a window below it is outside, and goes up a window; one closer stays.
    try testing.expectEqual(0x37f, decode(0x2fe, .{ .value = 0x7f, .len = 1 }));
    try testing.expectEqual(0x280, decode(0x2fe, .{ .value = 0x80, .len = 1 }));
}

test "Appendix A.3: the first window never goes below zero, and the last never past 2^62-1" {
    try testing.expectEqual(0, decode(null, .{ .value = 0, .len = 1 }));
    try testing.expectEqual(0xff, decode(null, .{ .value = 0xff, .len = 1 }));
    try testing.expectEqual(0xfe, decode(3, .{ .value = 0xfe, .len = 1 }));
    const max = constants.packet_number_max;
    try testing.expectEqual(max, decode(max - 1, .{ .value = 0xff, .len = 1 }));
    // The window above the last one does not exist, so a number half a window below stays.
    try testing.expectEqual(max - 0xef, decode(max - 1, .{ .value = 0x10, .len = 1 }));
    // Expected is 2^62, past the last number, and the window above does not exist.
    try testing.expectEqual(max - 0xfe, decode(max, .{ .value = 0x01, .len = 1 }));
}

test "§17.1: a field is read most significant octet first, all of it or none" {
    var reader = Reader.init(&.{ 0xac, 0xe8, 0xfe, 0x01 });
    try testing.expectEqual(Truncated{ .value = 0xace8fe, .len = 3 }, try read(&reader, 3));
    try testing.expectError(error.Truncated, read(&reader, 2));
    try testing.expectEqual(Truncated{ .value = 0x01, .len = 1 }, try read(&reader, 1));
}
