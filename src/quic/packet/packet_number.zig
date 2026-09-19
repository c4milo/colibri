//! Packet number encoding and decoding (RFC 9000 §17.1, Appendix A.2 and A.3). A packet number is
//! 0 to 2^62-1 (§12.3), and a header carries its 1 to 4 least significant octets. The sender picks
//! how many from what the peer has acknowledged; the receiver rebuilds the rest from the largest
//! number it has processed.
//!
//! Both functions are pure, and neither reads a connection. RFC 9001 §9.5 asks that a receiver
//! recover the packet number together with removing header and packet protection, with no side
//! channel between the steps, so whichever code removes the protection calls `decode`.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("../constants.zig");

const Reader = core.Reader;
const Writer = core.Writer;

/// The octets of a packet number as a header carries them.
pub const Truncated = struct {
    /// The `len` least significant octets of the full packet number.
    value: u32,
    /// Octets of the Packet Number field, 1 to 4 (RFC 9000 §17.1).
    len: u8,
};

pub const EncodeError = error{
    /// Four octets cannot represent twice the range between the packet number and the largest one
    /// acknowledged, so no encoding RFC 9000 §17.1 permits exists.
    RangeTooLarge,
};

/// Picks the shortest Packet Number field that lets the peer recover `full` (RFC 9000 Appendix
/// A.2). `largest_acked` is the largest packet number the peer has acknowledged in this packet
/// number space, or null before any.
pub fn encode(full: u64, largest_acked: ?u64) EncodeError!Truncated {
    assert(full <= constants.packet_number_max);
    assert(largest_acked == null or largest_acked.? < full);
    // RFC 9000 §17.1: before an acknowledgment arrives the full packet number MUST be included,
    // which Appendix A.2 gets by counting every number from 0 as unacknowledged.
    const unacknowledged = if (largest_acked) |acked| full - acked else full + 1;
    // RFC 9000 §17.1: the sender MUST use a size able to represent more than twice as large a
    // range as the difference between the largest acknowledged number and the one being sent.
    const range = unacknowledged * constants.packet_number_range_factor;
    for (1..constants.packet_number_len_max + 1) |len| {
        if (range < window_of(@intCast(len))) {
            return .{ .value = @truncate(full & (window_of(@intCast(len)) - 1)), .len = @intCast(len) };
        }
    }
    // RFC 9000 §17.1: the field is 1 to 4 bytes, and four do not represent twice this range.
    return error.RangeTooLarge;
}

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
fn window_of(len: u8) u64 {
    assert(len >= 1 and len <= constants.packet_number_len_max);
    return @as(u64, 1) << @intCast(@as(u8, @bitSizeOf(u8)) * len);
}

/// Writes the Packet Number field, most significant octet first (RFC 9000 §17.1).
pub fn write(writer: *Writer, truncated: Truncated) core.writer.Error!void {
    assert(truncated.len >= 1 and truncated.len <= constants.packet_number_len_max);
    var octets: [constants.packet_number_len_max]u8 = undefined;
    for (0..truncated.len) |index| {
        const shift = @as(u8, @bitSizeOf(u8)) * @as(u8, @intCast(truncated.len - 1 - index));
        octets[index] = @truncate(truncated.value >> @intCast(shift));
    }
    try writer.write_bytes(octets[0..truncated.len]);
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

test "Appendix A.2: the two sample encodings" {
    // 29,519 numbers are outstanding, and twice that needs 16 bits.
    try testing.expectEqual(Truncated{ .value = 0x5c02, .len = 2 }, try encode(0xac5c02, 0xabe8b3));
    // 65,611 are outstanding, and twice that needs 18 bits, so 24 are sent.
    try testing.expectEqual(Truncated{ .value = 0xace8fe, .len = 3 }, try encode(0xace8fe, 0xabe8b3));
}

test "§17.1: before any acknowledgment the whole number is carried" {
    try testing.expectEqual(Truncated{ .value = 0, .len = 1 }, try encode(0, null));
    try testing.expectEqual(Truncated{ .value = 126, .len = 1 }, try encode(126, null));
    // 128 numbers outstanding is a range of 256, which one octet does not exceed.
    try testing.expectEqual(Truncated{ .value = 127, .len = 2 }, try encode(127, null));
    try testing.expectEqual(Truncated{ .value = 0x7fff_fffe, .len = 4 }, try encode(0x7fff_fffe, null));
    try testing.expectError(error.RangeTooLarge, encode(0x7fff_ffff, null));
}

test "§17.1: each length starts where twice the range stops fitting the one below" {
    const acked: u64 = 1 << 40;
    try testing.expectEqual(1, (try encode(acked + 127, acked)).len);
    try testing.expectEqual(2, (try encode(acked + 128, acked)).len);
    try testing.expectEqual(2, (try encode(acked + 0x7fff, acked)).len);
    try testing.expectEqual(3, (try encode(acked + 0x8000, acked)).len);
    try testing.expectEqual(4, (try encode(acked + 0x80_0000, acked)).len);
    try testing.expectError(error.RangeTooLarge, encode(acked + 0x8000_0000, acked));
    try testing.expectEqual(1, (try encode(constants.packet_number_max, constants.packet_number_max - 1)).len);
}

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

test "§17.1: what encode truncates, decode rebuilds, across every length" {
    const acked = [_]u64{ 0, 1, 0xfe, 0xffff, 0xab_cdef, 1 << 33, constants.packet_number_max - 0x7fff_ffff };
    const ahead = [_]u64{ 1, 2, 127, 128, 0x7fff, 0x8000, 0x7f_ffff, 0x80_0000, 0x7fff_ffff };
    for (acked) |largest_acked| {
        for (ahead) |distance| {
            const full = largest_acked + distance;
            const truncated = try encode(full, largest_acked);
            // The receiver has processed anything from the acknowledged number to one below.
            try testing.expectEqual(full, decode(largest_acked, truncated));
            try testing.expectEqual(full, decode(full - 1, truncated));
        }
    }
}

test "§17.1: the field is written most significant octet first, and read back" {
    var buffer: [constants.packet_number_len_max]u8 = undefined;
    for ([_]Truncated{
        .{ .value = 0x9b, .len = 1 },
        .{ .value = 0x9b32, .len = 2 },
        .{ .value = 0xace8fe, .len = 3 },
        .{ .value = 0xdeadbeef, .len = 4 },
    }) |truncated| {
        var writer = Writer.init(&buffer);
        try write(&writer, truncated);
        try testing.expectEqual(truncated.len, writer.written().len);
        try testing.expectEqual(@as(u8, @truncate(truncated.value)), writer.written()[truncated.len - 1]);
        var reader = Reader.init(writer.written());
        try testing.expectEqual(truncated, try read(&reader, truncated.len));
    }
    var reader = Reader.init(&.{ 0x01, 0x02 });
    try testing.expectError(error.Truncated, read(&reader, 3));
}
