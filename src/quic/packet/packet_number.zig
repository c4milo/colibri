//! Choosing and writing a Packet Number field (RFC 9000 §17.1, Appendix A.2). A packet number is
//! 0 to 2^62-1 (§12.3), and a header carries its 1 to 4 least significant octets. The sender picks
//! how many from what the peer has acknowledged.
//!
//! The receiver's half, Appendix A.3, is `crypto.packet_number.decode`: decision 48 has the suite
//! recover the packet number while it removes protection (RFC 9001 §9.5). The tests here encode
//! with this file and decode with that one, so the two halves are checked against each other.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const crypto = @import("crypto");
const constants = @import("../constants.zig");

const Reader = core.Reader;
const Writer = core.Writer;

/// The octets of a packet number as a header carries them.
pub const Truncated = crypto.packet_number.Truncated;

const decode = crypto.packet_number.decode;
const read = crypto.packet_number.read;
const window_of = crypto.packet_number.window_of;

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
