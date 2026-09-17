//! The Pad Length rule that DATA, HEADERS and PUSH_PROMISE share (RFC 9113 §6.1, §6.2, §6.6).
//! When the PADDED flag is set, the payload starts with a Pad Length octet and ends with that many
//! padding octets, and the frame's own fields sit between the two.
//!
//! `strip` checks, in order (invariant 7):
//!   1. the PADDED flag is unset, in which case the whole payload is the frame's own fields;
//!   2. the Pad Length octet is present, or `error.LengthInvalid` (§4.2: too small for its
//!      mandatory data, a FRAME_SIZE_ERROR);
//!   3. the padding length is less than the payload length, or `error.PaddingTooLong`, a
//!      connection error of PROTOCOL_ERROR (§6.1, §6.2, §6.6).
//!
//! The padding octets are not verified: §6.1 lets a receiver treat non-zero padding as an error
//! (a MAY), and colibri does not. On send every padding octet is zero (§6.1: a MUST). A padding
//! length of 0 sends no Pad Length octet and no PADDED flag.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("../constants.zig");
const frame_header = @import("frame_header.zig");

const Reader = core.Reader;
const Writer = core.Writer;
const Header = frame_header.Header;

/// The two errors `strip` returns.
pub const Error = error{
    /// A PADDED frame whose payload has no Pad Length octet (RFC 9113 §4.2).
    LengthInvalid,
    /// The Pad Length names the whole payload or more (RFC 9113 §6.1, §6.2, §6.6).
    PaddingTooLong,
};

/// A payload with the Pad Length octet and the padding removed.
pub const Unpadded = struct {
    /// The frame's own fields: everything between the Pad Length octet and the padding.
    payload: []const u8,
    /// Padding octets the frame carried, 0 when the PADDED flag was unset.
    padding_len: u8,
};

/// Removes the Pad Length octet and the padding from `payload` when `header` has the PADDED flag.
pub fn strip(header: Header, payload: []const u8) Error!Unpadded {
    assert(payload.len == header.length);
    if (!frame_header.has_flag(header, constants.flag_padded)) {
        return .{ .payload = payload, .padding_len = 0 };
    }
    var reader = Reader.init(payload);
    // RFC 9113 §4.2: a frame too small to contain its mandatory data is a FRAME_SIZE_ERROR.
    const padding_len = reader.read_byte() catch return error.LengthInvalid;
    // RFC 9113 §6.1, §6.2, §6.6: padding of the payload length or greater is a connection error
    // of PROTOCOL_ERROR.
    if (padding_len >= payload.len) return error.PaddingTooLong;
    // The check above leaves at least `padding_len` octets after the Pad Length octet.
    const fields = reader.take(reader.remaining_len() - padding_len) catch unreachable;
    const padding = reader.take_rest();
    assert(padding.len == padding_len);
    assert(fields.len + padding.len + constants.pad_length_len == payload.len);
    return .{ .payload = fields, .padding_len = padding_len };
}

/// The PADDED flag when `padding_len` is not 0, and no flag when it is.
pub fn flag(padding_len: u8) u8 {
    return if (padding_len == 0) 0 else constants.flag_padded;
}

/// The Length field of a frame whose own fields take `fields_len` octets and that carries
/// `padding_len` octets of padding, counting the Pad Length octet when there is padding.
pub fn padded_len(fields_len: usize, padding_len: u8) u32 {
    const padding_total: usize = if (padding_len == 0) 0 else constants.pad_length_len + padding_len;
    const total = fields_len + padding_total;
    assert(total <= constants.frame_length_max);
    return @intCast(total);
}

/// Writes the Pad Length octet when `padding_len` is not 0 (RFC 9113 §6.1).
pub fn write_pad_length(writer: *Writer, padding_len: u8) core.writer.Error!void {
    if (padding_len == 0) return;
    try writer.write_byte(padding_len);
}

/// Writes `padding_len` zero octets (RFC 9113 §6.1: padding octets MUST be set to zero when
/// sending). The caller writes through a copy of its writer, so a short buffer costs nothing.
pub fn write_padding(writer: *Writer, padding_len: u8) core.writer.Error!void {
    const start = writer.offset;
    for (0..padding_len) |_| try writer.write_byte(0);
    assert(writer.offset - start == padding_len);
}

const testing = std.testing;

fn padded_header(length: u32) Header {
    return .{ .length = length, .type = constants.frame_type_data, .flags = constants.flag_padded, .stream_id = 1 };
}

test "an unpadded payload is returned whole with a padding length of 0" {
    const header: Header = .{ .length = 3, .type = constants.frame_type_data, .flags = 0, .stream_id = 1 };
    const unpadded = try strip(header, "abc");
    try testing.expectEqualStrings("abc", unpadded.payload);
    try testing.expectEqual(0, unpadded.padding_len);
}

test "a padded payload loses its Pad Length octet and its padding (RFC 9113 §6.1)" {
    const unpadded = try strip(padded_header(6), "\x02abc\xaa\xbb");
    try testing.expectEqualStrings("abc", unpadded.payload);
    try testing.expectEqual(2, unpadded.padding_len);
}

test "padding one shorter than the payload leaves no fields, and is legal" {
    const unpadded = try strip(padded_header(3), "\x02\xaa\xbb");
    try testing.expectEqual(0, unpadded.payload.len);
    try testing.expectEqual(2, unpadded.padding_len);
}

test "padding of the payload length or greater is PaddingTooLong (RFC 9113 §6.1)" {
    try testing.expectError(error.PaddingTooLong, strip(padded_header(3), "\x03\xaa\xbb"));
    try testing.expectError(error.PaddingTooLong, strip(padded_header(4), "\x04\xaa\xaa\xaa"));
    try testing.expectError(error.PaddingTooLong, strip(padded_header(1), "\x01"));
    try testing.expectError(error.PaddingTooLong, strip(padded_header(2), "\xff\xaa"));
}

test "a PADDED frame with an empty payload has no Pad Length octet and is LengthInvalid" {
    try testing.expectError(error.LengthInvalid, strip(padded_header(0), ""));
}

test "non-zero padding octets are not verified on receipt (RFC 9113 §6.1, a MAY not taken)" {
    const unpadded = try strip(padded_header(4), "\x02a\x01\xff");
    try testing.expectEqualStrings("a", unpadded.payload);
}

test "the writers produce the Pad Length octet, the fields' length and zero padding" {
    try testing.expectEqual(0, flag(0));
    try testing.expectEqual(constants.flag_padded, flag(1));
    try testing.expectEqual(3, padded_len(3, 0));
    try testing.expectEqual(3 + 1 + 6, padded_len(3, 6));
    var buffer: [8]u8 = @splat(0xee);
    var writer = Writer.init(&buffer);
    try write_pad_length(&writer, 0);
    try testing.expectEqual(0, writer.offset);
    try write_pad_length(&writer, 3);
    try write_padding(&writer, 3);
    try testing.expectEqualSlices(u8, &.{ 0x03, 0x00, 0x00, 0x00 }, writer.written());
    try testing.expectError(error.NoSpaceLeft, write_padding(&writer, 5));
}

test "what the writers produce, strip reads back" {
    var buffer: [16]u8 = @splat(0);
    var writer = Writer.init(&buffer);
    try write_pad_length(&writer, 4);
    try writer.write_bytes("xyz");
    try write_padding(&writer, 4);
    const unpadded = try strip(padded_header(padded_len(3, 4)), writer.written());
    try testing.expectEqualStrings("xyz", unpadded.payload);
    try testing.expectEqual(4, unpadded.padding_len);
}
