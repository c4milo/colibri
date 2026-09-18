//! The 9-octet frame header of RFC 9113 §4.1: a 24-bit Length, an 8-bit Type, an 8-bit Flags
//! field, one reserved bit and a 31-bit Stream Identifier, all in network byte order (§2.2).
//!
//! `read` takes the nine octets through the bounded reader (invariant 3) and masks the reserved
//! bit off the stream identifier, which §4.1 says a receiver ignores. It applies no other rule:
//! whether the Length fits SETTINGS_MAX_FRAME_SIZE is the connection's check (§4.2), and every
//! rule of a frame type is that type's parser's. `write` asserts its contract, writes the reserved
//! bit as zero (§4.1) and writes all nine octets or none.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("../constants.zig");

const Reader = core.Reader;
const Writer = core.Writer;

/// The four fields of a frame header (RFC 9113 §4.1), the reserved bit already dropped.
pub const Header = struct {
    /// Octets of payload after the header, as the Length field states (RFC 9113 §4.1).
    length: u32,
    /// The Type octet, which `frame.Type` names for the ten defined types.
    type: u8,
    flags: u8,
    /// The 31-bit Stream Identifier with the reserved bit already masked off.
    stream_id: u32,
};

/// Reads one header. The reader moves past all nine octets or, on `error.Truncated`, none.
pub fn read(reader: *Reader) core.reader.Error!Header {
    var cursor = reader.*;
    var length: u32 = 0;
    for (0..constants.frame_length_len) |_| {
        length = (length << @bitSizeOf(u8)) | try cursor.read_byte();
    }
    const frame_type = try cursor.read_byte();
    const flags = try cursor.read_byte();
    // RFC 9113 §4.1: the reserved bit MUST be ignored when receiving.
    const stream_id = (try cursor.read_int(u32)) & ~constants.reserved_bit_mask;
    assert(length <= constants.frame_length_max);
    assert(stream_id <= constants.stream_id_max);
    reader.* = cursor;
    return .{ .length = length, .type = frame_type, .flags = flags, .stream_id = stream_id };
}

/// Writes one header, all nine octets or none, with the reserved bit unset (RFC 9113 §4.1).
pub fn write(writer: *Writer, header: Header) core.writer.Error!void {
    assert(header.length <= constants.frame_length_max);
    assert(header.stream_id <= constants.stream_id_max);
    var cursor = writer.*;
    var length_octets: [constants.frame_length_len]u8 = @splat(0);
    var rest = header.length;
    for (0..constants.frame_length_len) |index| {
        length_octets[constants.frame_length_len - 1 - index] = @truncate(rest);
        rest >>= @bitSizeOf(u8);
    }
    assert(rest == 0);
    try cursor.write_bytes(&length_octets);
    try cursor.write_byte(header.type);
    try cursor.write_byte(header.flags);
    // RFC 9113 §4.1: the reserved bit MUST remain unset when sending.
    try cursor.write_int(u32, header.stream_id & ~constants.reserved_bit_mask);
    assert(cursor.offset - writer.offset == constants.frame_header_len);
    writer.* = cursor;
}

/// Whether `flag` is set. A flag the frame type does not define is unused and read by nothing
/// (RFC 9113 §4.1), so the answer means something only for a flag the type defines:
/// `connection_receive.zig` reads ACK before it knows the type and drops the answer when it is
/// not SETTINGS.
pub fn has_flag(header: Header, flag: u8) bool {
    assert(flag != 0);
    return header.flags & flag != 0;
}

const testing = std.testing;

test "a header reads its four fields in network byte order and moves past nine octets" {
    var reader = Reader.init(&.{ 0x00, 0x00, 0x14, 0x00, 0x08, 0x00, 0x00, 0x00, 0x02, 0xff });
    const header = try read(&reader);
    try testing.expectEqual(20, header.length);
    try testing.expectEqual(constants.frame_type_data, header.type);
    try testing.expectEqual(constants.flag_padded, header.flags);
    try testing.expectEqual(2, header.stream_id);
    try testing.expectEqual(1, reader.remaining_len());
}

test "the reserved bit of the stream identifier is ignored on receipt (RFC 9113 §4.1)" {
    var reader = Reader.init(&.{ 0x00, 0x00, 0x00, 0x04, 0x00, 0xff, 0xff, 0xff, 0xff });
    const header = try read(&reader);
    try testing.expectEqual(constants.stream_id_max, header.stream_id);
    try testing.expectEqual(0, header.stream_id & constants.reserved_bit_mask);
}

test "the length field is 24 bits wide" {
    var reader = Reader.init(&.{ 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 });
    const header = try read(&reader);
    try testing.expectEqual(constants.frame_length_max, header.length);
}

test "fewer than nine octets is Truncated and consumes nothing" {
    var reader = Reader.init(&.{ 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00 });
    try testing.expectError(error.Truncated, read(&reader));
    try testing.expectEqual(0, reader.offset);
}

test "a header writes the nine octets read reads, with the reserved bit unset (RFC 9113 §4.1)" {
    var buffer: [constants.frame_header_len]u8 = @splat(0);
    var writer = Writer.init(&buffer);
    try write(&writer, .{
        .length = 0x010203,
        .type = constants.frame_type_goaway,
        .flags = 0,
        .stream_id = constants.stream_id_max,
    });
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x02, 0x03, 0x07, 0x00, 0x7f, 0xff, 0xff, 0xff }, &buffer);
    var reader = Reader.init(&buffer);
    const header = try read(&reader);
    try testing.expectEqual(0x010203, header.length);
    try testing.expectEqual(constants.stream_id_max, header.stream_id);
}

test "a header write into a short buffer commits nothing" {
    var buffer: [constants.frame_header_len - 1]u8 = @splat(0xee);
    var writer = Writer.init(&buffer);
    try testing.expectError(error.NoSpaceLeft, write(&writer, .{
        .length = 0,
        .type = constants.frame_type_ping,
        .flags = 0,
        .stream_id = 0,
    }));
    try testing.expectEqual(0, writer.offset);
    try testing.expectEqual(0, writer.written().len);
}

test "has_flag reads one bit of the flags octet" {
    const header: Header = .{ .length = 0, .type = 0, .flags = 0x05, .stream_id = 1 };
    try testing.expect(has_flag(header, constants.flag_end_stream));
    try testing.expect(has_flag(header, constants.flag_end_headers));
    try testing.expect(!has_flag(header, constants.flag_padded));
}
