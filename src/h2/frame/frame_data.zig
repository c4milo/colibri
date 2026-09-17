//! The DATA frame of RFC 9113 §6.1: application data on one stream, with optional padding and
//! the END_STREAM flag.
//!
//! `parse` checks, in order (invariant 7):
//!   1. the stream identifier is not 0, or `error.StreamIdZero`, a connection error of
//!      PROTOCOL_ERROR (§6.1);
//!   2. the padding rule of frame_padding.zig (§6.1).
//! Whether the stream is open is the connection's check, not the codec's. `write_data` writes the
//! whole frame or nothing and sets only the two flags §6.1 defines.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("../constants.zig");
const frame_header = @import("frame_header.zig");
const frame_padding = @import("frame_padding.zig");

const Reader = core.Reader;
const Writer = core.Writer;
const Header = frame_header.Header;

/// Every error `parse` returns: the padding rule's two, and the stream rule of RFC 9113 §6.1.
pub const Error = frame_padding.Error || error{
    /// A DATA frame on stream 0 (RFC 9113 §6.1).
    StreamIdZero,
};

/// The fields and the END_STREAM flag of a DATA frame (RFC 9113 §6.1).
pub const Data = struct {
    /// The Data field, with the Pad Length octet and the padding removed.
    data: []const u8,
    /// Padding octets the frame carried, 0 when it was not padded.
    padding_len: u8,
    end_stream: bool,
};

/// Parses the payload of a DATA frame whose header the connection has read and sized.
pub fn parse(header: Header, payload: []const u8) Error!Data {
    assert(header.type == constants.frame_type_data);
    assert(payload.len == header.length);
    // RFC 9113 §6.1: a DATA frame whose Stream Identifier field is 0x00 is a connection error of
    // PROTOCOL_ERROR.
    if (header.stream_id == constants.connection_stream_id) return error.StreamIdZero;
    const unpadded = try frame_padding.strip(header, payload);
    return .{
        .data = unpadded.payload,
        .padding_len = unpadded.padding_len,
        .end_stream = frame_header.has_flag(header, constants.flag_end_stream),
    };
}

/// Writes one DATA frame, header included, all of it or nothing. `padding_len` octets of zero
/// padding follow the data when it is not 0 (RFC 9113 §6.1).
pub fn write_data(
    writer: *Writer,
    stream_id: u32,
    data: []const u8,
    end_stream: bool,
    padding_len: u8,
) core.writer.Error!void {
    assert(stream_id != constants.connection_stream_id and stream_id <= constants.stream_id_max);
    const length = frame_padding.padded_len(data.len, padding_len);
    var cursor = writer.*;
    const end_stream_flag: u8 = if (end_stream) constants.flag_end_stream else 0;
    try frame_header.write(&cursor, .{
        .length = length,
        .type = constants.frame_type_data,
        .flags = end_stream_flag | frame_padding.flag(padding_len),
        .stream_id = stream_id,
    });
    try frame_padding.write_pad_length(&cursor, padding_len);
    try cursor.write_bytes(data);
    try frame_padding.write_padding(&cursor, padding_len);
    assert(cursor.offset - writer.offset == constants.frame_header_len + length);
    writer.* = cursor;
}

const testing = std.testing;

fn data_header(length: u32, flags: u8, stream_id: u32) Header {
    return .{ .length = length, .type = constants.frame_type_data, .flags = flags, .stream_id = stream_id };
}

test "a DATA frame yields its data, its padding length and END_STREAM" {
    const plain = try parse(data_header(5, 0, 1), "hello");
    try testing.expectEqualStrings("hello", plain.data);
    try testing.expectEqual(0, plain.padding_len);
    try testing.expect(!plain.end_stream);

    const flags = constants.flag_padded | constants.flag_end_stream;
    const padded = try parse(data_header(8, flags, 3), "\x02hello\x00\x00");
    try testing.expectEqualStrings("hello", padded.data);
    try testing.expectEqual(2, padded.padding_len);
    try testing.expect(padded.end_stream);
}

test "an empty DATA frame is legal, with or without END_STREAM" {
    const empty = try parse(data_header(0, constants.flag_end_stream, 1), "");
    try testing.expectEqual(0, empty.data.len);
    try testing.expect(empty.end_stream);
}

test "DATA on stream 0 is StreamIdZero (RFC 9113 §6.1)" {
    try testing.expectError(error.StreamIdZero, parse(data_header(1, 0, 0), "\xaa"));
}

test "DATA with padding of the payload length is PaddingTooLong (RFC 9113 §6.1)" {
    try testing.expectError(error.PaddingTooLong, parse(data_header(4, constants.flag_padded, 1), "\x04\xaa\xaa\xaa"));
}

test "a PADDED DATA frame with no Pad Length octet is LengthInvalid (RFC 9113 §4.2)" {
    try testing.expectError(error.LengthInvalid, parse(data_header(0, constants.flag_padded, 1), ""));
}

test "stream 0 is refused before the padding is read" {
    try testing.expectError(error.StreamIdZero, parse(data_header(4, constants.flag_padded, 0), "\x04\xaa\xaa\xaa"));
}

test "an unused flag on DATA is ignored on receipt (RFC 9113 §4.1)" {
    const data = try parse(data_header(1, constants.flag_end_headers, 1), "a");
    try testing.expectEqualStrings("a", data.data);
    try testing.expect(!data.end_stream);
}

test "write_data writes the header, the data and zero padding, and parse reads it back" {
    var buffer: [32]u8 = @splat(0xee);
    var writer = Writer.init(&buffer);
    try write_data(&writer, 2, "Hi", true, 3);
    try testing.expectEqualSlices(u8, &.{
        0x00, 0x00, 0x06, 0x00, 0x09, 0x00, 0x00, 0x00, 0x02, 0x03, 'H', 'i', 0x00, 0x00, 0x00,
    }, writer.written());
    var reader = Reader.init(writer.written());
    const header = try frame_header.read(&reader);
    const data = try parse(header, reader.take_rest());
    try testing.expectEqualStrings("Hi", data.data);
    try testing.expectEqual(3, data.padding_len);
    try testing.expect(data.end_stream);
}

test "write_data with no padding sets neither PADDED nor a Pad Length octet" {
    var buffer: [16]u8 = @splat(0);
    var writer = Writer.init(&buffer);
    try write_data(&writer, 1, "ab", false, 0);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 'a', 'b' }, writer.written());
}

test "write_data into a short buffer commits nothing" {
    var buffer: [12]u8 = @splat(0xee);
    var writer = Writer.init(&buffer);
    try testing.expectError(error.NoSpaceLeft, write_data(&writer, 1, "abcd", false, 0));
    try testing.expectEqual(0, writer.offset);
    try testing.expectEqual(0, writer.written().len);
}
