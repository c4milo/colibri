//! The blocks of the "QPACK Offline Interop" format: a 64-bit stream ID, a 32-bit length and that
//! many octets, both integers in network byte order. Stream 0 is the encoder stream, and a request
//! stream's block holds one encoded field section. Part of design §9's QIF tools.
const std = @import("std");
const core = @import("core");
const constants = @import("constants.zig");

const Reader = core.Reader;
const Writer = core.Writer;

pub const Block = struct {
    stream_id: u64,
    octets: []const u8,
};

/// Writes one block, whole or not at all.
pub fn write(writer: *Writer, stream_id: u64, octets: []const u8) core.writer.Error!void {
    var cursor = writer.*;
    try cursor.write_int(u64, stream_id);
    try cursor.write_int(u32, std.math.cast(u32, octets.len) orelse return error.NoSpaceLeft);
    try cursor.write_bytes(octets);
    writer.* = cursor;
}

/// Reads one block, whole or not at all.
pub fn read(reader: *Reader) core.reader.Error!Block {
    var cursor = reader.*;
    const stream_id = try cursor.read_int(u64);
    const len = try cursor.read_int(u32);
    const octets = try cursor.take(len);
    reader.* = cursor;
    return .{ .stream_id = stream_id, .octets = octets };
}

const testing = std.testing;

test "a block is its stream ID and length in network byte order, then its octets" {
    var octets: [constants.block_header_len + 2]u8 = undefined;
    var writer = Writer.init(&octets);
    try write(&writer, 4, &.{ 0x03, 0x81 });
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 2, 0x03, 0x81 }, writer.written());
    var reader = Reader.init(writer.written());
    const block = try read(&reader);
    try testing.expectEqual(4, block.stream_id);
    try testing.expectEqualSlices(u8, &.{ 0x03, 0x81 }, block.octets);
    // A block cut short is not read at all.
    var short = Reader.init(writer.written()[0 .. writer.written().len - 1]);
    try testing.expectError(error.Truncated, read(&short));
    try testing.expectEqual(writer.written().len - 1, short.remaining_len());
}
