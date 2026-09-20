//! The frames that carry octets: STREAM (RFC 9000 §19.8), CRYPTO (§19.6), NEW_TOKEN (§19.7) and
//! PADDING (§19.1). Split off `frame.zig` because each one ends in a payload whose length comes
//! from somewhere different — a Length field, an implicit run to the end of the packet, or the
//! frame's own repetition.
//!
//! Every payload is a slice of the caller's octets. Nothing is copied here and nothing is held
//! past the call (design §4.1).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const constants = @import("../constants.zig");

const Reader = core.Reader;
const Writer = core.Writer;
const frame = @import("frame.zig");

/// A STREAM frame (RFC 9000 §19.8). The three flags of its type are read into fields: `offset`
/// is 0 when the OFF bit was clear, `data` runs to the end of the packet when the LEN bit was
/// clear, and `fin` is the FIN bit.
pub const Stream = struct {
    stream_id: u64,
    offset: u64,
    data: []const u8,
    fin: bool,
    /// Whether the frame carried a Length field. A frame without one runs to the end of the
    /// packet, so it can only be the last, and a writer must know which shape to produce.
    has_length: bool,
};

/// A CRYPTO frame (RFC 9000 §19.6). It always carries an offset and a length, because it never
/// runs to the end of a packet and there is one crypto stream per encryption level.
pub const Crypto = struct {
    offset: u64,
    data: []const u8,
};

/// Reads a STREAM frame whose type has been consumed. `frame_type` carries the three flags.
pub fn read_stream(reader: *Reader, frame_type: u64) frame.Error!Stream {
    assert(frame_type >= constants.frame_stream_first and frame_type <= constants.frame_stream_last);
    const stream_id = try frame.read_varint(reader);
    // RFC 9000 §19.8: the OFF bit says an Offset field is present, and its absence means 0.
    const offset = if (frame_type & constants.stream_flag_off != 0) try frame.read_varint(reader) else 0;
    // RFC 9000 §19.8: the LEN bit says a Length field is present; without one the data extends
    // to the end of the packet, so this frame is the packet's last.
    const has_length = frame_type & constants.stream_flag_len != 0;
    const data = if (has_length) try read_sized(reader) else reader.take_rest();
    // RFC 9000 §19.8: the largest offset delivered, the sum of the offset and the data length,
    // cannot exceed 2^62-1.
    if (offset > constants.stream_offset_max - data.len) return error.StreamOffsetTooLarge;
    return .{
        .stream_id = stream_id,
        .offset = offset,
        .data = data,
        .fin = frame_type & constants.stream_flag_fin != 0,
        .has_length = has_length,
    };
}

pub fn write_stream(writer: *Writer, stream: Stream) core.writer.Error!void {
    assert(stream.offset <= constants.stream_offset_max - stream.data.len);
    var frame_type = constants.frame_stream_first;
    // RFC 9000 §19.8: an offset of 0 needs no Offset field, and the flags say what is present.
    if (stream.offset != 0) frame_type |= constants.stream_flag_off;
    if (stream.has_length) frame_type |= constants.stream_flag_len;
    if (stream.fin) frame_type |= constants.stream_flag_fin;
    try frame.write_type(writer, frame_type);
    try wire.varint.encode(writer, stream.stream_id);
    if (stream.offset != 0) try wire.varint.encode(writer, stream.offset);
    if (stream.has_length) try wire.varint.encode(writer, stream.data.len);
    try writer.write_bytes(stream.data);
}

/// Reads a CRYPTO frame whose type has been consumed (RFC 9000 §19.6).
pub fn read_crypto(reader: *Reader) frame.Error!Crypto {
    const offset = try frame.read_varint(reader);
    const data = try read_sized(reader);
    // RFC 9000 §19.6: the sum of the offset and the length cannot exceed 2^62-1, which §19.8
    // states for a stream and which the crypto stream shares.
    if (offset > constants.stream_offset_max - data.len) return error.StreamOffsetTooLarge;
    return .{ .offset = offset, .data = data };
}

pub fn write_crypto(writer: *Writer, crypto: Crypto) core.writer.Error!void {
    assert(crypto.offset <= constants.stream_offset_max - crypto.data.len);
    try frame.write_type(writer, constants.frame_crypto);
    try wire.varint.encode(writer, crypto.offset);
    try wire.varint.encode(writer, crypto.data.len);
    try writer.write_bytes(crypto.data);
}

/// Reads a NEW_TOKEN frame whose type has been consumed (RFC 9000 §19.7).
pub fn read_token(reader: *Reader) frame.Error![]const u8 {
    const token = try read_sized(reader);
    // RFC 9000 §19.7: the token MUST NOT be empty, and a client treats an empty one as a
    // connection error of FRAME_ENCODING_ERROR.
    if (token.len == 0) return error.TokenEmpty;
    return token;
}

pub fn write_token(writer: *Writer, token: []const u8) core.writer.Error!void {
    assert(token.len > 0);
    try frame.write_type(writer, constants.frame_new_token);
    try wire.varint.encode(writer, token.len);
    try writer.write_bytes(token);
}

/// A length as a variable-length integer, then that many octets.
fn read_sized(reader: *Reader) frame.Error![]const u8 {
    const len = try frame.read_varint(reader);
    if (len > reader.remaining_len()) return error.Truncated;
    return reader.take(@intCast(len)) catch unreachable;
}

/// Reads a run of PADDING frames as one (RFC 9000 §19.1). The type octet of the first has been
/// consumed, so the run is one octet plus every zero after it. A packet is padded with many of
/// these and reading them one at a time would cost a call per octet.
pub fn read_padding(reader: *Reader) usize {
    var len: usize = 1;
    // The octets present bound the run.
    for (0..reader.remaining_len()) |_| {
        const next = reader.peek_byte() catch return len;
        if (next != constants.frame_padding) return len;
        _ = reader.read_byte() catch unreachable;
        len += 1;
    }
    return len;
}

pub fn write_padding(writer: *Writer, len: usize) core.writer.Error!void {
    assert(len > 0);
    if (len > writer.remaining_len()) return error.NoSpaceLeft;
    for (0..len) |_| try writer.write_byte(@intCast(constants.frame_padding));
}
