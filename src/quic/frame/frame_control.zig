//! The frames that carry only numbers, and the two that carry a fixed-size value:
//! RESET_STREAM and STOP_SENDING (RFC 9000 §19.4, §19.5), the limit and blocked frames (§19.9 to
//! §19.14), the connection ID frames (§19.15, §19.16), path validation (§19.17, §19.18),
//! CONNECTION_CLOSE (§19.19) and HANDSHAKE_DONE (§19.20). Split off `frame.zig` for length.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const constants = @import("../constants.zig");

const Reader = core.Reader;
const Writer = core.Writer;
const frame = @import("frame.zig");
const Frame = frame.Frame;
const Directionality = frame.Directionality;
const CloseLayer = frame.CloseLayer;

/// A NEW_CONNECTION_ID frame (RFC 9000 §19.15).
pub const NewConnectionId = struct {
    sequence_number: u64,
    retire_prior_to: u64,
    connection_id: []const u8,
    stateless_reset_token: *const [constants.stateless_reset_token_len]u8,
};

/// A CONNECTION_CLOSE frame (RFC 9000 §19.19).
pub const ConnectionClose = struct {
    layer: CloseLayer,
    error_code: u64,
    /// The frame type that caused the error, present only in a transport close (§19.19).
    frame_type: ?u64,
    /// RFC 9000 §19.19: it may be zero length, and is not necessarily valid UTF-8.
    reason: []const u8,
};

/// Reads the frame whose type has been consumed. Every type `frame.zig` did not handle reaches
/// here, so an unknown one is refused here too.
pub fn read(reader: *Reader, frame_type: u64) frame.Error!Frame {
    return switch (frame_type) {
        constants.frame_reset_stream => .{ .reset_stream = .{
            .stream_id = try frame.read_varint(reader),
            .error_code = try frame.read_varint(reader),
            .final_size = try frame.read_varint(reader),
        } },
        constants.frame_stop_sending => .{ .stop_sending = .{
            .stream_id = try frame.read_varint(reader),
            .error_code = try frame.read_varint(reader),
        } },
        constants.frame_max_data => .{ .max_data = .{ .maximum = try frame.read_varint(reader) } },
        constants.frame_max_stream_data => .{ .max_stream_data = .{
            .stream_id = try frame.read_varint(reader),
            .maximum = try frame.read_varint(reader),
        } },
        constants.frame_max_streams_bidirectional,
        constants.frame_max_streams_unidirectional,
        => .{ .max_streams = .{
            .directionality = directionality_of(frame_type),
            .maximum = try read_stream_limit(reader),
        } },
        constants.frame_data_blocked => .{ .data_blocked = .{ .limit = try frame.read_varint(reader) } },
        constants.frame_stream_data_blocked => .{ .stream_data_blocked = .{
            .stream_id = try frame.read_varint(reader),
            .limit = try frame.read_varint(reader),
        } },
        constants.frame_streams_blocked_bidirectional,
        constants.frame_streams_blocked_unidirectional,
        => .{ .streams_blocked = .{
            .directionality = directionality_of(frame_type),
            .limit = try read_stream_limit(reader),
        } },
        constants.frame_new_connection_id => .{ .new_connection_id = try read_new_connection_id(reader) },
        constants.frame_retire_connection_id => .{ .retire_connection_id = .{
            .sequence_number = try frame.read_varint(reader),
        } },
        constants.frame_path_challenge => .{ .path_challenge = .{ .data = try read_path_data(reader) } },
        constants.frame_path_response => .{ .path_response = .{ .data = try read_path_data(reader) } },
        constants.frame_connection_close_transport,
        constants.frame_connection_close_application,
        => .{ .connection_close = try read_connection_close(reader, frame_type) },
        constants.frame_handshake_done => .handshake_done,
        // RFC 9000 §12.4: an endpoint treats the receipt of a frame of unknown type as a
        // connection error of type FRAME_ENCODING_ERROR.
        else => error.TypeUnknown,
    };
}

/// RFC 9000 §19.11, §19.14: the low bit of the type says unidirectional.
fn directionality_of(frame_type: u64) Directionality {
    return if (frame_type & constants.frame_low_bit != 0) .unidirectional else .bidirectional;
}

/// A MAX_STREAMS or STREAMS_BLOCKED count (RFC 9000 §19.11, §19.14).
fn read_stream_limit(reader: *Reader) frame.Error!u64 {
    const value = try frame.read_varint(reader);
    // RFC 9000 §4.6, §19.11: a value above 2^60 would permit a stream ID no variable-length
    // integer can hold, and is a connection error of FRAME_ENCODING_ERROR.
    if (value > constants.max_streams_max) return error.StreamLimitTooLarge;
    return value;
}

fn read_new_connection_id(reader: *Reader) frame.Error!NewConnectionId {
    const sequence_number = try frame.read_varint(reader);
    const retire_prior_to = try frame.read_varint(reader);
    // RFC 9000 §19.15: Retire Prior To greater than the Sequence Number is a connection error.
    if (retire_prior_to > sequence_number) return error.RetirePriorToTooLarge;
    const len = reader.read_byte() catch return error.Truncated;
    const admitted = len >= constants.connection_id_len_min and len <= constants.connection_id_len_max;
    // RFC 9000 §19.15: a connection ID length below 1 or above 20 is invalid and is a connection
    // error of FRAME_ENCODING_ERROR.
    if (!admitted) return error.ConnectionIdLengthInvalid;
    const connection_id = reader.take(len) catch return error.Truncated;
    const token = reader.take(constants.stateless_reset_token_len) catch return error.Truncated;
    return .{
        .sequence_number = sequence_number,
        .retire_prior_to = retire_prior_to,
        .connection_id = connection_id,
        .stateless_reset_token = token[0..constants.stateless_reset_token_len],
    };
}

fn read_path_data(reader: *Reader) frame.Error!*const [constants.path_challenge_len]u8 {
    const data = reader.take(constants.path_challenge_len) catch return error.Truncated;
    return data[0..constants.path_challenge_len];
}

fn read_connection_close(reader: *Reader, frame_type: u64) frame.Error!ConnectionClose {
    const transport = frame_type == constants.frame_connection_close_transport;
    const error_code = try frame.read_varint(reader);
    // RFC 9000 §19.19: the Frame Type field is present in a transport close alone, because an
    // application close names no frame.
    const caused_by = if (transport) try frame.read_varint(reader) else null;
    const reason_len = try frame.read_varint(reader);
    if (reason_len > reader.remaining_len()) return error.Truncated;
    return .{
        .layer = if (transport) .transport else .application,
        .error_code = error_code,
        .frame_type = caused_by,
        .reason = reader.take(@intCast(reason_len)) catch unreachable,
    };
}

/// Writes the frame, which `frame.zig` did not handle.
pub fn write(writer: *Writer, value: Frame) core.writer.Error!void {
    switch (value) {
        .reset_stream => |reset| {
            try frame.write_type(writer, constants.frame_reset_stream);
            try write_varints(writer, &.{ reset.stream_id, reset.error_code, reset.final_size });
        },
        .stop_sending => |stop| {
            try frame.write_type(writer, constants.frame_stop_sending);
            try write_varints(writer, &.{ stop.stream_id, stop.error_code });
        },
        .max_data => |max| {
            try frame.write_type(writer, constants.frame_max_data);
            try write_varints(writer, &.{max.maximum});
        },
        .max_stream_data => |max| {
            try frame.write_type(writer, constants.frame_max_stream_data);
            try write_varints(writer, &.{ max.stream_id, max.maximum });
        },
        .max_streams => |max| {
            assert(max.maximum <= constants.max_streams_max);
            try frame.write_type(writer, type_of(constants.frame_max_streams_bidirectional, max.directionality));
            try write_varints(writer, &.{max.maximum});
        },
        .data_blocked => |blocked| {
            try frame.write_type(writer, constants.frame_data_blocked);
            try write_varints(writer, &.{blocked.limit});
        },
        .stream_data_blocked => |blocked| {
            try frame.write_type(writer, constants.frame_stream_data_blocked);
            try write_varints(writer, &.{ blocked.stream_id, blocked.limit });
        },
        .streams_blocked => |blocked| {
            assert(blocked.limit <= constants.max_streams_max);
            try frame.write_type(writer, type_of(constants.frame_streams_blocked_bidirectional, blocked.directionality));
            try write_varints(writer, &.{blocked.limit});
        },
        .new_connection_id => |new| try write_new_connection_id(writer, new),
        .retire_connection_id => |retire| {
            try frame.write_type(writer, constants.frame_retire_connection_id);
            try write_varints(writer, &.{retire.sequence_number});
        },
        .path_challenge => |challenge| try write_path(writer, constants.frame_path_challenge, challenge.data),
        .path_response => |response| try write_path(writer, constants.frame_path_response, response.data),
        .connection_close => |close| try write_connection_close(writer, close),
        // Every other type is written by `frame.zig`.
        else => unreachable,
    }
}

/// The type of a frame whose low bit carries the directionality (RFC 9000 §19.11, §19.14).
fn type_of(bidirectional: u64, directionality: Directionality) u64 {
    return if (directionality == .unidirectional) bidirectional | constants.frame_low_bit else bidirectional;
}

fn write_varints(writer: *Writer, values: []const u64) core.writer.Error!void {
    for (values) |value| try wire.varint.encode(writer, value);
}

fn write_new_connection_id(writer: *Writer, new: NewConnectionId) core.writer.Error!void {
    assert(new.retire_prior_to <= new.sequence_number);
    assert(new.connection_id.len >= constants.connection_id_len_min);
    assert(new.connection_id.len <= constants.connection_id_len_max);
    try frame.write_type(writer, constants.frame_new_connection_id);
    try write_varints(writer, &.{ new.sequence_number, new.retire_prior_to });
    try writer.write_byte(@intCast(new.connection_id.len));
    try writer.write_bytes(new.connection_id);
    try writer.write_bytes(new.stateless_reset_token);
}

fn write_path(writer: *Writer, frame_type: u64, data: *const [constants.path_challenge_len]u8) core.writer.Error!void {
    try frame.write_type(writer, frame_type);
    try writer.write_bytes(data);
}

fn write_connection_close(writer: *Writer, close: ConnectionClose) core.writer.Error!void {
    const transport = close.layer == .transport;
    assert(transport == (close.frame_type != null));
    const frame_type = if (transport)
        constants.frame_connection_close_transport
    else
        constants.frame_connection_close_application;
    try frame.write_type(writer, frame_type);
    try wire.varint.encode(writer, close.error_code);
    if (close.frame_type) |caused_by| try wire.varint.encode(writer, caused_by);
    try wire.varint.encode(writer, close.reason.len);
    try writer.write_bytes(close.reason);
}
