//! QUIC frames (RFC 9000 §19): what a packet's payload holds once its protection is removed.
//! This is the frame layer of design §8 step 9, and it is the piece of that step that needs no
//! key, no handshake and no connection state — a frame is read out of octets and written into
//! them, and what it means is the connection's business.
//!
//! Every frame begins with a type, which is a variable-length integer (RFC 9000 §12.4). The
//! twenty types of Table 3 are one octet each, and this reader admits no other: §12.4 makes a
//! frame of unknown type a connection error of FRAME_ENCODING_ERROR, so an extension frame
//! (§19.21) is refused here and not ignored.
//!
//! Three types carry their shape in the type itself. A STREAM frame's three low bits say whether
//! an Offset and a Length are present and whether the stream ends (§19.8); an ACK frame's low bit
//! says whether the ECN counts follow (§19.3.2); a MAX_STREAMS, STREAMS_BLOCKED or
//! CONNECTION_CLOSE type's low bit picks between two readings. Each is read into a field of the
//! frame rather than left in the type, so nothing downstream reads a bit out of a number.
//!
//! Every slice a frame carries points into the caller's octets and is valid until the caller
//! reuses them (design §4.1). Nothing here allocates and nothing copies.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const constants = @import("../constants.zig");

const Reader = core.Reader;
const Level = core.Level;
const Writer = core.Writer;

pub const frame_ack = @import("frame_ack.zig");
pub const frame_stream = @import("frame_stream.zig");
pub const frame_control = @import("frame_control.zig");

pub const Ack = frame_ack.Ack;
pub const AckRanges = frame_ack.AckRanges;
pub const EcnCounts = frame_ack.EcnCounts;
pub const Stream = frame_stream.Stream;
pub const Crypto = frame_stream.Crypto;

/// Why a frame was not read. RFC 9000 §19 makes each of these a connection error of
/// FRAME_ENCODING_ERROR, which `connection_error_code` gives; they are separate values so a
/// trace and a test name which rule refused the frame.
pub const Error = error{
    /// The frame runs past the octets present.
    Truncated,
    /// RFC 9000 §12.4: a frame of a type this version does not define.
    TypeUnknown,
    /// RFC 9000 §19.3.1: an ACK range would put a packet number below zero.
    AckRangeBelowZero,
    /// RFC 9000 §19.8: a STREAM frame whose offset and length together pass 2^62-1.
    StreamOffsetTooLarge,
    /// RFC 9000 §19.7: a NEW_TOKEN frame whose token is empty.
    TokenEmpty,
    /// RFC 9000 §19.11, §19.14: a stream limit above 2^60.
    StreamLimitTooLarge,
    /// RFC 9000 §19.15: a connection ID shorter than 1 octet or longer than 20.
    ConnectionIdLengthInvalid,
    /// RFC 9000 §19.15: a Retire Prior To above the frame's own Sequence Number.
    RetirePriorToTooLarge,
};

/// RFC 9000 §20.1: the transport error code every refusal above carries.
pub const frame_encoding_error: u64 = 0x07;

/// The code an endpoint closes the connection with when a frame is refused. Every value of
/// `Error` is one rule of RFC 9000 §19, and §19 names the same code for all of them.
pub fn connection_error_code(failure: Error) u64 {
    return switch (failure) {
        error.Truncated,
        error.TypeUnknown,
        error.AckRangeBelowZero,
        error.StreamOffsetTooLarge,
        error.TokenEmpty,
        error.StreamLimitTooLarge,
        error.ConnectionIdLengthInvalid,
        error.RetirePriorToTooLarge,
        => frame_encoding_error,
    };
}

/// Whether streams are bidirectional or unidirectional, which the low bit of a MAX_STREAMS or
/// STREAMS_BLOCKED type picks (RFC 9000 §19.11, §19.14).
pub const Directionality = enum { bidirectional, unidirectional };

/// Which layer a CONNECTION_CLOSE speaks for (RFC 9000 §19.19). A transport close carries the
/// frame type that caused it; an application close does not, because the application knows no
/// frame types.
pub const CloseLayer = enum { transport, application };

/// One frame. The payload of a packet is a sequence of these, read until the octets run out
/// (RFC 9000 §12.4).
pub const Frame = union(enum) {
    /// RFC 9000 §19.1: one octet of 0x00, and a run of them is still one frame to the reader.
    padding: struct { len: usize },
    ping,
    ack: Ack,
    reset_stream: struct { stream_id: u64, error_code: u64, final_size: u64 },
    stop_sending: struct { stream_id: u64, error_code: u64 },
    crypto: Crypto,
    new_token: struct { token: []const u8 },
    stream: Stream,
    max_data: struct { maximum: u64 },
    max_stream_data: struct { stream_id: u64, maximum: u64 },
    max_streams: struct { directionality: Directionality, maximum: u64 },
    data_blocked: struct { limit: u64 },
    stream_data_blocked: struct { stream_id: u64, limit: u64 },
    streams_blocked: struct { directionality: Directionality, limit: u64 },
    new_connection_id: frame_control.NewConnectionId,
    retire_connection_id: struct { sequence_number: u64 },
    path_challenge: struct { data: *const [constants.path_challenge_len]u8 },
    path_response: struct { data: *const [constants.path_challenge_len]u8 },
    connection_close: frame_control.ConnectionClose,
    handshake_done,

    /// Whether this frame may appear in a packet at `level` (RFC 9000 §12.4's Table 3, narrowed
    /// by §12.5). A frame that may not is a connection error of PROTOCOL_VIOLATION: §12.4 says
    /// "an endpoint MUST treat receipt of a frame in a packet type that is not permitted as a
    /// connection error of type PROTOCOL_VIOLATION".
    ///
    /// Table 3's Pkts column has four letters and colibri has three levels, because
    /// [decision 20](../../../docs/decisions.md) refuses 0-RTT. What is left is a short rule:
    /// §12.5 says "all other frame types MUST only be sent in the application data packet number
    /// space", so the Initial and Handshake levels admit five frames and the application level
    /// admits every one.
    pub fn permitted_at(frame: Frame, level: Level) bool {
        if (level == .application) return true;
        return switch (frame) {
            // Table 3 marks these IH01 and IH_1, so each is admitted at both handshake levels.
            .padding, .ping, .ack, .crypto => true,
            // §12.5: "CONNECTION_CLOSE frames signaling errors at the QUIC layer (type 0x1c) MAY
            // appear in any packet number space. CONNECTION_CLOSE frames signaling application
            // errors (type 0x1d) MUST only appear in the application data packet number space."
            // Table 3's "ih" is the same rule, which is why this reads the layer and not the type.
            .connection_close => |close| close.layer == .transport,
            else => false,
        };
    }

    /// Whether a packet carrying this frame is ack-eliciting (RFC 9000 §2 of [QUIC-RECOVERY],
    /// RFC 9000 §13.2.1). Everything but ACK, PADDING and CONNECTION_CLOSE elicits one.
    pub fn is_ack_eliciting(frame: Frame) bool {
        return switch (frame) {
            .padding, .ack, .connection_close => false,
            else => true,
        };
    }
};

/// Reads the frame at the reader's cursor, consuming all of it or none.
pub fn read(reader: *Reader) Error!Frame {
    var copy = reader.*;
    const frame = read_at(&copy) catch |failure| return failure;
    reader.* = copy;
    return frame;
}

fn read_at(reader: *Reader) Error!Frame {
    const frame_type = (wire.varint.decode(reader) catch return error.Truncated).value;
    if (frame_type >= constants.frame_stream_first and frame_type <= constants.frame_stream_last) {
        return .{ .stream = try frame_stream.read_stream(reader, frame_type) };
    }
    return switch (frame_type) {
        constants.frame_padding => .{ .padding = .{ .len = frame_stream.read_padding(reader) } },
        constants.frame_ping => .ping,
        constants.frame_ack, constants.frame_ack_ecn => .{ .ack = try frame_ack.read(reader, frame_type) },
        constants.frame_crypto => .{ .crypto = try frame_stream.read_crypto(reader) },
        constants.frame_new_token => .{ .new_token = .{ .token = try frame_stream.read_token(reader) } },
        else => frame_control.read(reader, frame_type),
    };
}

/// Writes `frame`, all of it or none.
pub fn write(writer: *Writer, frame: Frame) core.writer.Error!void {
    var copy = writer.*;
    try write_at(&copy, frame);
    writer.* = copy;
}

fn write_at(writer: *Writer, frame: Frame) core.writer.Error!void {
    switch (frame) {
        .padding => |padding| try frame_stream.write_padding(writer, padding.len),
        .ping => try write_type(writer, constants.frame_ping),
        .ack => |ack| try frame_ack.write(writer, ack),
        .crypto => |crypto| try frame_stream.write_crypto(writer, crypto),
        .new_token => |new_token| try frame_stream.write_token(writer, new_token.token),
        .stream => |stream| try frame_stream.write_stream(writer, stream),
        .handshake_done => try write_type(writer, constants.frame_handshake_done),
        else => try frame_control.write(writer, frame),
    }
}

/// Writes a frame type, which is a variable-length integer written in its shortest form: RFC 9000
/// §12.4 requires the Frame Type field to be encoded as minimally as possible, and §16 admits a
/// longer encoding everywhere else.
pub fn write_type(writer: *Writer, frame_type: u64) core.writer.Error!void {
    assert(frame_type <= constants.frame_handshake_done);
    try wire.varint.encode(writer, frame_type);
}

/// A variable-length integer field of a frame, which a short read makes a truncation.
pub fn read_varint(reader: *Reader) Error!u64 {
    return (wire.varint.decode(reader) catch return error.Truncated).value;
}

test {
    _ = frame_ack;
    _ = frame_stream;
    _ = frame_control;
    _ = @import("frame_test.zig");
}
