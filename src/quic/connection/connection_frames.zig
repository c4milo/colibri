//! The frames of one packet that opened (RFC 9000 §12.4), read and acted on.
//!
//! The walk sits between two rules that pull in opposite directions. §12.3 has a receiver
//! suppress a duplicate before it processes anything, which `connection_receive.zig` already did
//! by asking the space. §13.1 then forbids recording the packet for acknowledgment "until packet
//! protection has been successfully removed and all frames contained in the packet have been
//! processed", which is after this file finishes. So the caller asks first, walks here, and
//! records last; `report` is what it records with.
//!
//! **A frame at the wrong level is the peer's fault and closes the connection.** Everything
//! `connection_receive.zig` does is a discard, because nothing there is authentic yet. Here the
//! AEAD tag has matched, so §12.4's "an endpoint MUST treat receipt of a frame in a packet type
//! that is not permitted as a connection error of type PROTOCOL_VIOLATION" applies, and so does
//! every other rule §19 states.
//!
//! This file takes the frames that act on the connection. The ones that name a stream are
//! `connection_stream_frames.zig`'s, because they need the stream table and both levels of flow
//! control and this file would not stay inside 500 lines with them.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("../constants.zig");
const error_code = @import("../error_code.zig");
const frame_module = @import("../frame/frame.zig");
const space_module = @import("../space/space.zig");
const connection_module = @import("connection.zig");
const receive = @import("connection_receive.zig");
const key_update = @import("connection_key_update.zig");
const connection_crypto = @import("connection_crypto.zig");
const stream_frames = @import("connection_stream/connection_stream_frames.zig");
const path_frames = @import("connection_path_frames.zig");

const Level = core.Level;
const Reader = core.Reader;
const Frame = frame_module.Frame;
const Connection = connection_module.Connection;
const ConnectionClose = @import("../frame/frame_control.zig").ConnectionClose;

/// Why a packet's frames closed the connection. Each is a connection error, and
/// `connection_error_code` says which code the CONNECTION_CLOSE carries.
pub const Error = error{
    /// RFC 9000 §12.4: "An endpoint MUST treat receipt of a packet containing no frames as a
    /// connection error of type PROTOCOL_VIOLATION."
    EmptyPayload,
    /// RFC 9000 §12.4, §12.5: a frame Table 3 does not permit at this packet's level.
    FrameNotPermitted,
    /// RFC 9000 §19: the frame did not parse, or its type is one this version does not define.
    FrameEncoding,
    /// RFC 9000 §13.1: an ACK naming a packet this endpoint never sent.
    AcknowledgedUnsentPacket,
    /// RFC 9000 §19.20: a client sent a HANDSHAKE_DONE frame, which only a server may send.
    HandshakeDoneFromClient,
    /// RFC 9001 §6.2: an ACK carried in a packet protected with old keys named a packet this
    /// endpoint protected with newer ones, so the peer acknowledged a key update without
    /// answering it.
    OldKeysAcknowledgeNew,
    /// The handshake failed, and `connection_crypto.Error` says how.
    Crypto,
    /// A frame naming a stream broke a rule, and `connection_stream_frames.Error` says which.
    Stream,
    /// A frame about a connection ID or a path did, and `connection_path_frames.Error` says so.
    Path,
};

/// The code a CONNECTION_CLOSE carries for `failure` (RFC 9000 §20.1). `Crypto` is not among
/// them: its code is `connection_crypto`'s, which the caller already holds.
pub fn connection_error_code(failure: Error) u64 {
    return switch (failure) {
        // RFC 9000 §12.4 names PROTOCOL_VIOLATION for all three of these.
        error.EmptyPayload, error.FrameNotPermitted => error_code.protocol_violation,
        // RFC 9000 §19.20: "A server MUST treat receipt of a HANDSHAKE_DONE frame as a
        // connection error of type PROTOCOL_VIOLATION."
        error.HandshakeDoneFromClient => error_code.protocol_violation,
        // RFC 9000 §13.1: an acknowledgment of an unsent packet is a protocol violation.
        error.AcknowledgedUnsentPacket => error_code.protocol_violation,
        // RFC 9001 §6.7: KEY_UPDATE_ERROR "is used to signal errors related to key updates".
        error.OldKeysAcknowledgeNew => error_code.key_update_error,
        // RFC 9000 §12.4: "An endpoint MUST treat the receipt of a frame of unknown type as a
        // connection error of type FRAME_ENCODING_ERROR", which §19's own refusals share.
        error.FrameEncoding => error_code.frame_encoding_error,
        // RFC 9000 §11: an endpoint with no more specific code sends INTERNAL_ERROR. A stream
        // frame's own code is `connection_stream_frames.connection_error_code`'s, which the
        // caller reads instead, because §20.1 gives each of its rules a code of its own.
        error.Crypto, error.Stream, error.Path => error_code.internal_error,
    };
}

/// What the packet's frames amounted to, which is what the caller records with (RFC 9000 §13.1).
pub const Report = struct {
    /// RFC 9000 §13.2.1: whether any frame in the packet obliges an acknowledgment.
    ack_eliciting: bool,
    /// How many frames were read, which a check reads and nothing else acts on.
    frames: usize,
    /// The peer's CONNECTION_CLOSE, when it sent one (RFC 9000 §19.19).
    close: ?Close,
    /// What the packet left for the send path to answer (RFC 9000 §8.2.2, §19.7).
    owed: path_frames.Owed,
    /// Whether the packet carried a HANDSHAKE_DONE frame, which confirms the handshake at a
    /// client (RFC 9001 §4.1.2). The caller then discards the Handshake keys, which RFC 9001
    /// §4.9.2 requires and which takes the suite this function is not given
    /// (`connection_keys.on_handshake_confirmed`).
    handshake_done: bool = false,
};

/// What a peer's CONNECTION_CLOSE said. The connection ends; the caller decides what to tell the
/// application, because §20 gives a transport code and an application code different meanings.
pub const Close = struct {
    layer: frame_module.CloseLayer,
    error_code: u64,
};

/// Reads every frame of one opened packet and acts on it.
///
/// `payload` is the plaintext `crypto.Suite.open` left in place. Nothing here discards: the tag
/// has matched, so a rule broken from this point is the peer's and closes the connection.
pub fn process(connection: *Connection, opened: receive.Opened, now_ns: u64) Error!Report {
    const level = opened.level;
    // RFC 9000 §12.4: "The payload of a packet that contains frames MUST contain at least one
    // frame", and a packet with none is a connection error.
    if (opened.payload.len == 0) return Error.EmptyPayload;
    var reader = Reader.init(opened.payload);
    var report: Report = .{ .ack_eliciting = false, .frames = 0, .close = null, .owed = .{} };
    // Bounded by the frames one packet can hold, which is its octets: §19.1 makes PADDING one
    // octet and no frame is shorter.
    while (report.frames < constants.frames_per_packet_max) {
        if (reader.remaining_len() == 0) break;
        const frame = frame_module.read(&reader) catch return Error.FrameEncoding;
        // RFC 9000 §12.4: a frame in a packet type that does not permit it is a connection error
        // of PROTOCOL_VIOLATION, which §12.5 spells out per level.
        if (!frame.permitted_at(level)) return Error.FrameNotPermitted;
        report.frames += 1;
        if (frame.is_ack_eliciting()) report.ack_eliciting = true;
        try apply(connection, opened, frame, now_ns, &report);
    }
    // A payload that held only octets no frame could be read from would have failed above, so
    // reaching here with nothing read means the payload was frames of zero length, which §19.1
    // does not define.
    assert(report.frames > 0);
    return report;
}

/// Acts on one frame. The arms are the frames that act on the connection; a frame naming a
/// stream is `connection_stream_frames.zig`'s and reaches it through `stream_frame`.
fn apply(connection: *Connection, opened: receive.Opened, frame: Frame, now_ns: u64, report: *Report) Error!void {
    switch (frame) {
        // RFC 9000 §19.1, §19.2: PADDING has no semantics and PING exists to elicit an
        // acknowledgment, which `is_ack_eliciting` already recorded.
        .padding, .ping => {},
        .ack => |ack| try take_ack(connection, opened, ack, now_ns),
        .crypto => |crypto| connection_crypto.receive_crypto(connection, opened.level, crypto) catch
            return Error.Crypto,
        .connection_close => |close| take_close(connection, close, now_ns, report),
        .handshake_done => {
            try take_handshake_done(connection);
            report.handshake_done = true;
        },
        // RFC 9000 §19.9: MAX_DATA raises what this endpoint may send on the connection, and
        // §4.1 makes a smaller value one to ignore rather than an error.
        .max_data => |max| _ = connection.send_flow.raise(max.maximum),
        // RFC 9000 §19.12: DATA_BLOCKED says the peer wants to send and cannot. It is a signal
        // for tuning and obliges nothing, so colibri records nothing from it.
        .data_blocked => {},
        // RFC 9000 §19.4 to §19.14: the frames that name a stream, which need the stream table
        // and both levels of flow control, so they live in their own file.
        .stream, .reset_stream, .stop_sending, .max_stream_data, .max_streams, .stream_data_blocked, .streams_blocked => stream_frames.apply(connection, frame) catch
            return Error.Stream,
        // RFC 9000 §19.7, §19.15 to §19.18: NEW_TOKEN, the connection ID frames and the path
        // frames, which act on what the connection holds once rather than on a stream.
        else => path_frames.apply(connection, frame, opened.addressed_to, &report.owed) catch return Error.Path,
    }
}

/// RFC 9000 §13.1 and §13.2: what a peer's ACK frame says about packets this endpoint sent.
fn take_ack(connection: *Connection, opened: receive.Opened, ack: frame_module.Ack, now_ns: u64) Error!void {
    // RFC 9001 §6.2: "An endpoint that receives an acknowledgment that is carried in a packet
    // protected with old keys where any acknowledged packet was protected with newer keys MAY
    // treat that as a connection error of type KEY_UPDATE_ERROR."
    if (key_update.acknowledges_newer_keys(connection, opened.key_set, ack.ranges.largest_acknowledged)) {
        return Error.OldKeysAcknowledgeNew;
    }
    _ = connection.space_at(opened.level).on_ack(ack) catch |failure| switch (failure) {
        // RFC 9000 §13.1: "if a packet is acknowledged that was never sent, this is a connection
        // error of type PROTOCOL_VIOLATION."
        error.AcknowledgedUnsentPacket => return Error.AcknowledgedUnsentPacket,
    };
    // RFC 9001 §6.5 waits three Probe Timeouts from "an acknowledgment that confirms that the
    // previous key update was received", which is this frame when it names the current phase.
    key_update.on_ack_processed(connection, opened.level, now_ns);
}

/// RFC 9000 §10.2.2: an endpoint that receives a CONNECTION_CLOSE enters the draining state and
/// sends nothing further on the connection.
fn take_close(connection: *Connection, close: ConnectionClose, now_ns: u64, report: *Report) void {
    report.close = .{ .layer = close.layer, .error_code = close.error_code };
    // §10.2: the draining period is three times the Probe Timeout. RFC 9002 §6.2.1 includes the
    // peer's max_ack_delay once the application level is in use, which it is by the time either
    // side closes deliberately, and an endpoint with no round trip sample still has the floor.
    const probe_timeout_ns = connection.recovery.rtt.probe_timeout_ns(true);
    connection.termination.on_close_received(now_ns, probe_timeout_ns);
}

/// RFC 9001 §4.1.2: a HANDSHAKE_DONE frame is what confirms the handshake for a client.
fn take_handshake_done(connection: *Connection) Error!void {
    // RFC 9000 §19.20: "A server MUST treat receipt of a HANDSHAKE_DONE frame as a connection
    // error of type PROTOCOL_VIOLATION", because only a server sends one.
    if (connection.role == .server) return Error.HandshakeDoneFromClient;
    connection.confirm_handshake();
}

test {
    _ = @import("connection_frames_test.zig");
}
