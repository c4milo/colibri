//! The frames one packet carries, written into the caller's scratch before anything is sealed.
//! Split off `packet_build.zig` for length; `plan` is what calls it, once per packet.
//!
//! The set is small on purpose: an ACK when the space owes one (RFC 9000 §13.2.1), the path
//! frames §8.2 leaves owed, and whatever handshake octets the provider owes at this level
//! (RFC 9001 §4.1.3). Every other frame is written by the piece that owns it, which is what
//! RFC 9000 §13.3 asks for — "the information that might be carried in frames is sent again in
//! new frames as needed", by whoever holds the information.
const std = @import("std");
const core = @import("core");
const tls = @import("tls");
const constants = @import("../../constants.zig");
const frame_module = @import("../../frame/frame.zig");
const connection_module = @import("../connection.zig");
const connection_crypto = @import("../connection_crypto.zig");
const connection_close = @import("../connection_close.zig");

const Level = core.Level;
const Writer = core.Writer;
const Connection = connection_module.Connection;
const Error = @import("packet_build.zig").Error;
const Carries = @import("../../recovery/recovery_sent.zig").Carries;

/// What went into the payload.
pub const Framed = struct {
    len: usize,
    ack_eliciting: bool,
    carries_close: bool = false,
    carries_ack: bool = false,
    path_challenge: ?[constants.path_challenge_len]u8 = null,
    carries_path_response: bool = false,
    /// RFC 9000 §13.3: which octets this packet carries and where they sit in their flow, so a
    /// lost packet can say which to send again (`recovery_sent.Record`).
    carries: Carries = .none,
    data_offset: u64 = 0,
    data_len: u16 = 0,
};

/// Writes the frames this packet carries. The set is small on purpose: an ACK when the space owes
/// one (RFC 9000 §13.2.1) and whatever handshake octets the provider owes at this level
/// (RFC 9001 §4.1.3). Every other frame is written by the piece that owns it.
pub fn write(
    connection: *Connection,
    provider: tls.QuicProvider,
    space: anytype,
    level: Level,
    payload: []u8,
    room: usize,
    now_ns: u64,
) Error!Framed {
    const budget = @min(room, payload.len);
    // RFC 9000 §10.2.1: a closing endpoint "retains only enough information to generate a packet
    // containing a CONNECTION_CLOSE frame", so once one is owed it is the only frame written.
    // Nothing else would be read: §10.2.2 puts the peer into the draining state on reading it.
    if (connection_close.owes(connection)) {
        const close_len = connection_close.write(connection, level, payload[0..budget]);
        // §13.2.1, Table 3's N marking: a CONNECTION_CLOSE elicits no acknowledgment, because
        // there is no longer a connection to acknowledge it on.
        return .{ .len = close_len, .ack_eliciting = false, .carries_close = close_len > 0 };
    }
    var writer = Writer.init(payload[0..budget]);
    // RFC 9000 §13.2.1: an ACK goes first because it is the frame a space owes soonest, and
    // §13.2 makes acknowledging cheap enough that it is never worth holding back.
    if (space.owes_ack(now_ns, connection.max_ack_delay_ns())) {
        _ = space.write_ack(&writer, now_ns, exponent_of(connection), report_ecn) catch {};
    }
    const written_ack = writer.written().len;
    // RFC 9000 §8.2: the path frames go next. §8.2.2 says an endpoint "MUST NOT delay
    // transmission of a packet containing a PATH_RESPONSE frame unless constrained by congestion
    // control", so they are written before the handshake's octets compete for the room.
    const path = write_path_frames(connection, level, &writer);
    const written_path = writer.written().len;
    // RFC 9001 §4.1.3: the handshake's octets, which `connection_crypto` puts in CRYPTO frames.
    const written_crypto = connection_crypto.write_crypto(connection, provider, level, payload[written_path..budget]) catch
        return Error.Crypto;
    const crypto_len = written_crypto.len;
    return .{
        .len = written_path + crypto_len,
        .carries = if (crypto_len > 0) .crypto else .none,
        .data_offset = written_crypto.offset,
        .data_len = written_crypto.payload_len,
        // RFC 9000 §13.2.1, Table 3's N marking: an ACK elicits nothing and a CRYPTO frame does.
        // Table 3 marks PATH_CHALLENGE and PATH_RESPONSE as eliciting one.
        .ack_eliciting = crypto_len > 0 or path.carries_path_response or path.path_challenge != null,
        .carries_ack = written_ack > 0,
        .path_challenge = path.path_challenge,
        .carries_path_response = path.carries_path_response,
    };
}

/// What the path frames amount to in one packet.
const PathFrames = struct {
    path_challenge: ?[constants.path_challenge_len]u8 = null,
    carries_path_response: bool = false,
};

/// Writes the PATH_RESPONSE this endpoint owes and the PATH_CHALLENGE it means to send, when
/// there is room for each (RFC 9000 §8.2.1, §8.2.2). A frame that does not fit is left owed, so
/// the next packet carries it.
///
/// §12.5's Table 3 permits neither below the application level, so nothing is written there.
fn write_path_frames(connection: *Connection, level: Level, writer: *Writer) PathFrames {
    if (level != .application) return .{};
    var held: PathFrames = .{};
    if (connection.path.response_owed) |data| {
        frame_module.write(writer, .{ .path_response = .{ .data = &data } }) catch return held;
        _ = connection.path.take_response_owed();
        held.carries_path_response = true;
    }
    if (connection.path.challenge_owed) |data| {
        // §8.2.1: "an endpoint SHOULD NOT send multiple PATH_CHALLENGE frames in a single
        // packet", and colibri holds one, so one is what goes out.
        frame_module.write(writer, .{ .path_challenge = .{ .data = &data } }) catch return held;
        _ = connection.path.take_challenge_owed();
        held.path_challenge = data;
    }
    return held;
}

/// RFC 9000 §18.2: the exponent this endpoint advertised, which its own parameters hold.
fn exponent_of(connection: *const Connection) u6 {
    return @intCast(connection.local_parameters.ack_delay_exponent);
}

/// RFC 9000 §13.4.1 leaves reporting ECN counts to an endpoint that can read the codepoints.
/// colibri owns no socket (non-negotiable 1), so it reports none until a caller says it can.
const report_ecn = false;
