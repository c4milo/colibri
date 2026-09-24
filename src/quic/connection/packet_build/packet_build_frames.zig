//! The frames one packet carries, written into the caller's scratch before anything is sealed.
//! Split off `packet_build.zig` for length; `plan` is what calls it, once per packet.
//!
//! This file decides the order frames compete in for one packet's room. Each frame is written by
//! the piece that holds its information, which is what RFC 9000 §13.3 asks for: "the information
//! that might be carried in frames is sent again in new frames as needed". The order, and why:
//!
//! 1. A CONNECTION_CLOSE, alone, when one is owed (§10.2.1).
//! 2. An ACK, when owed, and when the space has new ack-eliciting packets and anything else goes
//!    out with it (§13.2.1). It goes first because a space owes it soonest.
//! 3. PATH_RESPONSE and PATH_CHALLENGE, which §8.2.2 says an endpoint "MUST NOT delay".
//! 4. HANDSHAKE_DONE, which a server sends "as soon as the handshake is complete" (RFC 9001
//!    §4.1.2).
//! 5. The limits this endpoint gives, then the BLOCKED frames, then RESET_STREAM and
//!    STOP_SENDING, then NEW_CONNECTION_ID and RETIRE_CONNECTION_ID: small frames a peer may be
//!    waiting on, ahead of any octets.
//! 6. One frame of octets: the handshake's CRYPTO octets, or a stream's. Lost stream octets go
//!    before new ones (§13.3), and new ones go in the order RFC 9000 §2.3 sets.
//! 7. A PING, when a probe is owed and nothing above elicits an acknowledgment (RFC 9002 §6.2.4).
//!
//! A packet the congestion window holds back carries the first two alone (`Room.in_flight_allowed`).
const std = @import("std");
const core = @import("core");
const tls = @import("tls");
const constants = @import("../../constants.zig");
const frame_module = @import("../../frame/frame.zig");
const connection_module = @import("../connection.zig");
const connection_crypto = @import("../connection_crypto.zig");
const connection_stream_send = @import("../connection_stream/connection_stream_send.zig");
const StreamProvider = @import("../../stream/stream_provider.zig").StreamProvider;
const connection_close = @import("../connection_close.zig");
const connection_handshake = @import("../connection_handshake.zig");
const connection_flow = @import("../connection_flow.zig");
const connection_id_frames = @import("../connection_id_frames.zig");

const Level = core.Level;
const Writer = core.Writer;
const Connection = connection_module.Connection;
const Error = @import("packet_build.zig").Error;
const Carries = @import("../../recovery/recovery_sent.zig").Carries;

/// What one packet may hold. RFC 9002 §7 bounds the octets in flight by the congestion window,
/// and §2 counts a packet of ACK frames alone as not in flight, so an endpoint the window holds
/// back still acknowledges.
pub const Room = struct {
    /// Octets of the datagram the packet may occupy.
    len: usize,
    /// Whether the packet may count toward the bytes in flight. False admits only ACK and
    /// CONNECTION_CLOSE, neither of which elicits an acknowledgment (§2).
    in_flight_allowed: bool = true,
    /// Whether the packet carries probing frames alone (RFC 9000 §9.1), as a packet to the
    /// previously active path does: §9.3 sends every other frame to the peer's new address.
    probing_only: bool = false,
};

/// What went into the payload.
pub const Framed = struct {
    len: usize,
    ack_eliciting: bool,
    carries_close: bool = false,
    carries_ack: bool = false,
    path_challenge: ?[constants.path_challenge_len]u8 = null,
    carries_path_response: bool = false,
    /// Whether it carries a HANDSHAKE_DONE frame, whose packet number §13.3 needs.
    carries_handshake_done: bool = false,
    /// RFC 9000 §13.3: which octets this packet carries and where they sit in their flow, so a
    /// lost packet can say which to send again (`recovery_sent.Record`).
    carries: Carries = .none,
    data_offset: u64 = 0,
    data_len: u16 = 0,
    stream_id: u64 = 0,
};

/// Writes the frames this packet carries, in the order this file's header gives. `number` is the
/// packet's, which the frames §13.3 sends again record.
pub fn write(
    connection: *Connection,
    provider: tls.QuicProvider,
    stream_provider: StreamProvider,
    space: anytype,
    level: Level,
    number: u64,
    payload: []u8,
    room: Room,
    now_ns: u64,
) Error!Framed {
    const budget = @min(room.len, payload.len);
    // RFC 9000 §10.2.1: a closing endpoint "retains only enough information to generate a packet
    // containing a CONNECTION_CLOSE frame", so once one is owed it is the only frame written.
    // Nothing else would be read: §10.2.2 puts the peer into the draining state on reading it.
    if (connection_close.owes(connection)) {
        const close_len = connection_close.write(connection, level, payload[0..budget]);
        // §13.2.1, Table 3's N marking: a CONNECTION_CLOSE elicits no acknowledgment, because
        // there is no longer a connection to acknowledge it on.
        return .{ .len = close_len, .ack_eliciting = false, .carries_close = close_len > 0 };
    }
    if (room.probing_only) return probing_packet(connection, level, payload[0..budget]);
    var writer = Writer.init(payload[0..budget]);
    const ack = write_ack(connection, space, &writer, now_ns);
    const written_ack = writer.written().len;
    // RFC 9002 §7: "An endpoint MUST NOT send a packet if it would cause bytes_in_flight ... to
    // be larger than the congestion window", and a packet of ACK frames alone adds nothing (§2).
    if (!room.in_flight_allowed) return acknowledgment_only(space, ack, written_ack);
    // RFC 9000 §8.2: the path frames go next. §8.2.2 says an endpoint "MUST NOT delay
    // transmission of a packet containing a PATH_RESPONSE frame unless constrained by congestion
    // control", so they are written before the handshake's octets compete for the room.
    const path = write_path_frames(connection, level, &writer);
    // RFC 9001 §4.1.2: "The server MUST send a HANDSHAKE_DONE frame as soon as the handshake is
    // complete", so it goes before any octets compete for the room.
    const carries_handshake_done = connection_handshake.write_done(connection, level, &writer);
    // RFC 9000 §4.2: the limits the peer may use, before any octets compete for the room, so a
    // peer waiting on credit is not kept waiting by this endpoint's own data.
    var carries_control = connection_flow.write_limits(connection, level, &writer, number, now_ns);
    // RFC 9000 §4.1, §4.6: what the peer's limits hold back, after the limits this endpoint gives.
    if (connection_flow.write_blocked(connection, level, &writer, number)) carries_control = true;
    // RFC 9000 §19.4, §19.5: the streams this endpoint ends, before any stream's octets.
    if (connection_stream_send.write_endings(connection, level, &writer, number)) carries_control = true;
    // RFC 9000 §19.15, §19.16: the connection IDs this endpoint gives and retires.
    if (connection_id_frames.write(connection, level, &writer, number)) carries_control = true;
    const written_path = writer.written().len;
    const data = try write_data(connection, provider, stream_provider, level, payload[written_path..budget]);
    // RFC 9000 §13.2.1, Table 3's N marking: an ACK elicits nothing, and a CRYPTO or STREAM
    // frame does. Table 3 marks PATH_CHALLENGE and PATH_RESPONSE as eliciting one.
    const eliciting = data.len > 0 or path.carries_path_response or path.path_challenge != null or
        carries_handshake_done or carries_control;
    const framed_len = written_path + data.len;
    const probe_len = write_probe(connection, level, payload[framed_len..budget], eliciting);
    // RFC 9000 §13.2.1 asks for an ACK "with other frames": one written only because it was
    // pending, with nothing after it, does not go out, and the space is as it was.
    if (!ack.owed and written_ack > 0 and framed_len + probe_len == written_ack) {
        space.restore_ack_pending(ack.pending);
        return .{ .len = 0, .ack_eliciting = false };
    }
    const ack_eliciting = eliciting or probe_len > 0;
    count_probe(connection, level, ack_eliciting);
    return .{
        .len = framed_len + probe_len,
        .carries = data.carries,
        .data_offset = data.offset,
        .data_len = data.data_len,
        .stream_id = data.stream_id,
        .ack_eliciting = ack_eliciting,
        .carries_handshake_done = carries_handshake_done,
        .carries_ack = written_ack > 0,
        .path_challenge = path.path_challenge,
        .carries_path_response = path.carries_path_response,
    };
}

/// A packet of the path frames alone, which RFC 9000 §9.1 counts as probing frames.
fn probing_packet(connection: *Connection, level: Level, payload: []u8) Framed {
    var writer = Writer.init(payload);
    const path = write_path_frames(connection, level, &writer);
    return .{
        .len = writer.written().len,
        // RFC 9000 §13.2.1, Table 3: PATH_CHALLENGE and PATH_RESPONSE elicit an acknowledgment.
        .ack_eliciting = path.path_challenge != null or path.carries_path_response,
        .path_challenge = path.path_challenge,
        .carries_path_response = path.carries_path_response,
    };
}

/// The packet `write` builds when nothing in flight may go: an ACK the space owes, or nothing.
/// One written only because it was pending is taken back, as `write` does (§13.2.1).
fn acknowledgment_only(space: anytype, ack: AckWritten, written_ack: usize) Framed {
    if (ack.owed) return .{ .len = written_ack, .ack_eliciting = false, .carries_ack = written_ack > 0 };
    if (written_ack > 0) space.restore_ack_pending(ack.pending);
    return .{ .len = 0, .ack_eliciting = false };
}

/// Writes a PING when a probe is owed at `level` and nothing already written elicits an
/// acknowledgment. RFC 9002 §6.2.4: "When there is no data to send, the sender SHOULD send a PING
/// or other ack-eliciting frame in a single packet". Returns the octets written.
fn write_probe(connection: *const Connection, level: Level, output: []u8, eliciting: bool) usize {
    if (connection.probes_owed[@intFromEnum(level)] == 0 or eliciting) return 0;
    var writer = Writer.init(output);
    frame_module.write(&writer, .ping) catch return 0;
    return writer.written().len;
}

/// Counts off one probe for an ack-eliciting packet at `level` (RFC 9002 §6.2.4: "All probe
/// packets sent on a PTO MUST be ack-eliciting").
fn count_probe(connection: *Connection, level: Level, ack_eliciting: bool) void {
    const owed = &connection.probes_owed[@intFromEnum(level)];
    if (owed.* > 0 and ack_eliciting) owed.* -= 1;
}

/// The one CRYPTO or STREAM frame a packet carries, and the range its record keeps.
const DataFrame = struct {
    len: usize = 0,
    carries: Carries = .none,
    offset: u64 = 0,
    data_len: u16 = 0,
    stream_id: u64 = 0,
};

/// Writes the handshake's octets when the provider owes some at this level, and a stream's
/// otherwise. Never both: a packet's record holds one range (decisions 56 and 57).
fn write_data(
    connection: *Connection,
    provider: tls.QuicProvider,
    stream_provider: StreamProvider,
    level: Level,
    output: []u8,
) Error!DataFrame {
    // RFC 9001 §4.1.3: the handshake's octets, which `connection_crypto` puts in CRYPTO frames.
    const crypto = connection_crypto.write_crypto(connection, provider, level, output) catch
        return Error.Crypto;
    if (crypto.len > 0) {
        return .{ .len = crypto.len, .carries = .crypto, .offset = crypto.offset, .data_len = crypto.payload_len };
    }
    // RFC 9000 §12.4, Table 3: STREAM frames travel in 0-RTT and 1-RTT packets alone, and
    // decision 20 refuses 0-RTT.
    if (level != .application) return .{};
    const stream = connection_stream_send.write(connection, stream_provider, output);
    if (stream.len == 0) return .{};
    return .{
        .len = stream.len,
        .carries = if (stream.fin) .stream_fin else .stream,
        .offset = stream.offset,
        .data_len = stream.data_len,
        .stream_id = stream.stream_id,
    };
}

/// What `write_ack` did, so `write` can take back an ACK nothing else went out with.
const AckWritten = struct {
    owed: bool,
    pending: @import("../../space/space.zig").Space.AckPending,
};

/// Writes an ACK when the space owes one (RFC 9000 §13.2.1, §13.2.2), and when it has new
/// ack-eliciting packets to acknowledge, which §13.2.1 asks for "with other frames": whether any
/// follow is known only once they are written, so `write` takes back one that stood alone. It
/// goes first because it is the frame a space owes soonest.
fn write_ack(connection: *const Connection, space: anytype, writer: *Writer, now_ns: u64) AckWritten {
    const held: AckWritten = .{ .owed = space.owes_ack(now_ns, connection.max_ack_delay_ns()), .pending = space.ack_pending() };
    if (!held.owed and !space.has_new_ack_eliciting()) return held;
    // RFC 9000 §13.4.1: only an endpoint with "access to received ECN codepoints" reports ECN,
    // and decision 68 has the caller say whether it has.
    _ = space.write_ack(writer, now_ns, exponent_of(connection), connection.ecn_reads) catch {};
    return held;
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
