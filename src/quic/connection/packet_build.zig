//! One QUIC packet, framed and sealed into a slice of the caller's datagram buffer.
//!
//! **It builds a packet, not a datagram.** RFC 9000 §12.2's coalescing, §14.1's expansion to
//! 1,200 octets and §8's anti-amplification limit are all about a datagram, and none of them is
//! here; the piece that assembles a datagram calls this once per packet. Nothing here tells
//! RFC 9002's recovery anything either: it reports what it built and the caller records it.
//!
//! **The header is final before the payload is framed, which sounds backwards.** RFC 9001 §5.3
//! makes the unprotected header the AEAD's associated data, so it cannot change after `seal`;
//! and RFC 9000 §17.2's Length counts the Packet Number and Payload, so it cannot be known
//! before framing. RFC 9000 §16 is the way out: outside the Frame Type field a variable-length
//! integer "need not be encoded on the minimum number of bytes necessary", so the Length field's
//! width is fixed up front from the most this packet could carry, the payload is framed once
//! against the budget that leaves, and the header is written once with the true value.
//!
//! **A tiny packet widens its packet number rather than padding.** RFC 9001 §5.4.2 wants the
//! packet number and payload to reach four octets together so header protection has a sample.
//! [Decision 54](../../../docs/decisions.md) meets that by widening, because RFC 9002 §2 counts
//! a packet carrying PADDING as in flight and a bare PING should not cost congestion window.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const crypto = @import("crypto");
const tls = @import("tls");
const wire = @import("wire");
const constants = @import("../constants.zig");
const frame_module = @import("../frame/frame.zig");
const header_write = @import("../packet/packet_header_write.zig");
const packet_number = @import("../packet/packet_number.zig");
const connection_module = @import("connection.zig");
const connection_crypto = @import("connection_crypto.zig");
const connection_close = @import("connection_close.zig");
const error_code = @import("../error_code.zig");
const keys_module = @import("connection_keys.zig");
const key_update = @import("connection_key_update.zig");
const recovery_sent = @import("../recovery/recovery_sent.zig");

const Level = core.Level;
const Writer = core.Writer;
const Connection = connection_module.Connection;

/// Where one packet is framed before it is sealed. `crypto.Sealing` says every slice is colibri's
/// and none overlaps the output, so the frames cannot be written at their final offset in the
/// datagram. The caller places this (decision 35) and `capacity` is how large a packet it admits;
/// decision 54 makes RFC 9000 §14.1's smallest allowed maximum datagram the default.
pub fn Scratch(comptime capacity: usize) type {
    comptime assert(capacity >= constants.protected_len_min);
    return struct {
        header: [constants.packet_header_len_max]u8 = undefined,
        payload: [capacity]u8 = undefined,

        /// How many octets of frames a packet built with this scratch can hold.
        pub const payload_len_max: usize = capacity;
    };
}

/// The scratch a caller gets by asking for no size in particular.
pub const DefaultScratch = Scratch(constants.datagram_len_min);

/// Why a packet was not built. Neither is the peer's doing.
pub const Error = error{
    /// The output cannot hold a packet at all, which is the caller offering too small a slice.
    NoSpaceLeft,
    /// RFC 9000 §12.3: this space has used every packet number, and §12.3 has the connection
    /// close rather than reuse one (invariant 17).
    PacketNumbersExhausted,
    /// The handshake failed while its octets were being written.
    Crypto,
    /// RFC 9001 §6.6: the keys have protected as many packets as the AEAD's confidentiality limit
    /// permits and no key update could free them, so the connection stops.
    AeadLimitReached,
};

/// The code a CONNECTION_CLOSE carries for `failure`, or null when no frame goes out.
pub fn connection_error_code(failure: Error) ?u64 {
    return switch (failure) {
        // RFC 9001 §6.6: "It is RECOMMENDED that endpoints immediately close the connection with
        // a connection error of type AEAD_LIMIT_REACHED before reaching a state where key updates
        // are not possible."
        error.AeadLimitReached => error_code.aead_limit_reached,
        // RFC 9000 §12.3: "If the packet number for sending reaches 2^62-1, the sender MUST close
        // the connection without sending a CONNECTION_CLOSE frame or any further packets."
        error.PacketNumbersExhausted => null,
        // Neither of these is a connection error: the caller offered a slice too small for a
        // packet, and a failed handshake carries `connection_crypto`'s own code.
        error.NoSpaceLeft, error.Crypto => null,
    };
}

/// What was built, which is what the caller tells RFC 9002's recovery.
pub const Built = struct {
    level: Level,
    packet_number: u64,
    /// Octets of `output` the packet occupies.
    len: usize,
    /// RFC 9002 §2: whether the peer must acknowledge it.
    ack_eliciting: bool,
    /// RFC 9002 §2, via `recovery_sent.counts_in_flight`.
    in_flight: bool,
};

/// One packet framed but not yet protected. RFC 9000 §14.1's expansion has to be decided before
/// `seal`, because the AEAD covers the payload and nothing may be appended after: so a datagram
/// that must reach 1,200 octets plans its packets first, learns which is last, and seals then.
pub const Planned = struct {
    level: Level,
    number: u64,
    truncated: packet_number.Truncated,
    payload_len: usize,
    ack_eliciting: bool,
    shape: Shape,
    /// Octets of PADDING added to reach RFC 9000 §14.1's size, which RFC 9002 §2 makes the packet
    /// count in flight whether or not anything in it elicits an acknowledgment.
    padding_len: usize = 0,
    /// Whether this packet carries a CONNECTION_CLOSE frame (RFC 9000 §10.2.3), which is what
    /// puts the connection into §10.2.1's closing state once the datagram goes out.
    carries_close: bool = false,
    /// Whether this packet carries an ACK frame (RFC 9000 §19.3). RFC 9001 §6.2 completes a key
    /// update on the first packet under the new keys that acknowledges the one that started it.
    carries_ack: bool = false,
    /// The PATH_CHALLENGE this packet carries, or null when it carries none (RFC 9000 §8.2.1).
    /// The datagram's length decides whether the path MTU is validated, so the octets travel this
    /// far and `Path.on_challenge_sent` takes them once the datagram exists.
    path_challenge: ?[constants.path_challenge_len]u8 = null,
    /// Whether this packet carries a PATH_RESPONSE (RFC 9000 §8.2.2), which §8.2.2 expands the
    /// datagram for just as §8.2.1 does for a challenge.
    carries_path_response: bool = false,
};

/// Frames one packet at `level` without protecting it. Null when there is nothing to send there,
/// which is the ordinary answer for two of the three levels most of the time.
pub fn plan(
    connection: *Connection,
    provider: tls.QuicProvider,
    level: Level,
    payload: []u8,
    room: usize,
    now_ns: u64,
) Error!?Planned {
    // RFC 9001 §4.9 and invariant 21: a level colibri never installed or already discarded is not
    // one to seal at, and §4.9.1 makes sending an Initial after the discard a rule broken.
    if (!keys_module.can_seal(connection, level)) return null;
    const space = connection.space_at(level);
    // RFC 9000 §17.1, Appendix A.2: the width is measured against the largest acknowledged in
    // this space and no other. It is settled before framing because it sizes the header.
    const number = space.peek_number() catch return Error.PacketNumbersExhausted;
    const truncated = packet_number.encode(number, space.largest_acknowledged) catch
        return Error.PacketNumbersExhausted;

    const shape = try shape_of(connection, level, truncated.len, room);
    const framed = try frame_payload(connection, provider, space, level, payload, shape.room, now_ns);
    if (framed.len == 0) return null;
    // The number is spent only once the packet exists, so a level with nothing to send leaves
    // no hole in its space (invariant 17).
    _ = space.next_number() catch unreachable;
    return .{
        .level = level,
        .number = number,
        // RFC 9001 §5.4.2, decision 54: the packet number and payload must reach four octets so
        // header protection has a sample, and a short packet widens the number to get there.
        .truncated = widen_for_sample(number, truncated, framed.len),
        .payload_len = framed.len,
        .ack_eliciting = framed.ack_eliciting,
        .shape = shape,
        .carries_close = framed.carries_close,
        .carries_ack = framed.carries_ack,
        .path_challenge = framed.path_challenge,
        .carries_path_response = framed.carries_path_response,
    };
}

/// Builds one packet at `level` into the front of `output`, planning and sealing in one step.
/// A caller assembling a datagram plans every packet first, because RFC 9000 §14.1's expansion
/// is not a thing that can be added after `seal`.
pub fn build(
    connection: *Connection,
    suite: crypto.Suite,
    provider: tls.QuicProvider,
    level: Level,
    scratch: anytype,
    output: []u8,
    now_ns: u64,
) Error!?Built {
    const budget = @min(output.len, @TypeOf(scratch.*).payload_len_max);
    const planned = try plan(connection, provider, level, &scratch.payload, output.len, now_ns) orelse return null;
    _ = budget;
    return try seal_planned(connection, suite, planned, &scratch.header, &scratch.payload, output);
}

/// What the header costs before its payload, and what that leaves for frames.
pub const Shape = struct {
    /// Octets the Length field is written in, fixed before the payload exists (RFC 9000 §16).
    length_len: u8,
    /// Octets of the header, which is everything before the payload (RFC 9000 §17.2, §17.3).
    header_len: usize,
    /// Octets of frames this packet may carry.
    room: usize,
};

fn shape_of(connection: *Connection, level: Level, packet_number_len: u8, output_len: usize) Error!Shape {
    const fixed = fixed_header_len(connection, level, packet_number_len);
    // RFC 9001 §5.3: the tag follows the payload and the Length counts it, so a packet needs room
    // for a header, the shortest legal payload and the tag before it is worth building.
    const overhead = fixed + constants.aead_tag_len;
    if (output_len <= overhead + 1) return Error.NoSpaceLeft;
    // RFC 9000 §16: the Length may be written wider than minimal, so its width is chosen from the
    // largest value this packet could carry and never has to change once the payload is framed.
    const largest_length = output_len - overhead;
    const length_len = if (level == .application) 0 else wire.varint.encoded_len_minimal(largest_length);
    const header = fixed + length_len;
    if (output_len <= header + constants.aead_tag_len) return Error.NoSpaceLeft;
    return .{ .length_len = length_len, .header_len = header, .room = output_len - header - constants.aead_tag_len };
}

/// The header's octets other than its Length field (RFC 9000 §17.2, §17.3).
fn fixed_header_len(connection: *Connection, level: Level, packet_number_len: u8) usize {
    const identity = &connection.identity;
    // RFC 9000 §17.3: a short header is byte 0, the Destination Connection ID and the number.
    if (level == .application) return 1 + identity.destination().len + packet_number_len;
    const destination = identity.destination().len;
    const source = identity.source().len;
    // §17.2: byte 0, the Version, both connection IDs with their length octets, and the number.
    var len: usize = 1 + @sizeOf(u32) + 1 + destination + 1 + source + packet_number_len;
    // §17.2.2: an Initial packet alone carries a Token Length and a Token, which §8.1.2 makes
    // the Retry token once one has arrived and a zero-length field until then.
    if (level == .initial) {
        const token_len = connection.retry_token.len;
        len += wire.varint.encoded_len_minimal(token_len) + token_len;
    }
    return len;
}

/// What went into the payload.
const Framed = struct {
    len: usize,
    ack_eliciting: bool,
    carries_close: bool = false,
    carries_ack: bool = false,
    path_challenge: ?[constants.path_challenge_len]u8 = null,
    carries_path_response: bool = false,
};

/// Writes the frames this packet carries. The set is small on purpose: an ACK when the space owes
/// one (RFC 9000 §13.2.1) and whatever handshake octets the provider owes at this level
/// (RFC 9001 §4.1.3). Every other frame is written by the piece that owns it.
fn frame_payload(
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
    const crypto_len = connection_crypto.write_crypto(connection, provider, level, payload[written_path..budget]) catch
        return Error.Crypto;
    return .{
        .len = written_path + crypto_len,
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

/// RFC 9001 §5.4.2: "the combined lengths of the encoded packet number and protected payload is
/// at least 4 bytes longer than the sample". Decision 54 reaches that by widening the number.
///
/// It is public so its rule can be checked directly: no frame this file writes today produces a
/// payload under four octets, because the shortest CRYPTO frame is four and an ACK is longer, so
/// nothing reaches it through `build` until the send path writes a bare PING.
pub fn widen_for_sample(number: u64, truncated: packet_number.Truncated, payload_len: usize) packet_number.Truncated {
    if (payload_len >= constants.protected_len_min) return truncated;
    const needed: u8 = @intCast(constants.protected_len_min - payload_len);
    if (needed <= truncated.len) return truncated;
    assert(needed <= constants.packet_number_len_max);
    // RFC 9000 §17.1 permits any width that represents the range, so a wider one is always
    // legal: the peer reads the width from byte 0 and recovers the same number. The value is the
    // number's low octets, which is what `Truncated` holds and `needed` never exceeds.
    return .{ .value = @truncate(number), .len = needed };
}

/// Everything `seal_packet` needs, gathered so its signature stays readable.
const Pending = struct {
    level: Level,
    number: u64,
    truncated: packet_number.Truncated,
    payload: []const u8,
    ack_eliciting: bool,
    shape: Shape,
};

/// Writes the header and asks the suite to protect a planned packet (RFC 9001 §5.3, §5.4).
/// `padding_len` octets of PADDING were added to `payload` by the caller before this.
pub fn seal_planned(
    connection: *Connection,
    suite: crypto.Suite,
    planned: Planned,
    header_scratch: []u8,
    payload: []const u8,
    output: []u8,
) Error!Built {
    const payload_len = planned.payload_len + planned.padding_len;
    const pending: Pending = .{
        .level = planned.level,
        .number = planned.number,
        .truncated = planned.truncated,
        .payload = payload[0..payload_len],
        .ack_eliciting = planned.ack_eliciting,
        .shape = planned.shape,
    };
    const written = try seal_pending(connection, suite, pending, header_scratch, output);
    // RFC 9001 §6.1, §6.2: the packet exists now, so what it does to the key phase is recorded
    // here and never on a packet the suite refused to protect.
    key_update.on_packet_sent(connection, pending.level, pending.number, planned.carries_ack);
    return .{
        .level = pending.level,
        .packet_number = pending.number,
        .len = written,
        .ack_eliciting = pending.ack_eliciting,
        // RFC 9002 §2, stated once in `recovery_sent`: a packet is in flight when it elicits an
        // acknowledgment or carries PADDING, and §14.1's expansion is what adds the second.
        .in_flight = recovery_sent.counts_in_flight(pending.ack_eliciting, planned.padding_len > 0),
    };
}

/// Writes the header and protects the packet, once, or after one key update.
///
/// RFC 9001 §6.6: "Endpoints MUST initiate a key update before sending more protected packets
/// than the confidentiality limit for the selected AEAD permits. If a key update is not possible
/// or integrity limits are reached, the endpoint MUST stop using the connection". colibri counts
/// nothing — the suite holds the keys and the counts — so the limit arrives as a refusal to seal,
/// and the update that §6.6 asks for is made before any further packet goes out.
fn seal_pending(
    connection: *Connection,
    suite: crypto.Suite,
    pending: Pending,
    header_scratch: []u8,
    output: []u8,
) Error!usize {
    return write_and_seal(connection, suite, pending, header_scratch, output) catch |failure| switch (failure) {
        error.ConfidentialityLimitReached => update_and_seal(connection, suite, pending, header_scratch, output),
        else => Error.NoSpaceLeft,
    };
}

/// The second attempt, under the keys a key update installed (RFC 9001 §6.6).
fn update_and_seal(
    connection: *Connection,
    suite: crypto.Suite,
    pending: Pending,
    header_scratch: []u8,
    output: []u8,
) Error!usize {
    // RFC 9001 §6.1's Note: "Keys of packets other than the 1-RTT packets are never updated", so
    // at any other level a key update frees nothing and §6.6's connection error is all that is
    // left.
    if (pending.level != .application) return Error.AeadLimitReached;
    // §6.6: "If a key update is not possible ... the endpoint MUST stop using the connection."
    // §6.1 is what says whether one is possible now, and §6.5's wait does not hold up a MUST.
    key_update.initiate_at_aead_limit(connection, suite) catch return Error.AeadLimitReached;
    // §6.1 toggled the Key Phase bit, so the header is written again rather than reused.
    return write_and_seal(connection, suite, pending, header_scratch, output) catch |failure| switch (failure) {
        // The new keys refusing as well is a key update that did not help, which §6.6 ends on.
        error.ConfidentialityLimitReached => Error.AeadLimitReached,
        else => Error.NoSpaceLeft,
    };
}

/// One attempt: the header, then the suite (RFC 9001 §5.3). `SealError.KeysUnavailable` is
/// colibri's own defect by invariant 21, and reaches the caller as a packet that would not fit.
fn write_and_seal(
    connection: *Connection,
    suite: crypto.Suite,
    pending: Pending,
    header_scratch: []u8,
    output: []u8,
) (core.writer.Error || crypto.suite.SealError)!usize {
    var header = Writer.init(header_scratch);
    try write_header(connection, suite, &header, pending);
    return suite.seal(.{
        .level = pending.level,
        .packet_number = pending.number,
        .header = header.written(),
        .packet_number_len = pending.truncated.len,
        .payload = pending.payload,
    }, output);
}

/// RFC 9000 §17.2 and §17.3: the header through the Packet Number field, unprotected, which
/// RFC 9001 §5.3 makes the AEAD's associated data.
fn write_header(connection: *Connection, suite: crypto.Suite, writer: *Writer, pending: Pending) core.writer.Error!void {
    const identity = &connection.identity;
    if (pending.level == .application) {
        return header_write.write_short(writer, .{
            .dcid = identity.destination().slice(),
            .packet_number = pending.truncated,
            // RFC 9001 §6: the bit is the suite's answer about its current write keys, read at
            // the moment the header is written and never stored by colibri.
            .key_phase = suite_key_phase(suite),
        });
    }
    return header_write.write_long(writer, .{
        .type = if (pending.level == .initial) .initial else .handshake,
        .dcid = identity.destination().slice(),
        .scid = identity.source().slice(),
        // RFC 9000 §8.1.2: the Retry token "MUST be repeated by the client in all Initial packets
        // it sends for that connection after it receives the Retry packet". §17.2.2 gives the
        // field to an Initial alone, and `write_long` asserts that.
        .token = if (pending.level == .initial) connection.retry_token.slice() else &.{},
        .packet_number = pending.truncated,
        .protected_payload_len = pending.payload.len + constants.aead_tag_len,
        .length_len = pending.shape.length_len,
    });
}

/// The Key Phase bit, which only a 1-RTT packet carries (RFC 9000 §17.3.1, RFC 9001 §6).
///
/// RFC 9001 §6: "The Key Phase bit indicates which packet protection keys are used to protect the
/// packet", and the keys are the suite's. colibri never stores the answer: `crypto.Suite` moves
/// both directions in one call (§6.1), so a copy here could disagree with what `seal` then uses.
fn suite_key_phase(suite: crypto.Suite) bool {
    return suite.vtable.key_phase(suite.context);
}

test {
    _ = @import("packet_build_test.zig");
    _ = @import("packet_build_ack_test.zig");
}
