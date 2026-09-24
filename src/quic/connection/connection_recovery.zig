//! What RFC 9002's loss recovery does to the rest of the connection (decision 59). Part of design
//! §8 step 9e.
//!
//! Recovery answers in packets: the ones an acknowledgment took out of flight and the ones it
//! declared lost, each a `recovery_sent.Record` naming what the packet carried. Every piece that
//! sends information RFC 9000 §13.3 repairs keeps its own record of it, so this file hands each
//! batch of packets to all of them. Which packets they are is `recovery_ack`'s and
//! `recovery_loss`'s to decide.
//!
//! It also runs the loss detection timer when `connection_timer.on_instant` finds it due, and
//! tells RFC 9002 Appendix A.8's timer the four facts it reads from the rest of the connection.
//! Each fact is state the connection already holds, so it is copied in before the timer is read
//! rather than recorded twice.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("../constants.zig");
const error_code = @import("../error_code.zig");
const frame_module = @import("../frame/frame.zig");
const space_module = @import("../space/space.zig");
const transport_parameters = @import("../transport_parameters.zig");
const recovery_sent = @import("../recovery/recovery_sent.zig");
const recovery_ack = @import("../recovery/recovery_ack.zig");
const recovery_congestion = @import("../recovery/recovery_congestion.zig");
const stream_module = @import("../stream/stream.zig");
const connection_module = @import("connection.zig");
const keys_module = @import("connection_keys.zig");
const connection_send = @import("connection_send.zig");
const connection_crypto = @import("connection_crypto.zig");
const connection_flow = @import("connection_flow.zig");
const connection_handshake = @import("connection_handshake.zig");
const connection_id_frames = @import("connection_id_frames.zig");
const stream_recovery = @import("connection_stream/connection_stream_recovery.zig");

const Level = core.Level;
const Connection = connection_module.Connection;
const Record = recovery_sent.Record;
const StreamId = stream_module.StreamId;

pub const Error = error{
    /// A lost packet carried CRYPTO octets the level's send window has already forgotten, so they
    /// cannot be sent again (`connection_crypto.on_packets_lost`). §13.3 has no answer for that.
    CryptoForgotten,
    /// The table of lost stream ranges cannot hold one more (`stream_lost.Error.Full`).
    LostRangesFull,
};

/// RFC 9000 §20.1: the code each refusal closes the connection with. Both leave octets the
/// connection can no longer send, and no code names that more closely than INTERNAL_ERROR.
pub fn connection_error_code(failure: Error) u64 {
    return switch (failure) {
        error.CryptoForgotten, error.LostRangesFull => error_code.internal_error,
    };
}

/// What the acknowledged packets finished: the streams that entered "Data Recvd" (RFC 9000
/// §3.1), whose octets the caller may now drop (decision 57).
pub const Acknowledged = stream_recovery.Acknowledged;

/// Where one ACK frame's packets are written while it is taken: the ones it acknowledged, the
/// ones it revealed lost, and the streams they finished. The caller places it (decision 35) and
/// passes it with every packet `connection_frames.process` reads. Each list holds a whole table,
/// so nothing is left out.
pub const Scratch = struct {
    acknowledged: [constants.sent_packets_max]Record,
    lost: [constants.sent_packets_max]Record,
    completed: [constants.streams_per_connection_max]StreamId,
};

/// RFC 9002 Appendix A.7's `OnAckReceived` for one ACK frame read at `level`, and what its
/// packets mean to the rest of the connection (decision 59). Returns how many streams it finished,
/// written into `scratch.completed` from `completed_from` on.
pub fn on_ack_received(
    connection: *Connection,
    level: Level,
    ack: frame_module.Ack,
    now_ns: u64,
    scratch: *Scratch,
    completed_from: usize,
) Error!usize {
    const kind: space_module.Kind = @enumFromInt(@intFromEnum(level));
    // RFC 9002 Appendix A.7 reads `PeerCompletedAddressValidation` and the handshake's state.
    sync_timer(connection);
    // RFC 9002 Appendix A.7 asks `PeerCompletedAddressValidation` once the ACK is taken, and for
    // a client "has received Handshake ACK" is this ACK.
    if (level == .handshake) connection.recovery.timer.peer_completed_address_validation = true;
    const decoded: recovery_ack.Ack = .{ .ranges = ack.ranges, .delay_ns = ack_delay_ns(connection, level, ack.delay), .ecn = ack.ecn };
    const outcome = recovery_ack.on_ack_received(&connection.recovery, kind, decoded, utilization(connection), now_ns, &scratch.acknowledged, &scratch.lost);
    // Each list holds a whole table, so no packet is left unreported.
    assert(outcome.unwritten == 0 and outcome.lost.unwritten == 0);
    const acknowledged = on_packets_acknowledged(connection, level, scratch.acknowledged[0..outcome.written], scratch.completed[completed_from..]);
    try on_packets_lost(connection, level, scratch.lost[0..outcome.lost.written]);
    return acknowledged.written;
}

/// The instant RFC 9002 Appendix A.8's loss detection timer is set for, or null when it is not
/// set. RFC 9000 §10.2.1: a closing endpoint "retains only enough information to generate a
/// packet containing a CONNECTION_CLOSE frame", so a connection that is no longer active sets none.
pub fn loss_deadline_ns(connection: *Connection) ?u64 {
    if (connection.termination.state != .active) return null;
    sync_timer(connection);
    const timer = connection.recovery.next_timer() orelse return null;
    return timer.at_ns;
}

/// RFC 9002 Appendix A.9's `OnLossDetectionTimeout`, when the timer is due at `now_ns`. Packets it
/// declares lost go to every piece that sends what they carried again; a Probe Timeout owes the
/// probes `send` builds (RFC 9002 §6.2.4). True when the timer was due.
pub fn on_loss_timer(connection: *Connection, now_ns: u64, scratch: *Scratch) Error!bool {
    const at_ns = loss_deadline_ns(connection) orelse return false;
    if (now_ns < at_ns) return false;
    switch (connection.recovery.on_timeout(now_ns, &scratch.lost)) {
        .none => {},
        .lost => |lost| {
            // The list holds a whole table, so no packet is left unreported.
            assert(lost.found.unwritten == 0);
            try on_packets_lost(connection, level_of(lost.space), scratch.lost[0..lost.found.written]);
        },
        .probe => |probe| try on_probe_timeout(connection, probe.space, probe.count, scratch),
    }
    return true;
}

/// RFC 9002 §6.2.4's probes: `count` in the space whose timer expired, and one in each other
/// space with ack-eliciting packets in flight (decision 70), which `send` coalesces.
fn on_probe_timeout(connection: *Connection, kind: space_module.Kind, count: u8, scratch: *Scratch) Error!void {
    try owe_probes(connection, kind, count, scratch);
    // Bounded by the three spaces of RFC 9000 §12.3.
    for (std.enums.values(space_module.Kind)) |other| {
        // RFC 9002 §6.2.4: "the sender SHOULD send ack-eliciting packets from other packet number
        // spaces with in-flight data, coalescing packets if possible."
        if (other == kind or connection.recovery.table_of(other).ack_eliciting_count() == 0) continue;
        try owe_probes(connection, other, 1, scratch);
    }
}

/// Probes that carry what packets declared lost here held rather than a PING. At the Initial and
/// Handshake levels decision 64 declares every packet in flight lost, so the probes carry their
/// CRYPTO octets. At the application level decision 66 declares the oldest ack-eliciting ones
/// lost, one for each probe owed.
fn owe_probes(connection: *Connection, kind: space_module.Kind, count: u8, scratch: *Scratch) Error!void {
    const level = level_of(kind);
    const lost_count = if (level == .application)
        connection.recovery.declare_oldest_lost(kind, count, &scratch.lost)
    else
        declare_all_lost(connection, kind, scratch);
    try on_packets_lost(connection, level, scratch.lost[0..lost_count]);
    connection_send.owe_probes(connection, level, count);
}

/// Decision 64: every packet `kind` has in flight, written into `scratch.lost`.
fn declare_all_lost(connection: *Connection, kind: space_module.Kind, scratch: *Scratch) usize {
    const removed = connection.recovery.declare_in_flight_lost(kind, &scratch.lost);
    // The list holds a whole table, so no packet is left unreported.
    assert(removed.unwritten == 0);
    return removed.written;
}

/// RFC 9002 §6.2.3 for a server, after one Initial packet's frames are processed.
/// `received_len_before` is the Initial CRYPTO flow's `received_len` from before them. An
/// ack-eliciting packet that brought no new CRYPTO octets shows the client lacks the server's
/// own: it repeats the ClientHello, or it is the padded Initial §6.2.2.1 has a client without
/// Handshake keys send. Decision 65 declares the server's Initial packets in flight lost, as
/// decision 64 does on a PTO, so the next datagram carries their CRYPTO octets. `now_ns` is the
/// instant the packet arrived, which decision 71 spaces the resends by.
pub fn on_initial_processed(connection: *Connection, ack_eliciting: bool, received_len_before: u64, now_ns: u64, scratch: *Scratch) Error!void {
    if (connection.role != .server or !ack_eliciting) return;
    // New octets are the client's own flight still arriving, which shows nothing about the
    // server's.
    if (connection.crypto_at(.initial).received_len() != received_len_before) return;
    // RFC 9002 §6.2.3: "for a limited number of times per connection".
    if (connection.early_crypto_resends == constants.early_crypto_resends_max) return;
    // RFC 9002 §6.2.3: what is sent early is "unacknowledged CRYPTO data", so without any there
    // is nothing to send and the limit is not spent.
    if (!crypto_in_flight(connection, .initial)) return;
    // Decision 71: a client's PTO sends its two probes at once, and a resend for each would put
    // both inside one burst of loss. The next waits a PTO, without backoff or max_ack_delay,
    // which RFC 9002 §6.2.1 leaves out at the Initial level.
    const spacing_ns = connection.recovery.rtt.probe_timeout_ns(false);
    if (connection.early_crypto_resends > 0 and now_ns -| connection.early_crypto_resent_at_ns < spacing_ns) return;
    connection.early_crypto_resends += 1;
    connection.early_crypto_resent_at_ns = now_ns;
    const removed = connection.recovery.declare_in_flight_lost(.initial, &scratch.lost);
    // The list holds a whole table, so no packet is left unreported.
    assert(removed.unwritten == 0);
    try on_packets_lost(connection, .initial, scratch.lost[0..removed.written]);
}

/// Whether a packet in flight in `kind`'s space carries CRYPTO octets.
fn crypto_in_flight(connection: *Connection, kind: space_module.Kind) bool {
    var records = connection.recovery.table_of(kind).iterator();
    // Bounded by the table, which `constants.sent_packets_max` sizes.
    while (records.next()) |record| {
        if (record.carries == .crypto) return true;
    }
    return false;
}

/// The encryption level whose packets fill `kind`'s space (RFC 9000 §12.3).
fn level_of(kind: space_module.Kind) Level {
    return @enumFromInt(@intFromEnum(kind));
}

/// Copies into `recovery.timer` what RFC 9002 Appendix A.8 reads from the rest of the connection.
fn sync_timer(connection: *Connection) void {
    const timer = &connection.recovery.timer;
    // RFC 9002 §6.2.1: "An endpoint MUST NOT set its PTO timer for the Application Data packet
    // number space until the handshake is confirmed."
    timer.handshake_confirmed = connection.handshake_confirmed;
    // RFC 9002 Appendix A.9: an anti-deadlock probe goes in a Handshake packet "if (has handshake
    // keys)", and in a padded Initial otherwise.
    timer.has_handshake_keys = keys_module.can_seal(connection, .handshake);
    timer.peer_completed_address_validation = peer_completed_address_validation(connection);
    // RFC 9002 Appendix A.8: "The server's timer is not set if nothing can be sent", which is
    // when `connection_send.send` would refuse any datagram (RFC 9000 §8.1).
    timer.at_anti_amplification_limit = connection.path.send_allowance() < constants.packet_header_len_max;
}

/// RFC 9002 Appendix A.8's `PeerCompletedAddressValidation`.
fn peer_completed_address_validation(connection: *const Connection) bool {
    // RFC 9002 Appendix A.8: "Assume clients validate the server's address implicitly."
    if (connection.role == .server) return true;
    // RFC 9002 Appendix A.8: "has received Handshake ACK || handshake confirmed". A Handshake
    // ACK is what sets the space's largest acknowledged packet.
    const handshake_space = @intFromEnum(space_module.Kind.handshake);
    return connection.handshake_confirmed or connection.recovery.largest_acknowledged[handshake_space] != null;
}

/// RFC 9000 §19.3: the ACK Delay is in microseconds, scaled by 2 to the power of the peer's
/// ack_delay_exponent (§18.2). RFC 9002 §5.3: an endpoint "MAY ignore the acknowledgment delay for
/// Initial packets", which colibri does.
fn ack_delay_ns(connection: *const Connection, level: Level, delay: u64) u64 {
    if (level == .initial) return 0;
    const exponent = if (connection.peer_parameters) |peer| peer.ack_delay_exponent else transport_parameters.default_ack_delay_exponent;
    return (delay <<| @as(u6, @intCast(exponent))) *| constants.nanoseconds_per_microsecond;
}

/// RFC 9002 §7.8: an acknowledgment grows the window only when the window bounded what was sent,
/// which the send path records.
fn utilization(connection: *const Connection) recovery_congestion.Utilization {
    return if (connection.window_limited) .full else .limited;
}

/// Hands the packets an acknowledgment took out of `level`'s space to every piece that keeps a
/// record of what it sent. `completed` receives the streams that finished.
pub fn on_packets_acknowledged(
    connection: *Connection,
    level: Level,
    acknowledged: []const Record,
    completed: []StreamId,
) Acknowledged {
    connection_handshake.on_packets_acknowledged(connection, level, acknowledged);
    connection_id_frames.on_packets_acknowledged(connection, level, acknowledged);
    return stream_recovery.on_packets_acknowledged(connection, level, acknowledged, completed);
}

/// Hands the packets declared lost in `level`'s space to every piece that sends what they carried
/// again (RFC 9000 §13.3).
pub fn on_packets_lost(connection: *Connection, level: Level, lost: []const Record) Error!void {
    const crypto = connection_crypto.on_packets_lost(connection, level, lost);
    if (crypto.forgotten) return Error.CryptoForgotten;
    stream_recovery.on_packets_lost(connection, level, lost) catch |failure| switch (failure) {
        error.Full => return Error.LostRangesFull,
    };
    connection_flow.on_packets_lost(connection, level, lost);
    connection_handshake.on_packets_lost(connection, level, lost);
    connection_id_frames.on_packets_lost(connection, level, lost);
}

test {
    _ = @import("connection_recovery_test.zig");
    _ = @import("connection_recovery_early_test.zig");
}
