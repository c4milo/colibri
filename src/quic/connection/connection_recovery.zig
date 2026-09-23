//! What RFC 9002's loss recovery does to the rest of the connection (decision 59). Part of design
//! §8 step 9e.
//!
//! Recovery answers in packets: the ones an acknowledgment took out of flight and the ones it
//! declared lost, each a `recovery_sent.Record` naming what the packet carried. Every piece that
//! sends information RFC 9000 §13.3 repairs keeps its own record of it, so this file hands each
//! batch of packets to all of them, and nothing else. Which packets they are is `recovery_ack`'s
//! and `recovery_loss`'s to decide.
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
    const decoded: recovery_ack.Ack = .{ .ranges = ack.ranges, .delay_ns = ack_delay_ns(connection, level, ack.delay), .ecn = ack.ecn };
    const outcome = recovery_ack.on_ack_received(&connection.recovery, kind, decoded, utilization(connection), now_ns, &scratch.acknowledged, &scratch.lost);
    // Each list holds a whole table, so no packet is left unreported.
    assert(outcome.unwritten == 0 and outcome.lost.unwritten == 0);
    const acknowledged = on_packets_acknowledged(connection, level, scratch.acknowledged[0..outcome.written], scratch.completed[completed_from..]);
    try on_packets_lost(connection, level, scratch.lost[0..outcome.lost.written]);
    return acknowledged.written;
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
}
