//! What RFC 9002's loss recovery does to the rest of the connection (decision 59). Part of design
//! §8 step 9e.
//!
//! Recovery answers in packets: the ones an acknowledgment took out of flight and the ones it
//! declared lost, each a `recovery_sent.Record` naming what the packet carried. Every piece that
//! sends information RFC 9000 §13.3 repairs keeps its own record of it, so this file hands each
//! batch of packets to all of them, and nothing else. Which packets they are is `recovery_ack`'s
//! and `recovery_loss`'s to decide.
const std = @import("std");
const core = @import("core");
const error_code = @import("../error_code.zig");
const recovery_sent = @import("../recovery/recovery_sent.zig");
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
