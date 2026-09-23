//! The handshake's two milestones as the connection sees them (RFC 9001 §4.1.1, §4.1.2), and the
//! HANDSHAKE_DONE frame that carries the second from server to client (RFC 9000 §19.20). Part of
//! design §8 step 9e.
//!
//! The provider says when the handshake completes, because the Finished messages are TLS's and
//! colibri reads none of them (decision 8). A server confirms at that moment and owes the client a
//! HANDSHAKE_DONE frame, which RFC 9000 §13.3 retransmits until it is acknowledged. A client
//! confirms when the frame arrives, which `connection_frames` reports. Either endpoint then
//! discards its Handshake keys (RFC 9001 §4.9.2).
//!
//! What §13.3 needs is the number of the one packet that last carried the frame, so the
//! connection keeps that number and `recovery_sent.Record` holds nothing for it.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const crypto = @import("crypto");
const tls = @import("tls");
const frame_module = @import("../frame/frame.zig");
const recovery_sent = @import("../recovery/recovery_sent.zig");
const connection_module = @import("connection.zig");
const connection_crypto = @import("connection_crypto.zig");
const keys_module = @import("connection_keys.zig");

const Level = core.Level;
const Writer = core.Writer;
const Connection = connection_module.Connection;
const Record = recovery_sent.Record;

/// What a server owes the client about the confirmed handshake (RFC 9000 §19.20, §13.3).
pub const HandshakeDone = struct {
    /// Whether a HANDSHAKE_DONE frame is owed: from the moment a server's handshake completes,
    /// and again when the packet that carried one is lost.
    owed: bool = false,
    /// The number of the 1-RTT packet that carried the last one, while that packet is neither
    /// acknowledged nor lost.
    sent_in: ?u64 = null,
};

/// Marks the handshake complete once the provider reports it (RFC 9001 §4.1.1). A server
/// confirms it at the same moment (§4.1.2), owes a HANDSHAKE_DONE frame and discards its
/// Handshake keys (§4.9.2). True when this call completed it.
pub fn complete(connection: *Connection, provider: tls.QuicProvider, suite: crypto.Suite) connection_crypto.Error!bool {
    if (connection.handshake_complete) return false;
    // RFC 9001 §4.1.1: "the TLS handshake is considered complete when the TLS stack has reported
    // that the handshake is complete."
    if (!provider.handshake_complete()) return false;
    // RFC 9001 §8.2: a handshake that completed without the peer's transport parameters is a
    // connection error. The caller reads them with `connection_crypto.take_peer_parameters` as
    // the handshake carries them, so by now they are held or they never came.
    try connection_crypto.require_peer_parameters(connection);
    connection.handshake_complete = true;
    // RFC 9001 §4.1.2: "the TLS handshake is considered confirmed at the server when the
    // handshake completes. The server MUST send a HANDSHAKE_DONE frame as soon as the handshake
    // is complete." A client waits for that frame.
    if (connection.role == .server) {
        connection.confirm_handshake();
        connection.handshake_done.owed = true;
        // RFC 9001 §4.9.2: "An endpoint MUST discard its Handshake keys when the TLS handshake
        // is confirmed".
        keys_module.on_handshake_confirmed(connection, suite);
    }
    return true;
}

/// Writes the HANDSHAKE_DONE frame a server owes, when `level` may carry it. True when it was
/// written; `on_done_sent` then records which packet carried it.
pub fn write_done(connection: *Connection, level: Level, writer: *Writer) bool {
    if (!connection.handshake_done.owed) return false;
    // RFC 9000 §12.4, Table 3 marks HANDSHAKE_DONE "___1": 1-RTT packets alone.
    if (level != .application) return false;
    // RFC 9000 §19.20: "A HANDSHAKE_DONE frame can only be sent by the server. Servers MUST NOT
    // send a HANDSHAKE_DONE frame before completing the handshake." `complete` owes one only then.
    assert(connection.role == .server and connection.handshake_complete);
    frame_module.write(writer, .handshake_done) catch return false;
    connection.handshake_done.owed = false;
    return true;
}

/// Records the number of the packet that carried a HANDSHAKE_DONE frame.
pub fn on_done_sent(connection: *Connection, number: u64) void {
    assert(!connection.handshake_done.owed);
    connection.handshake_done.sent_in = number;
}

/// Ends §13.3's obligation once the packet that carried the frame is acknowledged. The records
/// are one space's, and a packet number means nothing outside its space (RFC 9000 §12.3).
pub fn on_packets_acknowledged(connection: *Connection, level: Level, acknowledged: []const Record) void {
    if (!carried_done(connection, level, acknowledged)) return;
    connection.handshake_done.sent_in = null;
}

/// RFC 9000 §13.3: "The HANDSHAKE_DONE frame MUST be retransmitted until it is acknowledged",
/// so losing the packet that carried it owes it again.
pub fn on_packets_lost(connection: *Connection, level: Level, lost: []const Record) void {
    if (!carried_done(connection, level, lost)) return;
    connection.handshake_done.sent_in = null;
    connection.handshake_done.owed = true;
}

/// Whether `records` hold the packet that carried the last HANDSHAKE_DONE frame.
fn carried_done(connection: *const Connection, level: Level, records: []const Record) bool {
    if (level != .application) return false;
    const number = connection.handshake_done.sent_in orelse return false;
    // Bounded by the slice the caller placed, which `constants.sent_packets_max` sizes.
    for (records) |record| {
        if (record.number == number) return true;
    }
    return false;
}

test {
    _ = @import("connection_handshake_test.zig");
}
