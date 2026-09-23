//! The connection ID frames this endpoint sends (RFC 9000 §5.1): NEW_CONNECTION_ID, which gives
//! the peer another connection ID to send to (§19.15), and RETIRE_CONNECTION_ID, which tells it a
//! connection ID of its own is no longer used (§19.16). Part of design §8 step 9e.
//!
//! The caller issues each new connection ID with its octets and its Stateless Reset Token.
//! colibri draws no random number for the octets (invariant 5) and holds no key to derive the
//! token from (§10.3.2, non-negotiable 2). The caller routes a datagram to its connection by
//! Destination Connection ID, and it chose the octets, so it knows every one this connection
//! answers to (§5.1.1: "When an endpoint issues a connection ID, it MUST accept packets that carry
//! this connection ID").
//!
//! RFC 9000 §13.3 sends both frames again when lost, with the same content. A NEW_CONNECTION_ID
//! is owed until the peer retires the ID, so an acknowledgment of it changes nothing; a
//! RETIRE_CONNECTION_ID is owed until acknowledged.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("../constants.zig");
const frame_module = @import("../frame/frame.zig");
const transport_parameters = @import("../transport_parameters.zig");
const recovery_sent = @import("../recovery/recovery_sent.zig");
const connection_module = @import("connection.zig");

const Level = core.Level;
const Writer = core.Writer;
const Connection = connection_module.Connection;
const Record = recovery_sent.Record;

pub const Error = error{
    /// This endpoint's connection IDs are zero-length. RFC 9000 §19.15: "An endpoint MUST NOT
    /// send this frame if it currently requires that its peer send packets with a zero-length
    /// Destination Connection ID." Nothing changed.
    ZeroLength,
    /// The octets are not the length of this endpoint's other connection IDs, which is the length
    /// it reads a short header's Destination Connection ID by. Nothing changed.
    LengthDiffers,
    /// The peer already holds as many as its `active_connection_id_limit` (§5.1.1: "An endpoint
    /// MUST NOT provide more connection IDs than the peer's limit"), or the table does. Nothing
    /// changed.
    LimitReached,
};

/// Issues a connection ID with `octets` and the Stateless Reset Token the peer may end the
/// connection with (§10.3), owes the NEW_CONNECTION_ID frame that gives it, and returns its
/// sequence number.
pub fn issue(
    connection: *Connection,
    octets: []const u8,
    token: *const [constants.stateless_reset_token_len]u8,
) Error!u64 {
    const local = &connection.local_ids;
    // RFC 9000 §19.15: no NEW_CONNECTION_ID from an endpoint whose peer sends it zero-length
    // Destination Connection IDs.
    if (local.zero_length) return Error.ZeroLength;
    // RFC 9000 §17.3.1: a short header does not encode the Destination Connection ID's length, so
    // this endpoint reads every one by the length of its first.
    if (octets.len != connection.identity.local_len()) return Error.LengthDiffers;
    // RFC 9000 §5.1.1: "An endpoint MUST NOT provide more connection IDs than the peer's limit."
    if (local.active_len() >= peer_limit(connection)) return Error.LimitReached;
    return local.issue(octets, token) orelse Error.LimitReached;
}

/// The peer's `active_connection_id_limit` (§18.2), or the default §18.2 gives before its
/// parameters arrive.
fn peer_limit(connection: *const Connection) u64 {
    const peer = connection.peer_parameters orelse return transport_parameters.default_active_connection_id_limit;
    return peer.active_connection_id_limit;
}

/// Writes the NEW_CONNECTION_ID and RETIRE_CONNECTION_ID frames owed now, and records packet
/// `number` as the one carrying them. True when any went in.
pub fn write(connection: *Connection, level: Level, writer: *Writer, number: u64) bool {
    // RFC 9000 §12.4, Table 3 marks both "__01", and decision 20 refuses 0-RTT.
    if (level != .application) return false;
    var wrote = false;
    // Bounded by the set, which `constants.connection_ids_max` caps.
    for (connection.local_ids.active_ids()) |*issued| {
        if (!issued.new_frame.owed) continue;
        const frame: frame_module.Frame = .{
            .new_connection_id = .{
                .sequence_number = issued.sequence_number,
                // RFC 9000 §19.15: "The value in the Retire Prior To field MUST be less than or equal
                // to the value in the Sequence Number field." colibri asks the peer to retire nothing.
                .retire_prior_to = 0,
                .connection_id = issued.value(),
                .stateless_reset_token = &issued.stateless_reset_token,
            },
        };
        if (issued.new_frame.write(writer, frame, number)) wrote = true;
    }
    // Bounded the same way.
    for (connection.remote_ids.retirements()) |*retirement| {
        if (!retirement.frame.owed) continue;
        const frame: frame_module.Frame = .{ .retire_connection_id = .{ .sequence_number = retirement.sequence_number } };
        if (retirement.frame.write(writer, frame, number)) wrote = true;
    }
    return wrote;
}

/// Drops the retirements the acknowledged packets told the peer of. A NEW_CONNECTION_ID needs
/// nothing: it stays until the peer retires it. The records are `level`'s space's (§12.3).
pub fn on_packets_acknowledged(connection: *Connection, level: Level, acknowledged: []const Record) void {
    if (level != .application) return;
    // Bounded by the slice the caller placed, which `constants.sent_packets_max` sizes.
    for (acknowledged) |record| connection.remote_ids.on_packet_acknowledged(record.number);
}

/// Owes again each connection ID frame whose most recent copy a lost packet carried (RFC 9000
/// §13.3). The records are `level`'s space's (§12.3).
pub fn on_packets_lost(connection: *Connection, level: Level, lost: []const Record) void {
    if (level != .application) return;
    // Bounded by the slice the caller placed, which `constants.sent_packets_max` sizes.
    for (lost) |record| {
        connection.local_ids.on_packet_lost(record.number);
        connection.remote_ids.on_packet_lost(record.number);
    }
}

test {
    _ = @import("connection_id_frames_test.zig");
}
