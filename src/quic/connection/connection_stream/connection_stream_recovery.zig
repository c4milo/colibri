//! What loss recovery's records do to the streams (RFC 9000 §3.1, §13.3): an acknowledged range
//! counts toward its stream, and a lost one is kept so `send` frames it again. Part of design §8
//! step 9e.
//!
//! The connection drives RFC 9002's loss recovery (decision 59), and `connection_recovery` hands
//! this file the records a packet number space took out: the acknowledged ones and the lost ones,
//! in slices the caller placed. Each record names the one stream range its packet
//! carried (decision 57), so this file reads nothing but those records. It runs for the
//! application space alone, because only 1-RTT packets carry STREAM frames (RFC 9000 §12.4,
//! Table 3), and a record from another space names no stream and is passed over.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const error_code = @import("../../error_code.zig");
const recovery_sent = @import("../../recovery/recovery_sent.zig");
const stream_module = @import("../../stream/stream.zig");
const connection_module = @import("../connection.zig");
const stream_close = @import("connection_stream_close.zig");

const Level = core.Level;
const Connection = connection_module.Connection;
const Record = recovery_sent.Record;
const StreamId = stream_module.StreamId;
const Range = stream_module.stream_lost.Range;

pub const Error = stream_module.stream_lost.Error;

/// RFC 9000 §20.1: the code a refusal closes the connection with. A lost table that cannot hold
/// a range leaves octets colibri can no longer send again, and no code names that more closely
/// than INTERNAL_ERROR.
pub fn connection_error_code(failure: Error) u64 {
    return switch (failure) {
        error.Full => error_code.internal_error,
    };
}

/// What the acknowledged records did.
pub const Acknowledged = struct {
    /// How many streams entered "Data Recvd" whose identifiers were written to the caller's
    /// slice, and how many more did not fit. A caller that wants every one passes a slice as long
    /// as the records.
    written: usize = 0,
    unwritten: usize = 0,
};

/// Counts the stream octets the acknowledged records carried (RFC 9000 §3.1). A stream whose
/// every octet and FIN are now acknowledged enters "Data Recvd", and its identifier goes into
/// `completed`: from then on the caller may drop that stream's octets (decision 57). A stream
/// whose RESET_STREAM the records carried enters "Reset Recvd". The records are the ones `level`'s
/// space took out, and a packet number means nothing outside its space (RFC 9000 §12.3).
pub fn on_packets_acknowledged(
    connection: *Connection,
    level: Level,
    acknowledged: []const Record,
    completed: []StreamId,
) Acknowledged {
    var held: Acknowledged = .{};
    // RFC 9000 §12.4, Table 3: every frame this file answers for travels in 1-RTT packets.
    if (level != .application) return held;
    // Bounded by the slice the caller placed, which `constants.sent_packets_max` sizes.
    for (acknowledged) |record| {
        acknowledge_reset(connection, record.number);
        const range = range_of(record) orelse continue;
        if (!connection.streams.on_range_acknowledged(range)) continue;
        if (held.written < completed.len) {
            completed[held.written] = .{ .value = range.stream_id };
            held.written += 1;
        } else {
            held.unwritten += 1;
        }
        // RFC 9000 §3.1: the sending part is in "Data Recvd", which may finish the stream.
        _ = stream_close.close_if_finished(connection, connection.streams.lookup(.{ .value = range.stream_id }).live);
    }
    return held;
}

/// Keeps the stream octets the lost records carried, so `send` frames them again (RFC 9000
/// §13.3: "Application data sent in STREAM frames is retransmitted in new STREAM frames"), and
/// owes again each RESET_STREAM and STOP_SENDING whose most recent copy was lost: §13.3 sends the
/// first "until acknowledged" and the second "until the receiving part of the stream enters
/// either a 'Data Recvd' or 'Reset Recvd' state". A lost table that cannot hold a range is `Full`,
/// which `connection_error_code` closes on.
pub fn on_packets_lost(connection: *Connection, level: Level, lost: []const Record) Error!void {
    if (level != .application) return;
    // Bounded by the slice the caller placed, which `constants.sent_packets_max` sizes.
    for (lost) |record| {
        owe_endings(connection, record.number);
        const range = range_of(record) orelse continue;
        try connection.streams.on_range_lost(range);
    }
}

/// Moves the stream whose most recent RESET_STREAM packet `number` carried to "Reset Recvd"
/// (RFC 9000 §3.1). Only a stream in "Reset Sent" has one outstanding, so the table is walked
/// only while one is, and acknowledging it clears the record.
fn acknowledge_reset(connection: *Connection, number: u64) void {
    const streams = &connection.streams;
    if (streams.resets_unacknowledged == 0) return;
    var walk = streams.pool.iterator();
    // Bounded by the table's capacity, `streams_per_connection_max`.
    while (walk.next()) |stream| {
        if (!stream.reset_stream.carried_by(number)) continue;
        streams.on_reset_acknowledged(stream);
        // RFC 9000 §3.1: the sending part is in "Reset Recvd", which may finish the stream.
        _ = stream_close.close_if_finished(connection, stream);
    }
}

/// Owes again the RESET_STREAM and STOP_SENDING whose most recent copy packet `number` carried.
fn owe_endings(connection: *Connection, number: u64) void {
    var walk = connection.streams.pool.iterator();
    // Bounded by the table's capacity, `streams_per_connection_max`.
    while (walk.next()) |stream| {
        stream.reset_stream.on_lost(number);
        stream.stop_sending.on_lost(number);
    }
}

/// The stream range a record's packet carried, or null when it carried none.
fn range_of(record: Record) ?Range {
    const fin = switch (record.carries) {
        .stream => false,
        .stream_fin => true,
        .none, .crypto => return null,
    };
    // A range carries octets or the FIN (RFC 9000 §19.8); a STREAM frame with neither is not
    // one colibri writes.
    assert(record.data_len > 0 or fin);
    return .{ .stream_id = record.stream_id, .offset = record.data_offset, .len = record.data_len, .fin = fin };
}

test {
    _ = @import("connection_stream_recovery_test.zig");
}
