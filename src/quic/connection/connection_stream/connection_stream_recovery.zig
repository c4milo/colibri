//! What loss recovery's records do to the streams (RFC 9000 §3.1, §13.3): an acknowledged range
//! counts toward its stream, and a lost one is kept so `send` frames it again. Part of design §8
//! step 9e.
//!
//! RFC 9002's loss recovery is the caller's to drive, and it hands out the records a packet
//! number space took out: `recovery_ack.on_ack_received` writes the acknowledged ones and the
//! lost ones into slices the caller placed. Each record names the one stream range its packet
//! carried (decision 57), so this file reads nothing but those records. It runs for the
//! application space alone, because only 1-RTT packets carry STREAM frames (RFC 9000 §12.4,
//! Table 3), and a record from another space names no stream and is passed over.
const std = @import("std");
const assert = std.debug.assert;
const error_code = @import("../../error_code.zig");
const recovery_sent = @import("../../recovery/recovery_sent.zig");
const stream_module = @import("../../stream/stream.zig");
const connection_module = @import("../connection.zig");

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
/// `completed`: from then on the caller may drop that stream's octets (decision 57).
pub fn on_packets_acknowledged(connection: *Connection, acknowledged: []const Record, completed: []StreamId) Acknowledged {
    var held: Acknowledged = .{};
    // Bounded by the slice the caller placed, which `constants.sent_packets_max` sizes.
    for (acknowledged) |record| {
        const range = range_of(record) orelse continue;
        if (!connection.streams.on_range_acknowledged(range)) continue;
        if (held.written < completed.len) {
            completed[held.written] = .{ .value = range.stream_id };
            held.written += 1;
        } else {
            held.unwritten += 1;
        }
    }
    return held;
}

/// Keeps the stream octets the lost records carried, so `send` frames them again (RFC 9000
/// §13.3: "Application data sent in STREAM frames is retransmitted in new STREAM frames"). A
/// lost table that cannot hold one is `Full`, which `connection_error_code` closes on.
pub fn on_packets_lost(connection: *Connection, lost: []const Record) Error!void {
    // Bounded by the slice the caller placed, which `constants.sent_packets_max` sizes.
    for (lost) |record| {
        const range = range_of(record) orelse continue;
        try connection.streams.on_range_lost(range);
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
