//! The invariants of docs/invariants.md 13 to 16, read off an h2 connection after every frame it
//! accepted or the one that ended it. Both connection checks use this: the cleartext one of design
//! §8 step 4 and the TLS one of step 5, which is why it is its own file.
//!
//! Each invariant compares a value against what it was at the frame before, so the reader holds
//! that history and nothing else. It reads the connection and never changes it.
const std = @import("std");
const h2 = @import("h2");

const h2_constants = h2.constants;

/// The six an invariant reader can raise: two each for invariants 13 and 16, one each for 14
/// and 15.
pub const Violation = error{
    /// Invariant 13: a watermark of the stream table's slot pool decreased.
    WatermarkDecreased,
    /// Invariant 13: the highest identifier the peer opened decreased.
    PeerOpenedIdentifierDecreased,
    /// Invariant 14: the octets fed to the field-block slot exceeded what one HEADERS frame and
    /// `continuation_count_max` CONTINUATION frames carry.
    FieldBlockTooLong,
    /// Invariant 15: a flow-control window went outside the range of a signed 31-bit quantity.
    WindowOutOfRange,
    /// Invariant 16: the last stream identifier of a GOAWAY colibri sent rose.
    GoawaySentLastIdIncreased,
    /// Invariant 16: the last stream identifier of a GOAWAY the peer sent rose.
    GoawayReceivedLastIdIncreased,
};

/// Invariant 14's bound on the octets one field block feeds the slot: the opening frame and at
/// most `continuation_count_max` CONTINUATION frames, each at most `frame_size_max`.
pub const field_block_octets_max: u64 =
    (h2_constants.continuation_count_max + 1) * h2_constants.frame_size_max;

/// What invariants 13 and 16 compare the connection's values against, as of the frame before.
pub const Invariants = struct {
    watermark: [h2_constants.stream_id_parity_count]u64,
    highest_peer_opened_id: u32,
    goaway_sent_last_id: ?u32,
    goaway_received_last_id: ?u32,

    /// Empties the history, for a connection that has read nothing.
    pub fn init(invariants: *Invariants) void {
        invariants.watermark = @splat(0);
        invariants.highest_peer_opened_id = 0;
        invariants.goaway_sent_last_id = null;
        invariants.goaway_received_last_id = null;
    }

    /// Reads all four invariants off `connection`, in the order the header gives.
    pub fn read(invariants: *Invariants, connection: *h2.Connection) ?Violation {
        if (invariants.read_identifiers(connection)) |broken| return broken;
        // Invariant 14: the slot holds one block, whose octets are the opening frame's and those
        // of the CONTINUATION frames the connection lets follow it.
        if (connection.block.octets_fed > field_block_octets_max) return error.FieldBlockTooLong;
        // Invariant 15: the connection's own two windows, then both windows of every stream.
        if (!connection.send_window.in_range()) return error.WindowOutOfRange;
        if (!connection.receive_window.in_range()) return error.WindowOutOfRange;
        if (read_stream_windows(connection)) |broken| return broken;
        return invariants.read_goaway(connection);
    }

    /// Invariant 13: neither watermark of the slot pool decreases, and neither does the highest
    /// identifier the peer opened.
    fn read_identifiers(invariants: *Invariants, connection: *h2.Connection) ?Violation {
        const pool = &connection.streams.pool;
        for (&invariants.watermark, 0..) |*seen, class| {
            const reached = pool.watermark[class] orelse 0;
            if (reached < seen.*) return error.WatermarkDecreased;
            seen.* = reached;
        }
        const opened = connection.streams.highest_peer_opened_id;
        if (opened < invariants.highest_peer_opened_id) return error.PeerOpenedIdentifierDecreased;
        invariants.highest_peer_opened_id = opened;
        return null;
    }

    /// Invariant 16: the last stream identifier of each endpoint's GOAWAY never rises.
    fn read_goaway(invariants: *Invariants, connection: *h2.Connection) ?Violation {
        const streams = &connection.streams;
        if (rises(invariants.goaway_sent_last_id, streams.goaway_sent_last_id)) {
            return error.GoawaySentLastIdIncreased;
        }
        if (rises(invariants.goaway_received_last_id, streams.goaway_received_last_id)) {
            return error.GoawayReceivedLastIdIncreased;
        }
        invariants.goaway_sent_last_id = streams.goaway_sent_last_id;
        invariants.goaway_received_last_id = streams.goaway_received_last_id;
        return null;
    }
};

/// Invariant 15: both windows of every record the stream table holds stay in range.
fn read_stream_windows(connection: *h2.Connection) ?Violation {
    var records = connection.streams.iterator();
    while (records.next()) |record| {
        if (!record.send_window.in_range()) return error.WindowOutOfRange;
        if (!record.receive.in_range()) return error.WindowOutOfRange;
    }
    return null;
}

/// True when a last stream identifier moved up, which RFC 9113 §6.8 forbids.
fn rises(before: ?u32, now: ?u32) bool {
    const seen = before orelse return false;
    const current = now orelse return false;
    return current > seen;
}

test "an empty reader accepts a connection that has read nothing" {
    var invariants: Invariants = undefined;
    invariants.init();
    var connection: h2.Connection = undefined;
    connection.init(.server);
    try std.testing.expectEqual(null, invariants.read(&connection));
    // Reading twice changes nothing, because nothing about the connection moved.
    try std.testing.expectEqual(null, invariants.read(&connection));
}
