//! The stream ranges a sent packet carried (decision 131). Part of design §8 step 26.
//!
//! A packet's record keeps its first STREAM frame's range in place, and the ring holds the ones
//! after it (`recovery_ranges.zig`). This file reads both, so the files that acknowledge, lose and
//! measure stream octets see every range a packet carried, in the order it carried them.
const std = @import("std");
const assert = std.debug.assert;
const recovery_sent = @import("../../recovery/recovery_sent.zig");
const stream_module = @import("../../stream/stream.zig");
const connection_module = @import("../connection.zig");

const Connection = connection_module.Connection;
const Record = recovery_sent.Record;
const Range = stream_module.stream_lost.Range;

/// The ring's tail: the position of the oldest application-level record the sent table holds, or
/// the head when it holds none (INV-33).
pub fn tail(connection: *Connection) u32 {
    const oldest = connection.recovery.table_of(.application).oldest() orelse return connection.stream_ranges.head;
    return oldest.ranges_from;
}

/// How many stream ranges `record`'s packet carried: none, or its first and the ones after it.
pub fn count(record: Record) usize {
    if (first(record) == null) {
        // Only a packet with a first STREAM frame writes ranges after it.
        assert(record.ranges_len == 0);
        return 0;
    }
    return 1 + @as(usize, record.ranges_len);
}

/// The `index`th stream range `record`'s packet carried, of `count(record)`.
pub fn at(connection: *const Connection, record: Record, index: usize) Range {
    assert(index < count(record));
    if (index == 0) return first(record).?;
    const extra = connection.stream_ranges.at(record.ranges_from, record.ranges_len, index - 1);
    return .{ .stream_id = extra.stream_id, .offset = extra.offset, .len = extra.len, .fin = extra.fin };
}

/// The range of the first STREAM frame `record`'s packet carried, or null when it carried none.
fn first(record: Record) ?Range {
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
