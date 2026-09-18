//! The pool slots of the table in `streams.zig`, split off `streams_open.zig` for length: which
//! record an open drops when the pool is full, and what the table remembers of an identifier whose
//! record is gone.
//!
//! The pool holds `concurrent_streams_max` records, live and closed alike, because RFC 9113 §5.1
//! decides a frame on a closed stream by how that stream closed. An open into a full pool drops
//! the oldest close, by `closed_at`, and only a stream colibri reset is remembered after the drop:
//! §5.1 discards the frames that follow a RST_STREAM colibri sent, and an identifier with nothing
//! remembered is `Lookup.forgotten`, which the connection refuses.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const stream = @import("stream.zig");
const table = @import("streams.zig");
const open = @import("streams_open.zig");

const Stream = table.Stream;
const Streams = table.Streams;

/// Moves the watermark of `id`'s parity to `id`, which the peer used for a stream colibri resets
/// without a record, and records the reset for `lookup`.
pub fn forget_reset(streams: *Streams, id: u32) void {
    assert(streams.pool.is_above_watermark(id));
    streams.pool.advance_watermark(open.class_of(id), id);
    record_forgotten_reset(streams, id);
    assert(streams.pool.watermark[open.class_of(id)] == id);
}

/// Raises `highest_forgotten_reset_id` of `id`'s parity to `id` when it is lower.
fn record_forgotten_reset(streams: *Streams, id: u32) void {
    assert(!streams.pool.is_above_watermark(id));
    const class = open.class_of(id);
    const highest = streams.highest_forgotten_reset_id[class] orelse 0;
    streams.highest_forgotten_reset_id[class] = @max(highest, id);
    assert(streams.highest_forgotten_reset_id[class].? >= id);
}

/// Whether the pool has a free slot, after dropping the oldest record closed by a RST_STREAM
/// colibri sent when it had none.
pub fn ensure_free_slot(streams: *Streams) bool {
    // The pool's capacity is `concurrent_streams_max` (`streams.zig`'s `Pool`).
    if (streams.pool.len() < constants.concurrent_streams_max) return true;
    return drop_oldest_closed(streams);
}

/// Drops the record with the lowest `closed_at` among the closed streams the pool holds, and, when
/// colibri reset that stream, records the reset for `lookup`. False when the pool holds no closed
/// stream.
fn drop_oldest_closed(streams: *Streams) bool {
    var oldest: ?*Stream = null;
    var records = streams.pool.iterator();
    while (records.next()) |record| {
        if (record.state != .closed) continue;
        assert(record.closed != null);
        assert(record.closed_at < streams.sequence);
        if (oldest == null or record.closed_at < oldest.?.closed_at) oldest = record;
    }
    const dropped = oldest orelse return false;
    assert(dropped.id <= constants.stream_id_max);
    // RFC 9113 §5.1: frames are discarded after the record is gone only for a stream colibri reset.
    if (dropped.closed == .rst_stream_sent) record_forgotten_reset(streams, @intCast(dropped.id));
    streams.pool.close(dropped.id);
    assert(streams.pool.len() < constants.concurrent_streams_max);
    return true;
}

// Tests. `streams_open.zig` holds the table these run on, and its test helpers.

const testing = std.testing;
const Lookup = table.Lookup;

test "an identifier at or below the highest reset colibri dropped is reset_and_dropped, and a record still held answers for its own" {
    open.test_table.init(.server);
    try open.fill_with_peer_streams();
    const refused = open.client_id(constants.concurrent_streams_max);
    try testing.expectError(error.Refused, open.test_table.open_peer(refused, open.test_send_window));
    try open.apply_frame(try open.expect_live(1), .receive, .rst_stream, false);
    const above = open.client_id(constants.concurrent_streams_max + 1);
    const record = try open.test_table.open_peer(above, open.test_send_window);
    try open.apply_frame(record, .receive, .data, true);
    try open.apply_frame(record, .send, .data, true);
    try testing.expectEqual(Lookup.reset_and_dropped, open.test_table.lookup(1));
    try testing.expectEqual(Lookup.reset_and_dropped, open.test_table.lookup(refused));
    try testing.expectEqual(stream.State.closed, (try open.expect_live(above)).state);
    try testing.expectEqual(refused, open.test_table.highest_forgotten_reset_id[1]);
}

/// Closes `record` with END_STREAM in both directions, as the state machine decides it. Test-only.
fn finish(record: *Stream) !void {
    try open.apply_frame(record, .receive, .data, true);
    try open.apply_frame(record, .send, .data, true);
    try testing.expectEqual(stream.Closed.end_stream, record.closed.?);
}

test "a pool full of streams closed by END_STREAM gives way too, and a dropped identifier is forgotten, not reset" {
    open.test_table.init(.server);
    try open.fill_with_peer_streams();
    const last_index = constants.concurrent_streams_max - 1;
    // Closing from the highest identifier down puts the oldest close in the last slot.
    for (0..constants.concurrent_streams_max) |index| try finish(try open.expect_live(open.client_id(last_index - @as(u32, @intCast(index)))));
    try testing.expectEqual(0, open.test_table.peer_active);
    try testing.expectEqual(constants.concurrent_streams_max, open.test_table.len());
    _ = try open.test_table.open_peer(open.client_id(last_index + 1), open.test_send_window);
    // The oldest close was the highest identifier, and nothing colibri reset was dropped.
    try testing.expectEqual(Lookup.forgotten, open.test_table.lookup(open.client_id(last_index)));
    try testing.expectEqual([_]?u32{ null, null }, open.test_table.highest_forgotten_reset_id);
    try testing.expectEqual(stream.State.closed, (try open.expect_live(open.client_id(last_index - 1))).state);
    try testing.expectEqual(constants.concurrent_streams_max, open.test_table.len());
    try testing.expectEqual(1, open.test_table.peer_active);
}

test "a pool full of streams closed by a RST_STREAM colibri sent gives way to new streams, oldest close first" {
    open.test_table.init(.server);
    try open.fill_with_peer_streams();
    const last_index = constants.concurrent_streams_max - 1;
    // Closing from the highest identifier down puts the oldest close in the last slot.
    for (0..constants.concurrent_streams_max) |index| try open.reset(try open.expect_live(open.client_id(last_index - @as(u32, @intCast(index)))));
    try testing.expectEqual(0, open.test_table.peer_active);
    try testing.expectEqual(constants.concurrent_streams_max, open.test_table.len());
    _ = try open.test_table.open_peer(open.client_id(last_index + 1), open.test_send_window);
    try testing.expectEqual(Lookup.reset_and_dropped, open.test_table.lookup(open.client_id(last_index)));
    try testing.expectEqual(stream.State.closed, (try open.expect_live(open.client_id(last_index - 1))).state);
    _ = try open.test_table.open_peer(open.client_id(last_index + 2), open.test_send_window);
    try testing.expectEqual(Lookup.reset_and_dropped, open.test_table.lookup(open.client_id(last_index - 1)));
    try testing.expectEqual(open.client_id(last_index), open.test_table.highest_forgotten_reset_id[1]);
    try testing.expectEqual(stream.State.closed, (try open.expect_live(open.client_id(0))).state);
    try testing.expectEqual(2, open.test_table.peer_active);
    try testing.expectEqual(constants.concurrent_streams_max, open.test_table.len());
}

test "a record closed by a RST_STREAM colibri sent stays while the pool has a free slot" {
    open.test_table.init(.server);
    try open.reset(try open.test_table.open_peer(1, open.test_send_window));
    _ = try open.test_table.open_peer(3, open.test_send_window);
    const kept = try open.expect_live(1);
    try testing.expectEqual(stream.Closed.rst_stream_sent, kept.closed.?);
    try testing.expectEqual(2, open.test_table.len());
    try testing.expectEqual(null, open.test_table.highest_forgotten_reset_id[1]);
}
