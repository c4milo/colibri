//! The pool slots of the table in `streams.zig`, split off `streams_open.zig` for length: what an
//! identifier finds in the table, which record an open drops when the pool is full, and what the
//! table remembers of an identifier whose record is gone.
//!
//! The pool holds `concurrent_streams_max` records, live and closed alike, because RFC 9113 §5.1
//! decides a frame on a closed stream by how that stream closed. An open into a full pool drops
//! the oldest close, by `closed_at`, and only a stream colibri reset is remembered after the drop:
//! §5.1 discards the frames that follow a RST_STREAM colibri sent, and an identifier with nothing
//! remembered is `Lookup.forgotten`, which the connection refuses. A record that owes a RST_STREAM
//! not yet written is never dropped, because the frame would be lost with it (`streams_reset.zig`).
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const stream = @import("stream.zig");
const table = @import("streams.zig");
const open = @import("streams_open.zig");

const Stream = table.Stream;
const Streams = table.Streams;
const Lookup = table.Lookup;

/// What the identifier of a frame the peer sent finds, as `Streams.lookup` says. An identifier
/// above its parity's watermark was never opened, so the pool holds no record of it (invariant
/// 13). That answer comes first, because it reads no record and every new stream gets it.
pub fn lookup(streams: *Streams, id: u32) Lookup {
    assert(id != constants.connection_stream_id);
    assert(id <= constants.stream_id_max);
    if (streams.pool.is_above_watermark(id)) return .{ .idle = open.initiated_by_peer(streams, id) };
    if (streams.pool.get(id)) |record| return .{ .live = record };
    return if (was_reset_and_dropped(streams, id)) .reset_and_dropped else .forgotten;
}

/// Whether an identifier at or below its watermark with no record names a stream colibri reset and
/// the table dropped, as `Lookup.reset_and_dropped` describes it.
fn was_reset_and_dropped(streams: *const Streams, id: u32) bool {
    assert(!streams.pool.is_above_watermark(id));
    const highest = streams.highest_forgotten_reset_id[open.class_of(id)] orelse return false;
    return id <= highest;
}

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

/// Whether the pool has a free slot, after dropping the oldest closed record when it had none.
pub fn ensure_free_slot(streams: *Streams) bool {
    // The pool's capacity is `concurrent_streams_max` (`streams.zig`'s `Pool`).
    if (streams.pool.len() < constants.concurrent_streams_max) return true;
    return drop_oldest_closed(streams);
}

/// Drops the record with the lowest `closed_at` among the closed streams the pool holds that owe no
/// RST_STREAM, and, when colibri reset that stream, records the reset for `lookup`. False when the
/// pool holds no such stream. The closed records wait in close order, so the oldest is the first
/// of them that owes nothing, and the pool closes it at its slot: no record is searched for.
fn drop_oldest_closed(streams: *Streams) bool {
    // Bounded by the closed records, and it passes one only when that one owes a RST_STREAM.
    for (0..streams.closed_len) |position| {
        const index = closed_slot(streams, @intCast(position));
        const record = streams.pool.at(index);
        assert(record.state == .closed and record.closed != null);
        assert(record.closed_at < streams.sequence);
        // Decision 113: the record holds the RST_STREAM the caller asked for until it is written.
        if (record.reset_owed != null) continue;
        assert(record.id <= constants.stream_id_max);
        // RFC 9113 §5.1: frames are discarded after the record is gone only for a stream colibri
        // reset.
        if (record.closed == .rst_stream_sent) record_forgotten_reset(streams, @intCast(record.id));
        forget_closed(streams, @intCast(position));
        streams.pool.close_at(index);
        assert(streams.pool.len() < constants.concurrent_streams_max);
        return true;
    }
    return false;
}

comptime {
    // A slot's number fits one octet of `closed_slots`.
    assert(constants.concurrent_streams_max <= std.math.maxInt(u8) + 1);
}

/// Empties the closed records, for a table that holds no record.
pub fn forget_all_closed(streams: *Streams) void {
    streams.closed_slots = @splat(0);
    streams.closed_first = 0;
    streams.closed_len = 0;
}

/// Adds `record`, which has just closed, after the closed records: `sequence` orders the closes,
/// and so does this.
pub fn note_closed(streams: *Streams, record: *const Stream) void {
    assert(record.state == .closed and record.closed != null);
    assert(streams.closed_len < constants.concurrent_streams_max);
    const place = (streams.closed_first + streams.closed_len) % constants.concurrent_streams_max;
    streams.closed_slots[place] = @intCast(streams.pool.index_of(record));
    streams.closed_len += 1;
}

/// The closed records are the records that are neither open nor half-closed, each once.
pub fn assert_closed_count(streams: *const Streams) void {
    const active = streams.peer_active + streams.local_active;
    assert(streams.closed_len == streams.pool.len() - active);
}

/// The slot of the closed record `position` places after the oldest.
fn closed_slot(streams: *const Streams, position: u32) u32 {
    assert(position < streams.closed_len);
    return streams.closed_slots[(streams.closed_first + position) % constants.concurrent_streams_max];
}

/// Takes the record `position` places after the oldest out of the closed records. Each older one
/// moves a place toward it, so the rest keep their order.
fn forget_closed(streams: *Streams, position: u32) void {
    assert(position < streams.closed_len);
    const capacity = constants.concurrent_streams_max;
    // Bounded by `position`: the older records, each of which owes a RST_STREAM.
    for (0..position) |step| {
        const to = (streams.closed_first + position - @as(u32, @intCast(step))) % capacity;
        const from = (to + capacity - 1) % capacity;
        streams.closed_slots[to] = streams.closed_slots[from];
    }
    streams.closed_first = (streams.closed_first + 1) % capacity;
    streams.closed_len -= 1;
}

// Tests. `streams_open.zig` holds the table these run on, and its test helpers.

const testing = std.testing;

/// The lookup `lookup` replaced, which scanned the pool for a record before it read the watermark:
/// the reference `lookup` must agree with. Test-only.
fn lookup_scan_first(streams: *Streams, id: u32) Lookup {
    if (streams.pool.get(id)) |record| return .{ .live = record };
    if (streams.pool.is_above_watermark(id)) return .{ .idle = open.initiated_by_peer(streams, id) };
    return if (was_reset_and_dropped(streams, id)) .reset_and_dropped else .forgotten;
}

/// The identifiers the comparison asks for: every one a full table has seen, and some past them.
/// Test-only.
const compared_ids: u32 = open.client_id(constants.concurrent_streams_max + compared_ids_past);
const compared_ids_past: u32 = 8;

/// Requires `lookup` to find what the reference finds in the tests' table, for each identifier of
/// either parity, and names the first that differs. Test-only.
fn expect_same_lookups() !void {
    for (1..compared_ids) |id| {
        const found = lookup(&open.test_table, @intCast(id));
        const scanned = lookup_scan_first(&open.test_table, @intCast(id));
        if (std.meta.eql(found, scanned)) continue;
        std.debug.print("first difference: identifier {d}: lookup {any}, scan first {any}\n", .{ id, found, scanned });
        return error.TestUnexpectedResult;
    }
}

test "lookup finds what a scan of the pool before the watermark finds, as a server's table fills, closes and drops" {
    open.test_table.init(.server);
    try expect_same_lookups();
    _ = try open.test_table.open_peer(open.client_id(0), open.test_send_window);
    _ = try open.test_table.open_peer(open.client_id(2), open.test_send_window);
    try expect_same_lookups();
    try finish(try open.expect_live(open.client_id(0)));
    try open.reset(try open.expect_live(open.client_id(2)));
    try expect_same_lookups();
    open.test_table.init(.server);
    try open.fill_with_peer_streams();
    try expect_same_lookups();
    // A stream past the limit is refused, and the watermark moves past it with no record.
    const refused = open.client_id(constants.concurrent_streams_max);
    try testing.expectError(error.Refused, open.test_table.open_peer(refused, open.test_send_window));
    try expect_same_lookups();
    // Two closes give way to two opens: one record is forgotten, and one reset is remembered.
    try finish(try open.expect_live(open.client_id(0)));
    try open.reset(try open.expect_live(open.client_id(1)));
    _ = try open.test_table.open_peer(open.client_id(constants.concurrent_streams_max + 1), open.test_send_window);
    _ = try open.test_table.open_peer(open.client_id(constants.concurrent_streams_max + 2), open.test_send_window);
    try expect_same_lookups();
}

test "lookup finds what a scan of the pool before the watermark finds in a client's table, with a promised stream" {
    open.test_table.init(.client);
    try expect_same_lookups();
    _ = try open.test_table.open_local(null, open.test_send_window);
    _ = try open.test_table.open_local(null, open.test_send_window);
    try open.test_table.reserve_peer(constants.stream_id_server_first + constants.stream_id_step);
    try expect_same_lookups();
}

/// The record the sweep `drop_oldest_closed` replaced would drop: the lowest `closed_at` among the
/// closed records that owe no RST_STREAM, or null. Test-only.
fn oldest_closed_by_sweep(streams: *Streams) ?*Stream {
    var oldest: ?*Stream = null;
    var records = streams.pool.iterator();
    while (records.next()) |record| {
        if (record.state != .closed or record.reset_owed != null) continue;
        if (oldest == null or record.closed_at < oldest.?.closed_at) oldest = record;
    }
    return oldest;
}

/// Requires the closed records to be every closed record the pool holds, in the order they
/// closed, and the first of them that owes no RST_STREAM to be the one the sweep would drop.
/// Test-only.
fn expect_closed_as_swept() !void {
    const streams = &open.test_table;
    var last_closed_at: ?u64 = null;
    var first_droppable: ?*Stream = null;
    for (0..streams.closed_len) |position| {
        const record = streams.pool.at(closed_slot(streams, @intCast(position)));
        try testing.expectEqual(stream.State.closed, record.state);
        if (last_closed_at) |last| try testing.expect(record.closed_at > last);
        last_closed_at = record.closed_at;
        if (first_droppable == null and record.reset_owed == null) first_droppable = record;
    }
    var closed_in_pool: u32 = 0;
    var records = streams.pool.iterator();
    while (records.next()) |record| closed_in_pool += @intFromBool(record.state == .closed);
    try testing.expectEqual(closed_in_pool, streams.closed_len);
    try testing.expectEqual(oldest_closed_by_sweep(streams), first_droppable);
}

test "the closed records keep the order of their closes, around the ring's end, and an open drops the one a sweep would" {
    const max = constants.concurrent_streams_max;
    open.test_table.init(.server);
    try expect_closed_as_swept();
    try open.fill_with_peer_streams();
    // From the highest identifier down, so the order of the closes is not the order of the slots:
    // one stream in three ends, one is reset, and one stays open.
    for (0..max) |index| {
        const record = try open.expect_live(open.client_id(@intCast(max - 1 - index)));
        switch (index % 3) {
            0 => try finish(record),
            1 => try open.reset(record),
            else => {},
        }
        try expect_closed_as_swept();
    }
    // The second and the fourth close were resets, and each now owes its RST_STREAM (decision
    // 113): an open drops neither, and passes over them for the oldest that owes nothing.
    const second_closed = try open.expect_live(open.client_id(max - 2));
    const fourth_closed = try open.expect_live(open.client_id(max - 5));
    open.test_table.owe_reset(second_closed, constants.error_cancel);
    open.test_table.owe_reset(fourth_closed, constants.error_cancel);
    try expect_closed_as_swept();
    // Each open drops one closed record, and each new stream's own close goes after the rest:
    // more closes than the ring has places, so they go around its end.
    for (0..max + max / 2) |index| {
        const record = try open.test_table.open_peer(open.client_id(@intCast(max + index)), open.test_send_window);
        try expect_closed_as_swept();
        try finish(record);
        try expect_closed_as_swept();
    }
    // The two that owe a frame are still held, the oldest two of the closed records.
    try testing.expectEqual(second_closed, open.test_table.pool.at(closed_slot(&open.test_table, 0)));
    try testing.expectEqual(fourth_closed, open.test_table.pool.at(closed_slot(&open.test_table, 1)));
    // Once its frame is written, the oldest gives way to the next open, and its reset is remembered.
    open.test_table.reset_written(second_closed);
    try expect_closed_as_swept();
    _ = try open.test_table.open_peer(open.client_id(@intCast(max + max + max)), open.test_send_window);
    try testing.expectEqual(Lookup.reset_and_dropped, open.test_table.lookup(open.client_id(max - 2)));
    try testing.expectEqual(fourth_closed, open.test_table.pool.at(closed_slot(&open.test_table, 0)));
    try expect_closed_as_swept();
}

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
