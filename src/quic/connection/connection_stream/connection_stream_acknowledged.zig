//! How far a stream's octets are acknowledged from its start (decision 78). Part of design §8
//! step 12.
//!
//! A caller keeps a stream's octets until the peer acknowledges them (decision 57). For a stream
//! that ends, "Data Recvd" says when (RFC 9000 §3.1). A stream that never ends, such as the
//! control stream of an application protocol, needs to know which of its first octets the peer
//! has, so the caller can reuse that storage.
//!
//! colibri keeps no state for it. Each octet colibri framed sits in one packet in flight, in the
//! lost table, or is acknowledged (invariant 29). So every octet below the lowest offset that a
//! packet in flight or a lost range holds is acknowledged, and so is every framed octet when
//! neither holds any. Finding it scans the application space's sent records and the lost table,
//! at most `sent_packets_max` and `stream_lost_ranges_max` entries: a few hundred reads of memory
//! already in cache, which a caller pays only when it needs room.
const std = @import("std");
const assert = std.debug.assert;
const stream_module = @import("../../stream/stream.zig");
const connection_module = @import("../connection.zig");

const Connection = connection_module.Connection;
const StreamId = stream_module.StreamId;

/// The offset below which the peer has acknowledged every octet of `id`. The caller may drop the
/// octets below it, because colibri never reads them through the stream provider again.
///
/// Null when colibri reads none of the stream's octets again at all: the stream is closed or
/// reset (RFC 9000 §13.3, "no further STREAM frames are needed"), or it is not one this endpoint
/// sends on.
pub fn acknowledged_end(connection: *Connection, id: StreamId) ?u64 {
    if (!id.is_sendable_by(connection.streams.role)) return null;
    const stream = switch (connection.streams.lookup(id)) {
        .live => |stream| stream,
        .closed, .unopened => return null,
    };
    // A reset stream's lost ranges are dropped rather than framed again, so its octets are done
    // with even where they were never acknowledged.
    if (stream.sending.state == .reset_sent or stream.sending.state == .reset_recvd) return null;
    const outgoing = &stream.outgoing;
    var lowest = outgoing.framed_end;
    var walk = connection.recovery.table_of(.application).iterator();
    // Bounded by the table's capacity, `sent_packets_max`.
    while (walk.next()) |record| {
        if (record.carries != .stream and record.carries != .stream_fin) continue;
        if (record.stream_id == id.value) lowest = @min(lowest, record.data_offset);
    }
    if (connection.streams.lost.lowest_offset(id.value)) |offset| lowest = @min(lowest, offset);
    // Invariant 29: every octet below it was acknowledged, and counted once.
    assert(lowest <= outgoing.acknowledged_len);
    assert(lowest <= outgoing.framed_end);
    return lowest;
}

const testing = std.testing;
const send = @import("../connection_send.zig");
const stream_send = @import("connection_stream_send.zig");
const stream_recovery = @import("connection_stream_recovery.zig");
const send_test = @import("connection_stream_send_test.zig");
const recovery_sent = @import("../../recovery/recovery_sent.zig");

const Record = recovery_sent.Record;
const Body = send_test.Body;

/// Room for every stream a test completes at once. Test-only.
const completed_max: usize = 4;

/// Sends one packet and returns the record loss recovery kept for it. Test-only.
fn sent_record(body: *Body) !Record {
    const sent = (try send_test.send_from(body, send_test.datagram.len)).?;
    const number = sent.packets[0].packet_number;
    var walk = send_test.client.recovery.table_of(.application).iterator();
    // Bounded by the table.
    while (walk.next()) |record| {
        if (record.number == number) return record;
    }
    return error.TestExpectedRecord;
}

/// Takes `record` out of the sent table as an acknowledgment of it would, and counts it.
fn acknowledge(record: Record) void {
    _ = send_test.client.recovery.table_of(.application).remove(record.number).?;
    var completed: [completed_max]StreamId = undefined;
    _ = stream_recovery.on_packets_acknowledged(&send_test.client, .application, &.{record}, &completed);
}

/// Takes `record` out of the sent table as a loss would, and keeps its range to send again.
fn lose(record: Record) !void {
    _ = send_test.client.recovery.table_of(.application).remove(record.number).?;
    try stream_recovery.on_packets_lost(&send_test.client, .application, &.{record});
}

fn end_of(id: StreamId) ?u64 {
    return acknowledged_end(&send_test.client, id);
}

test "decision 78: the acknowledged end stops at the lowest octet in flight or lost" {
    send_test.open_pair(.{});
    var body: Body = .{ .len = send_test.long_body_len };
    const id = try send_test.open_supplied(send_test.long_body_len, true);
    try testing.expectEqual(0, end_of(id).?);
    var records: [3]Record = undefined;
    for (&records) |*record| record.* = try sent_record(&body);
    try testing.expectEqual(0, end_of(id).?);
    // The middle packet's acknowledgment leaves the first in flight, so nothing moves.
    acknowledge(records[1]);
    try testing.expectEqual(0, end_of(id).?);
    acknowledge(records[0]);
    try testing.expectEqual(records[2].data_offset, end_of(id).?);
    // Lost, the last range waits in the lost table, and then in flight again once resent.
    try lose(records[2]);
    try testing.expectEqual(records[2].data_offset, end_of(id).?);
    const again = try sent_record(&body);
    try testing.expectEqual(records[2].data_offset, again.data_offset);
    try testing.expectEqual(records[2].data_offset, end_of(id).?);
    acknowledge(again);
    try testing.expectEqual(send_test.long_body_len, end_of(id).?);
}

test "decision 78: another stream's octets in flight do not hold the end back" {
    send_test.open_pair(.{});
    var body: Body = .{ .len = send_test.short_body_len };
    const first = try send_test.open_supplied(send_test.short_body_len, false);
    const second = try send_test.open_supplied(send_test.short_body_len, false);
    const first_record = try sent_record(&body);
    const second_record = try sent_record(&body);
    try testing.expectEqual(first.value, first_record.stream_id);
    acknowledge(first_record);
    try testing.expectEqual(send_test.short_body_len, end_of(first).?);
    try testing.expectEqual(0, end_of(second).?);
    // The same holds for another stream's lost range.
    try lose(second_record);
    try testing.expectEqual(send_test.short_body_len, end_of(first).?);
    try testing.expectEqual(0, end_of(second).?);
}

test "decision 78: a reset stream, and one this endpoint does not send on, have no end" {
    send_test.open_pair(.{});
    var body: Body = .{ .len = send_test.long_body_len };
    const id = try send_test.open_supplied(send_test.long_body_len, true);
    const record = try sent_record(&body);
    try stream_send.reset(&send_test.client, id, 0);
    // The lost range is not kept, so its octets are never acknowledged, and none is read again.
    try lose(record);
    try testing.expectEqual(null, end_of(id));
    // A stream the peer opened for its own octets alone, and one not yet opened.
    const peer_stream = StreamId.of(.server, .unidirectional, 0);
    _ = try send_test.client.streams.open_peer(peer_stream);
    try testing.expectEqual(.live, std.meta.activeTag(send_test.client.streams.lookup(peer_stream)));
    try testing.expectEqual(null, end_of(peer_stream));
    try testing.expectEqual(null, end_of(StreamId.of(.client, .bidirectional, 3)));
}
