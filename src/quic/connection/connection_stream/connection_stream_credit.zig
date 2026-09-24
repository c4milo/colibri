//! How many more octets a stream can send before flow control stops them (decision 81). Part of
//! design §8 step 12.
//!
//! RFC 9204 §2.1.3 asks a QPACK encoder not to write an instruction "unless sufficient stream and
//! connection flow-control credit is available for the entire instruction". An octet supplied now
//! waits behind octets supplied earlier, and those spend credit first:
//! - the stream's own octets not yet framed spend its stream's credit and the connection's;
//! - RFC 9000 §2.3's order (`set_priority`) frames a stream with a lower priority value first, and
//!   streams of one value take turns, so their octets not yet framed spend the connection's credit.
//!
//! A stream with a higher priority value frames after this one, so its octets spend nothing first.
//! colibri keeps no state for it: it reads two limits and walks the stream table once, at most
//! `streams_per_connection_max` entries.
const std = @import("std");
const assert = std.debug.assert;
const stream_module = @import("../../stream/stream.zig");
const connection_module = @import("../connection.zig");

const Connection = connection_module.Connection;
const StreamId = stream_module.StreamId;

/// The octets `id` can still send once everything supplied before them is framed: the smaller of
/// its stream's flow-control credit and the connection's, each less the octets not yet framed
/// that spend it first (RFC 9000 §4.1).
///
/// Null when `id` sends no new octets: it is not one this endpoint sends on, it is closed, or it
/// was reset or has sent its FIN (RFC 9000 §3.1).
pub fn send_credit(connection: *Connection, id: StreamId) ?u64 {
    if (!id.is_sendable_by(connection.streams.role)) return null;
    const stream = switch (connection.streams.lookup(id)) {
        .live => |stream| stream,
        .closed, .unopened => return null,
    };
    // RFC 9000 §3.1: new octets leave from "Ready" or "Send" alone.
    if (!stream.sending.may_send_data()) return null;
    const stream_credit = stream.send_flow.available() -| stream.outgoing.unframed_len();
    var ahead: u64 = 0;
    var walk = connection.streams.pool.iterator();
    // Bounded by the table's capacity, `streams_per_connection_max`.
    while (walk.next()) |other| {
        // RFC 9000 §2.3: a stream with a higher priority value frames after this one.
        if (other.priority > stream.priority) continue;
        if (!other.sending.may_send_data()) continue;
        ahead +|= other.outgoing.unframed_len();
    }
    // The walk met `id` itself, so its own octets are among those ahead.
    assert(ahead >= stream.outgoing.unframed_len());
    const connection_credit = connection.send_flow.available() -| ahead;
    return @min(stream_credit, connection_credit);
}

const testing = std.testing;
const stream_send = @import("connection_stream_send.zig");
const send_test = @import("connection_stream_send_test.zig");

/// A window smaller than the other, and octets supplied inside it. Test-only.
const small_window: u64 = 100;
const supplied_len: u64 = 30;
/// A priority below the default, which goes first. Test-only.
const urgent: u8 = 0;
const test_error_code: u64 = 0;

fn credit_of(id: StreamId) ?u64 {
    return send_credit(&send_test.client, id);
}

test "RFC 9000 §4.1: a stream's credit is its window less the octets it has not framed" {
    send_test.open_pair(.{ .stream = small_window });
    const id = try send_test.open_supplied(supplied_len, false);
    try testing.expectEqual(small_window - supplied_len, credit_of(id).?);
    // A stream past its window has none.
    try stream_send.supply(&send_test.client, id, small_window + supplied_len, false);
    try testing.expectEqual(0, credit_of(id).?);
}

test "RFC 9000 §2.3: the connection's credit goes first to streams framed before or with this one" {
    send_test.open_pair(.{ .connection = small_window });
    const id = try send_test.open_supplied(0, false);
    try stream_send.set_priority(&send_test.client, id, urgent);
    // A stream of the default priority frames after `id`, so it spends nothing first.
    _ = try send_test.open_supplied(supplied_len, false);
    try testing.expectEqual(small_window, credit_of(id).?);
    // A stream of `id`'s priority takes turns with it.
    const turn = try send_test.open_supplied(supplied_len, false);
    try stream_send.set_priority(&send_test.client, turn, urgent);
    try testing.expectEqual(small_window - supplied_len, credit_of(id).?);
    // The default-priority stream counts everything ahead of or beside it.
    const later: StreamId = .{ .value = turn.value - stream_id_step };
    try testing.expectEqual(small_window - 2 * supplied_len, credit_of(later).?);
    // A reset stream frames nothing more, so its octets spend nothing.
    try stream_send.reset(&send_test.client, turn, test_error_code);
    try testing.expectEqual(small_window, credit_of(id).?);
}

/// The distance between two client-initiated bidirectional stream IDs (RFC 9000 §2.1). Test-only.
const stream_id_step: u64 = 4;

test "RFC 9000 §3.1: a stream that sends no new octets has no credit" {
    send_test.open_pair(.{});
    const id = try send_test.open_supplied(supplied_len, false);
    try testing.expect(credit_of(id) != null);
    try stream_send.reset(&send_test.client, id, test_error_code);
    try testing.expectEqual(null, credit_of(id));
    const peer_unidirectional = StreamId.of(.server, .unidirectional, 0);
    _ = try send_test.client.streams.open_peer(peer_unidirectional);
    try testing.expectEqual(null, credit_of(peer_unidirectional));
    try testing.expectEqual(null, credit_of(StreamId.of(.client, .bidirectional, 2)));
}
