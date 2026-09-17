//! The last stream identifiers of the GOAWAY frames each endpoint sent, held by the stream table
//! of `streams.zig` (RFC 9113 §6.8, invariant 16), and the value colibri puts in its next one.
//! `open_peer` and `open_local` in `streams_open.zig` read the held values: colibri ignores a peer
//! stream above the value it sent (`is_above_goaway_sent`), and opens no stream once the peer has
//! sent one.
//!
//! colibri chooses the value it sends, so its two rules are assertions: the value is at least every
//! peer stream colibri opened (§8.7), and at most the value colibri sent before (§6.8).
//! `last_peer_stream_id` gives a value that meets both. On the peer's side §6.8's rule is one
//! check, made before the value is held (invariant 7): the value is at most the one the peer sent
//! before, or `error.LastStreamIdIncreased`, a connection error of PROTOCOL_ERROR. No assertion
//! reads the peer's value (invariant 24).
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const open = @import("streams_open.zig");
const table = @import("streams.zig");
const Streams = table.Streams;

/// Records the last stream identifier of a GOAWAY colibri sends: at least every peer stream it
/// opened, and at most the one it sent before.
pub fn record_goaway_sent(streams: *Streams, last_stream_id: u32) void {
    assert(last_stream_id <= constants.stream_id_max);
    // RFC 9113 §8.7: a GOAWAY MUST include a stream identifier greater than or equal to that of
    // every stream whose frames reached the application, and colibri counts every stream it opened.
    assert(last_stream_id >= streams.highest_peer_opened_id);
    if (streams.goaway_sent_last_id) |previous| {
        // RFC 9113 §6.8: endpoints MUST NOT increase the value they send in the last stream
        // identifier. Invariant 16's runtime assertion.
        assert(last_stream_id <= previous);
    }
    streams.goaway_sent_last_id = last_stream_id;
    assert(streams.goaway_sent_last_id.? == last_stream_id);
}

/// Records the last stream identifier of a GOAWAY the peer sent. `error.LastStreamIdIncreased`
/// is the connection error of PROTOCOL_ERROR, and the value held stays as it was.
pub fn record_goaway_received(streams: *Streams, last_stream_id: u32) error{LastStreamIdIncreased}!void {
    // The frame codec masks the reserved bit, so 31 bits hold the value.
    assert(last_stream_id <= constants.stream_id_max);
    if (streams.goaway_received_last_id) |previous| {
        // RFC 9113 §6.8: endpoints MUST NOT increase the value they send in the last stream
        // identifier, so a larger one from the peer is a connection error of PROTOCOL_ERROR.
        if (last_stream_id > previous) return error.LastStreamIdIncreased;
    }
    streams.goaway_received_last_id = last_stream_id;
    assert(streams.goaway_received_last_id.? == last_stream_id);
}

/// Whether colibri has sent a GOAWAY whose last stream identifier is below `id`, a stream the peer
/// initiated, so that colibri ignores the stream (RFC 9113 §6.8).
pub fn is_above_goaway_sent(streams: *const Streams, id: u32) bool {
    assert(open.initiated_by_peer(streams, id));
    const last = streams.goaway_sent_last_id orelse return false;
    return id > last;
}

/// The last stream identifier colibri puts in its next GOAWAY (RFC 9113 §6.8): the highest
/// identifier of the peer's parity the table opened, refused or reserved, or 0 when there is none,
/// and never above the value of a GOAWAY colibri already sent.
pub fn last_peer_stream_id(streams: *const Streams) u32 {
    const watermark = streams.pool.watermark[open.class_of(open.first_stream_id(streams.role.peer()))];
    assert(watermark == null or watermark.? <= constants.stream_id_max);
    const highest: u32 = @intCast(watermark orelse 0);
    assert(highest >= streams.highest_peer_opened_id);
    // RFC 9113 §6.8: endpoints MUST NOT increase the value they send in the last stream identifier.
    const previous = streams.goaway_sent_last_id orelse return highest;
    assert(previous >= streams.highest_peer_opened_id);
    return @min(highest, previous);
}

// Tests.

const testing = std.testing;
const Lookup = table.Lookup;

/// The table the tests run in, placed outside any stack frame.
var test_table: Streams = undefined;

/// The peer's SETTINGS_INITIAL_WINDOW_SIZE in the tests.
const test_send_window: u32 = 1000;

test "colibri's GOAWAY may repeat or lower its last stream identifier" {
    test_table.init(.server);
    test_table.record_goaway_sent(constants.stream_id_max);
    try testing.expectEqual(constants.stream_id_max, test_table.goaway_sent_last_id);
    test_table.record_goaway_sent(5);
    test_table.record_goaway_sent(5);
    try testing.expectEqual(5, test_table.goaway_sent_last_id);
    test_table.record_goaway_sent(0);
    try testing.expectEqual(0, test_table.goaway_sent_last_id);
    try testing.expectEqual(null, test_table.goaway_received_last_id);
}

test "colibri's GOAWAY may name exactly the highest peer stream it opened (§8.7)" {
    test_table.init(.server);
    _ = try test_table.open_peer(1, test_send_window);
    _ = try test_table.open_peer(5, test_send_window);
    try testing.expectEqual(5, test_table.highest_peer_opened_id);
    test_table.record_goaway_sent(test_table.last_peer_stream_id());
    try testing.expectEqual(5, test_table.goaway_sent_last_id);
    test_table.record_goaway_sent(5);
    try testing.expectEqual(5, test_table.last_peer_stream_id());
}

test "after colibri sends a GOAWAY, a peer stream above its last identifier is AfterGoaway and one at it opens (§6.8)" {
    test_table.init(.server);
    _ = try test_table.open_peer(1, test_send_window);
    test_table.record_goaway_sent(5);
    try testing.expectError(error.AfterGoaway, test_table.open_peer(7, test_send_window));
    try testing.expectEqual(1, test_table.last_peer_stream_id());
    try testing.expectEqual(Lookup{ .idle = true }, test_table.lookup(7));
    try testing.expectEqual(5, (try test_table.open_peer(5, test_send_window)).id);
    try testing.expectEqual(2, test_table.peer_active);
    test_table.init(.server);
    test_table.record_goaway_sent(0);
    try testing.expectError(error.AfterGoaway, test_table.open_peer(1, test_send_window));
    try testing.expectEqual(0, test_table.len());
}

test "a peer's GOAWAY that raises its last stream identifier is LastStreamIdIncreased, and an equal or lower one is held" {
    test_table.init(.client);
    try test_table.record_goaway_received(7);
    try testing.expectError(error.LastStreamIdIncreased, test_table.record_goaway_received(9));
    try testing.expectEqual(7, test_table.goaway_received_last_id);
    try test_table.record_goaway_received(7);
    try test_table.record_goaway_received(3);
    try testing.expectEqual(3, test_table.goaway_received_last_id);
    try testing.expectError(error.LastStreamIdIncreased, test_table.record_goaway_received(5));
    try testing.expectEqual(3, test_table.goaway_received_last_id);
    try testing.expectEqual(null, test_table.goaway_sent_last_id);
    test_table.init(.client);
    try test_table.record_goaway_received(0);
    try testing.expectError(error.LastStreamIdIncreased, test_table.record_goaway_received(1));
    try testing.expectEqual(0, test_table.goaway_received_last_id);
}

test "last_peer_stream_id is the highest peer identifier opened or reserved, never colibri's own, and never above colibri's last GOAWAY (§6.8)" {
    test_table.init(.server);
    try testing.expectEqual(0, test_table.last_peer_stream_id());
    _ = try test_table.open_peer(1, test_send_window);
    _ = try test_table.open_peer(5, test_send_window);
    try testing.expectEqual(5, test_table.last_peer_stream_id());
    test_table.init(.client);
    _ = try test_table.open_local(null, test_send_window);
    try testing.expectEqual(0, test_table.last_peer_stream_id());
    try test_table.reserve_peer(2);
    try testing.expectEqual(2, test_table.last_peer_stream_id());
    test_table.record_goaway_sent(0);
    try test_table.reserve_peer(6);
    try testing.expectEqual(0, test_table.last_peer_stream_id());
    try testing.expectEqual(6, test_table.pool.watermark[0]);
}
