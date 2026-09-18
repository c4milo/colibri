//! The retroactive send-window adjustment of RFC 9113 §6.9.2, split off `streams.zig` for length: a
//! change to the peer's SETTINGS_INITIAL_WINDOW_SIZE moves the send window of every stream colibri
//! may still send DATA on, by the difference between the old value and the new. This adjustment is
//! why the table's records are an array the connection can walk rather than a map (decision 13).
//!
//! The change is applied in two passes, because §6.9.2 makes a change that takes any window past
//! `window_max` a connection error of FLOW_CONTROL_ERROR and colibri leaves no window half-moved:
//! the first pass adjusts a copy of each window, and the second moves them once every copy fits.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const stream = @import("stream.zig");
const table = @import("streams.zig");
const open = @import("streams_open.zig");

const Streams = table.Streams;

/// Adds `delta`, the change in the peer's SETTINGS_INITIAL_WINDOW_SIZE, to the send window of
/// every stream colibri may still send DATA on (RFC 9113 §6.9.2). colibri keeps no send window
/// for a half-closed (local) or closed stream (§5.1), so that window neither moves nor
/// overflows. `error.Overflow` is the connection error FLOW_CONTROL_ERROR, and no window moves.
pub fn adjust_send_windows(streams: *Streams, delta: i64) error{Overflow}!void {
    assert(delta >= -@as(i64, constants.window_max) and delta <= constants.window_max);
    open.assert_counts(streams);
    var probes = streams.pool.iterator();
    while (probes.next()) |record| {
        if (!may_send_data(record.state)) continue;
        var probe = record.send_window;
        // RFC 9113 §6.9.2: a change to SETTINGS_INITIAL_WINDOW_SIZE that causes any
        // flow-control window to exceed the maximum is a connection error of
        // FLOW_CONTROL_ERROR. Every window is checked on a copy before any window moves.
        try probe.adjust(delta);
    }
    var records = streams.pool.iterator();
    while (records.next()) |record| {
        if (!may_send_data(record.state)) continue;
        // The first pass adjusted a copy of this window by the same delta.
        record.send_window.adjust(delta) catch unreachable;
    }
}

/// Whether colibri may still send DATA on a stream in `state` (RFC 9113 §5.1): on an open or
/// half-closed (remote) stream, and on a reserved (local) one once it sends HEADERS. Not on an
/// idle, half-closed (local), closed or reserved (remote) stream.
fn may_send_data(state: stream.State) bool {
    return switch (state) {
        .open, .half_closed_remote, .reserved_local => true,
        .idle, .reserved_remote, .half_closed_local, .closed => false,
    };
}

// Tests. `streams.zig` holds the table these run on, and its test helpers.

const testing = std.testing;

test "http2/6.9.2/1: a change to the initial window moves every send window colibri keeps by the difference, and no other" {
    table.test_streams.init(.server);
    const first = try table.test_streams.open_peer(1, table.test_send_window);
    const second = try table.test_streams.open_peer(3, table.test_send_window);
    const half_closed = try table.test_streams.open_peer(5, table.test_send_window);
    const reset = try table.test_streams.open_peer(7, table.test_send_window);
    try first.send_window.consume(400);
    try second.send_window.add(500);
    try table.apply_frame(half_closed, .receive, .data, true);
    try table.apply_frame(reset, .send, .rst_stream, false);
    try table.test_streams.adjust_send_windows(-700);
    try testing.expectEqual(-100, first.send_window.available);
    try testing.expectEqual(800, second.send_window.available);
    try testing.expectEqual(300, half_closed.send_window.available);
    try testing.expectEqual(1000, reset.send_window.available);
    table.test_streams.init(.client);
    const local = try table.test_streams.open_local(null, table.test_send_window);
    const finished = try table.test_streams.open_local(null, table.test_send_window);
    try finished.send_window.add(constants.window_max - table.test_send_window);
    try table.apply_frame(finished, .send, .headers, true);
    try table.test_streams.adjust_send_windows(-1500);
    try table.test_streams.adjust_send_windows(2200);
    try testing.expectEqual(1700, local.send_window.available);
    try testing.expectEqual(constants.window_max, finished.send_window.available);
}

test "a change that takes one send window past window_max is Overflow and moves none, and a reset stream's window never overflows" {
    table.test_streams.init(.server);
    const first = try table.test_streams.open_peer(1, table.test_send_window);
    const second = try table.test_streams.open_peer(3, table.test_send_window);
    try second.send_window.add(constants.window_max - table.test_send_window);
    try testing.expectError(error.Overflow, table.test_streams.adjust_send_windows(1));
    try testing.expectEqual(table.test_send_window, first.send_window.available);
    try testing.expectEqual(constants.window_max, second.send_window.available);
    try table.apply_frame(second, .send, .rst_stream, false);
    try table.test_streams.adjust_send_windows(1);
    try testing.expectEqual(table.test_send_window + 1, first.send_window.available);
    try testing.expectEqual(constants.window_max, second.send_window.available);
}
