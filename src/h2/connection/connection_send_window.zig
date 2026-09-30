//! How long the next DATA frame is (RFC 9113 §6.1, §6.9.1): what the connection's send window,
//! the stream's, one frame and the caller's buffer allow, and which of them held it short of the
//! payload. Split off `connection_send.zig` for length.
//!
//! A window below `Connection.data_frame_len_min` sends nothing unless it holds the whole payload
//! (decision 110). A peer that opens its window a few octets at a time then gets no frame for each
//! few octets, which RFC 9113 §10.5 names as a way to make a sender write many frames.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const streams_table = @import("../stream/streams.zig");
const connection = @import("connection.zig");

const Connection = connection.Connection;
const Stream = streams_table.Stream;

/// What held a DATA frame short of the whole payload.
pub const ShortBy = enum {
    /// Nothing: the frame carries all of it.
    none,
    /// The stream's send window, or the connection's (RFC 9113 §6.9.1).
    stream_window,
    connection_window,
    /// The largest frame the peer takes (RFC 9113 §4.2).
    frame_size,
    /// The room in the caller's buffer.
    room,
};

pub const Sendable = struct {
    len: usize,
    short_by: ShortBy,
};

/// The payload octets of the next DATA frame on `record`'s stream, out of `payload_len`, in a
/// buffer of `room_len` octets, and what held it short.
pub fn sendable(target: *const Connection, record: *const Stream, room_len: usize, payload_len: usize) Sendable {
    const stream_window = record.send_window.sendable();
    const connection_window = target.send_window.sendable();
    var next: Sendable = .{ .len = payload_len, .short_by = .none };
    // RFC 9113 §6.9.1: a sender spends both the stream's window and the connection's.
    const window: usize = @min(stream_window, connection_window);
    if (window < next.len) {
        // RFC 9113 §10.5: tiny window increments can make a sender write many frames, so a window
        // below the floor sends nothing (decision 110).
        const floored = if (window < target.data_frame_len_min) 0 else window;
        const held_by: ShortBy = if (connection_window < stream_window) .connection_window else .stream_window;
        next = .{ .len = floored, .short_by = held_by };
    }
    // RFC 9113 §4.2: no frame is longer than the peer's SETTINGS_MAX_FRAME_SIZE.
    if (target.peer.max_frame_size < next.len) next = .{ .len = target.peer.max_frame_size, .short_by = .frame_size };
    const room = if (room_len > constants.frame_header_len) room_len - constants.frame_header_len else 0;
    if (room < next.len) next = .{ .len = room, .short_by = .room };
    assert(next.len <= payload_len);
    return next;
}

const testing = std.testing;
const window_module = @import("../window.zig");
const connection_send = @import("connection_send.zig");
const support = @import("connection_test_support.zig");
const test_connection = &support.test_connection;
const test_output = &support.test_output;

/// The floor the tests set, the octets of their body, and the status of their response. Test-only.
const floor_len: u32 = 1_024;
const body_len: usize = 2_048;
const ok: u16 = 200;
const test_body: [constants.frame_size_max + 1]u8 = @splat('x');

/// A server that has read a request on stream 1 and answered it with a head, with a floor of
/// `floor_len` and a stream window of `stream_window` octets. Test-only.
fn start(stream_window: u32) !*Stream {
    try support.start_server();
    _ = try support.feed_request(1, "/", true);
    _ = try connection_send.write_response(test_connection, test_output, 1, ok, &.{}, false);
    test_connection.data_frame_len_min = floor_len;
    const record = test_connection.streams.lookup(1).live;
    record.send_window = window_module.Window.init(stream_window);
    return record;
}

test "RFC 9113 §10.5: a window below the floor sends nothing, and one at the floor sends a frame" {
    const record = try start(floor_len - 1);
    const held = try connection_send.write_data(test_connection, test_output, 1, test_body[0..body_len], true);
    try testing.expectEqual(0, held.consumed);
    try testing.expectEqual(.stream_window, held.short_by);
    record.send_window = window_module.Window.init(floor_len);
    const sent = try connection_send.write_data(test_connection, test_output, 1, test_body[0..body_len], true);
    try testing.expectEqual(floor_len, sent.consumed);
    try testing.expectEqual(.stream_window, sent.short_by);
}

test "decision 110: a payload the window holds goes out whole, however short" {
    _ = try start(floor_len - 1);
    const sent = try connection_send.write_data(test_connection, test_output, 1, test_body[0 .. floor_len - 1], true);
    try testing.expectEqual(floor_len - 1, sent.consumed);
    try testing.expectEqual(.none, sent.short_by);
}

test "RFC 9113 §6.9.1: the connection's window, the frame size and the room each say they held a frame short" {
    _ = try start(constants.window_max);
    test_connection.send_window = window_module.Window.init(floor_len);
    try testing.expectEqual(.connection_window, (try connection_send.write_data(test_connection, test_output, 1, test_body[0..body_len], false)).short_by);
    test_connection.send_window = window_module.Window.init(constants.window_max);
    const frame = try connection_send.write_data(test_connection, test_output, 1, &test_body, false);
    try testing.expectEqual(.frame_size, frame.short_by);
    const room = try connection_send.write_data(test_connection, test_output[0 .. constants.frame_header_len + floor_len], 1, test_body[0..body_len], false);
    try testing.expectEqual(floor_len, room.consumed);
    try testing.expectEqual(.room, room.short_by);
}

test "decision 110: with no floor, a window of one octet sends one" {
    _ = try start(1);
    test_connection.data_frame_len_min = 0;
    try testing.expectEqual(1, (try connection_send.write_data(test_connection, test_output, 1, test_body[0..body_len], true)).consumed);
}
