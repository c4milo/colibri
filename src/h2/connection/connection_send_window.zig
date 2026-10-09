//! How long the next DATA frame is (RFC 9113 §6.1, §6.9.1): what the connection's send window,
//! the stream's, one frame and the caller's buffer allow, and which of them held it short of the
//! payload. Split off `connection_send.zig` for length.
//!
//! A window below `Connection.data_frame_len_min` sends nothing unless it holds the whole payload,
//! once the peer has sent a WINDOW_UPDATE whose increment is below the floor, and while its
//! SETTINGS_INITIAL_WINDOW_SIZE is at least the floor (decision 110 as amended). A peer that opens
//! a window of its usual size a few octets at a time then gets no frame for each few octets, which
//! RFC 9113 §10.5 names as a way to make a sender write many frames. A peer that asks for small
//! windows gets frames that fit them, and one that gives credit back in pieces of the floor or more
//! never meets it.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const streams_table = @import("../stream/streams.zig");
const stream = @import("../stream/stream.zig");
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
        // below the floor sends nothing once the peer has sent one, unless it asked for windows
        // that small (decision 110 as amended).
        const floor = if (target.peer.initial_window_size < target.data_frame_len_min or !target.tiny_update_read) 0 else target.data_frame_len_min;
        const floored = if (window < floor) 0 else window;
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

/// The octets of `payload_len` that `write_data` sends now on `stream_id` into a buffer of
/// `room_len` octets, or 0 for a stream that takes no DATA frame now.
pub fn sendable_len(target: *Connection, stream_id: u32, room_len: usize, payload_len: usize) usize {
    const found = target.streams.lookup(stream_id);
    // RFC 9113 §5.1: a stream the table holds no record for is idle or closed, and takes nothing.
    if (found != .live) return 0;
    const record = found.live;
    // RFC 9113 §5.1: a frame the state does not permit is one colibri never puts on the wire.
    if (stream.on_send(record.state, record.closed, .data, false, target.role, record.peer_initiated) != .state) return 0;
    // RFC 9113 §8.1: a message's DATA frames follow its final header section.
    if (!record.final_sent) return 0;
    return sendable(target, record, room_len, payload_len).len;
}

/// Notes an increment the peer granted on the connection or a stream: one below the floor makes
/// the floor apply from then on (decision 110 as amended).
pub fn note_increment(target: *Connection, increment: u32) void {
    // RFC 9113 §10.5: a peer that opens a window a few octets at a time makes its sender write
    // many small frames.
    if (increment < target.data_frame_len_min) target.tiny_update_read = true;
}

const testing = std.testing;
const window_module = @import("../window.zig");
const connection_send = @import("connection_send.zig");
const support = @import("connection_test_support.zig");
const Writer = @import("core").Writer;
const test_connection = &support.test_connection;
const test_output = &support.test_output;

/// The floor the tests set, the octets of their body, and the status of their response. Test-only.
const floor_len: u32 = 1_024;
const body_len: usize = 2_048;
const ok: u16 = 200;
const test_body: [constants.frame_size_max + 1]u8 = @splat('x');

/// A server that has read a request on stream 1 and answered it with a head, with a floor of
/// `floor_len` that applies, as after a small increment, and a stream window of `stream_window`
/// octets. Test-only.
fn start(stream_window: u32) !*Stream {
    try support.start_server();
    _ = try support.feed_request(1, "/", true);
    _ = try connection_send.write_response(test_connection, test_output, 1, ok, &.{}, false);
    test_connection.data_frame_len_min = floor_len;
    test_connection.tiny_update_read = true;
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

test "decision 110 as amended: a peer that asks for windows under the floor gets frames that fit them" {
    _ = try start(1);
    test_connection.peer.initial_window_size = floor_len - 1;
    try testing.expectEqual(1, (try connection_send.write_data(test_connection, test_output, 1, test_body[0..body_len], true)).consumed);
    // At the floor, the floor holds a frame short of it again.
    test_connection.peer.initial_window_size = floor_len;
    try testing.expectEqual(0, (try connection_send.write_data(test_connection, test_output, 1, test_body[0..body_len], true)).consumed);
}

test "decision 110: with no floor, a window of one octet sends one" {
    _ = try start(1);
    test_connection.data_frame_len_min = 0;
    try testing.expectEqual(1, (try connection_send.write_data(test_connection, test_output, 1, test_body[0..body_len], true)).consumed);
}

test "decision 110 as amended: until the peer sends an increment below the floor, a short window sends what fits" {
    _ = try start(floor_len - 1);
    test_connection.tiny_update_read = false;
    const sent = try connection_send.write_data(test_connection, test_output, 1, test_body[0..body_len], true);
    try testing.expectEqual(floor_len - 1, sent.consumed);
    try testing.expectEqual(.stream_window, sent.short_by);
}

/// A WINDOW_UPDATE frame on `stream_id` granting `increment` octets. Test-only.
fn window_update(stream_id: u32, increment: u32) ![]const u8 {
    var payload: [constants.window_update_len]u8 = undefined;
    var writer = Writer.init(&payload);
    try writer.write_int(u32, increment);
    return support.frame_bytes(&support.test_input, constants.frame_type_window_update, 0, stream_id, writer.written());
}

test "RFC 9113 §10.5: an increment below the floor, on the connection or a stream, makes the floor apply" {
    _ = try start(floor_len);
    test_connection.tiny_update_read = false;
    // An increment of the floor or more leaves it off.
    _ = try support.feed(try window_update(constants.connection_stream_id, floor_len));
    _ = try support.feed(try window_update(1, floor_len));
    try testing.expect(!test_connection.tiny_update_read);
    _ = try support.feed(try window_update(1, floor_len - 1));
    try testing.expect(test_connection.tiny_update_read);
    test_connection.tiny_update_read = false;
    _ = try support.feed(try window_update(constants.connection_stream_id, floor_len - 1));
    try testing.expect(test_connection.tiny_update_read);
}

test "decision 110 as amended: a new connection's floor waits for a small increment" {
    // The tests above leave the connection with the floor on.
    try support.start_server();
    try testing.expect(!test_connection.tiny_update_read);
}

test "decision 119: sendable_len is what write_data sends, under the windows, the floor and the room" {
    const record = try start(floor_len - 1);
    // A window below the floor holds no frame of a longer payload, and all of a shorter one.
    try testing.expectEqual(0, test_connection.sendable_len(1, test_output.len, body_len));
    try testing.expectEqual(floor_len - 1, test_connection.sendable_len(1, test_output.len, floor_len - 1));
    record.send_window = window_module.Window.init(floor_len);
    try testing.expectEqual(floor_len, test_connection.sendable_len(1, test_output.len, body_len));
    // RFC 9113 §4.1: the room holds the frame's header before its payload.
    try testing.expectEqual(room_payload_len, test_connection.sendable_len(1, constants.frame_header_len + room_payload_len, body_len));
    const sent = try connection_send.write_data(test_connection, test_output, 1, test_body[0..body_len], false);
    try testing.expectEqual(floor_len, sent.consumed);
}

/// Payload octets a test's room holds after a frame's header. Test-only.
const room_payload_len: usize = 10;

test "RFC 9113 §5.1, §8.1: a stream before its final head, unknown, or reset, has nothing to send" {
    _ = try start(floor_len);
    // Stream 3's request is read and not answered, and stream 5 was never opened.
    _ = try support.feed_request(3, "/", true);
    try testing.expectEqual(0, test_connection.sendable_len(3, test_output.len, body_len));
    try testing.expectEqual(0, test_connection.sendable_len(5, test_output.len, body_len));
    try testing.expect(test_connection.sendable_len(1, test_output.len, body_len) > 0);
    try test_connection.reset_stream(1, constants.error_cancel);
    try testing.expectEqual(0, test_connection.sendable_len(1, test_output.len, body_len));
}
