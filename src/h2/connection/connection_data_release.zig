//! The stream credit a caller holds and gives back (RFC 9113 §6.9.1). Part of design §8 step 39,
//! beside `connection_data.zig`.
//!
//! A stream that `write_request` opened with `hold_credit` gives back no stream credit for its data
//! as its DATA frames arrive. The caller gives the credit back with `release_stream` once it has
//! used the octets, so the peer sends no more on that stream than the caller takes. The
//! connection's credit still goes back at each frame, so the other streams keep their windows.
//!
//! The program calls `release_stream`, not a frame the connection reads, so the reply queue can be
//! full. The credit then stays in the stream's `released` count, and `write_replies` queues the
//! WINDOW_UPDATE once the queue has room again.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const streams_table = @import("../stream/streams.zig");
const connection = @import("connection.zig");

const Connection = connection.Connection;
const Stream = streams_table.Stream;

/// Gives back `len` octets of the stream credit `stream_id` holds. It does nothing on a stream the
/// table no longer holds, and queues no WINDOW_UPDATE on a stream the peer can send no more on
/// (RFC 9113 §5.1).
pub fn release_stream(target: *Connection, stream_id: u32, len: u32) void {
    const record = switch (target.streams.lookup(stream_id)) {
        .live => |record| record,
        // RFC 9113 §5.1: the stream is closed, so no WINDOW_UPDATE may go out on it.
        .idle, .reset_and_dropped, .forgotten => return,
    };
    assert(record.hold_credit);
    assert(len <= record.receive.unreleased);
    // RFC 9113 §5.1: once the peer ended its side, or the stream closed, no DATA comes on it and
    // no WINDOW_UPDATE may follow. The count still moves, so the window stays whole.
    if (!receives_data(record)) {
        _ = record.receive.release(len);
        return;
    }
    if (!has_stream_room(target)) {
        record.receive.release_later(len);
        target.stream_credit_waiting = true;
        return;
    }
    const increment = record.receive.release(len) orelse return;
    push_update(target, record, increment);
}

/// Queues the WINDOW_UPDATE frames that `release_stream` kept back for want of room, as many as
/// the queue holds now. `write_replies` calls it once its first write has made room.
pub fn queue_waiting(target: *Connection) void {
    assert(target.stream_credit_waiting);
    // RFC 9113 §6.8: a connection that failed sends its GOAWAY last, so it owes no more credit.
    if (target.failure != null) {
        target.stream_credit_waiting = false;
        return;
    }
    var records = target.streams.iterator();
    // Bounded by the table's capacity, `concurrent_streams_max`.
    while (records.next()) |record| {
        if (!record.hold_credit or !receives_data(record)) continue;
        if (record.receive.released < constants.policy.window_update_threshold) continue;
        if (!has_stream_room(target)) return;
        // The credit is at the threshold, so a release of no more octets gives all of it back.
        push_update(target, record, record.receive.release(0).?);
    }
    target.stream_credit_waiting = false;
}

/// Whether the peer may still send DATA on the stream: it is open, or only colibri ended its side
/// (RFC 9113 §5.1).
fn receives_data(record: *const Stream) bool {
    return record.state == .open or record.state == .half_closed_local;
}

fn has_stream_room(target: *const Connection) bool {
    return target.replies.stream_reply_count < constants.limits.stream_replies_max;
}

fn push_update(target: *Connection, record: *const Stream, increment: u32) void {
    assert(record.id <= constants.protocol.stream_id_max);
    target.replies.push_stream_reply(.{
        .stream_id = @intCast(record.id),
        .kind = .window_update,
        .value = increment,
    });
}

const testing = std.testing;
const support = @import("connection_test_support.zig");
const test_connection = &support.test_connection;
const feed_data = support.feed_data;
const updates_on = support.updates_on;
const write_queued = support.write_queued;

/// The largest DATA payload the peer sends colibri (RFC 9113 §4.2). Test-only.
const full_payload: [constants.limits.frame_size_max]u8 = @splat('x');

/// Opens stream 1 at a client with `hold_credit`, and reads the response's head. Test-only.
fn open_held_stream() !void {
    try open_held_stream_ending(true);
}

/// As `open_held_stream`, with the request's own side ended when `end_stream`, and left open for
/// its content otherwise. Test-only.
fn open_held_stream_ending(end_stream: bool) !void {
    try support.start_client();
    const request: connection.Connection.RequestHead = .{ .method = "POST", .scheme = "https", .path = "/", .authority = "a", .hold_credit = true };
    const sent = try test_connection.write_request(&support.test_output, &request, &.{}, &.{}, end_stream);
    try testing.expectEqual(1, sent.stream_id);
    _ = try support.feed_response(1, "200", false);
}

/// Feeds the peer's whole stream window on stream 1 in full frames. Test-only.
fn fill_stream_window() !void {
    var left: usize = constants.protocol.initial_window_size_initial;
    // Bounded: each frame carries at least one octet of what is left.
    while (left > 0) {
        const len = @min(left, full_payload.len);
        _ = (try feed_data(1, full_payload[0..len], false)).?.data;
        left -= len;
    }
}

test "§6.9: a held stream owes no WINDOW_UPDATE for its whole window, and the connection's goes back" {
    try open_held_stream();
    try fill_stream_window();
    const queued = write_queued();
    try testing.expectEqual(0, try updates_on(queued, 1));
    // RFC 9113 §6.9.1: the connection's credit flows on, so the other streams keep their windows.
    try testing.expect(try updates_on(queued, constants.protocol.connection_stream_id) >= 1);
    try testing.expectEqual(constants.protocol.initial_window_size_initial, test_connection.receive_window.window.available);
    try testing.expectEqual(0, test_connection.streams.lookup(1).live.receive.window.available);
}

test "§6.9: a release gives the stream its credit back in one WINDOW_UPDATE" {
    try open_held_stream();
    try fill_stream_window();
    _ = write_queued();
    test_connection.release_stream(1, constants.protocol.initial_window_size_initial);
    try testing.expect(test_connection.owes_window_update());
    try testing.expectEqual(1, try updates_on(write_queued(), 1));
    const record = test_connection.streams.lookup(1).live;
    try testing.expectEqual(constants.protocol.initial_window_size_initial, record.receive.window.available);
    try testing.expect(!test_connection.owes_window_update());
}

test "§5.1: a release on a stream the peer ended, or one the table forgot, queues nothing" {
    try open_held_stream();
    _ = try feed_data(1, &full_payload, false);
    _ = try feed_data(1, &full_payload, true);
    _ = write_queued();
    test_connection.release_stream(1, 2 * full_payload.len);
    try testing.expectEqual(0, try updates_on(write_queued(), 1));
    test_connection.release_stream(1001, 1);
    try testing.expect(!test_connection.has_pending());
}

/// The stream that gives its credit back at each frame, beside the held stream 1. Test-only.
const plain_stream_id: u32 = 3;
/// Full frames for each WINDOW_UPDATE a stream owes: two pass `window_update_threshold`.
/// Test-only.
const frames_per_update: usize = 2;

/// Holds two full frames of credit on stream 1, and fills the reply queue with stream 3's
/// WINDOW_UPDATE frames. Test-only.
fn fill_reply_queue() !void {
    try open_held_stream();
    _ = try feed_data(1, &full_payload, false);
    _ = try feed_data(1, &full_payload, false);
    const plain: connection.Connection.RequestHead = .{ .method = "GET", .scheme = "https", .path = "/", .authority = "a" };
    _ = try test_connection.write_request(&support.test_output, &plain, &.{}, &.{}, true);
    _ = try support.feed_response(plain_stream_id, "200", false);
    for (0..frames_per_update * constants.limits.stream_replies_max) |_| _ = try feed_data(plain_stream_id, &full_payload, false);
    try testing.expectEqual(constants.limits.stream_replies_max, test_connection.replies.stream_reply_count);
}

test "a release while the reply queue is full keeps its credit until the queue empties" {
    try fill_reply_queue();
    test_connection.release_stream(1, 2 * full_payload.len);
    try testing.expect(test_connection.owes_window_update());
    const queued = write_queued();
    try testing.expectEqual(1, try updates_on(queued, 1));
    try testing.expectEqual(constants.limits.stream_replies_max, try updates_on(queued, 3));
    try testing.expect(!test_connection.owes_window_update());
    try testing.expect(!test_connection.has_pending());
}

test "§6.9.1: a held stream that is open both ways gets its credit back at a release" {
    try open_held_stream_ending(false);
    try testing.expectEqual(.open, test_connection.streams.lookup(1).live.state);
    try fill_stream_window();
    _ = write_queued();
    test_connection.release_stream(1, constants.protocol.initial_window_size_initial);
    try testing.expectEqual(1, try updates_on(write_queued(), 1));
}

/// The data and the padding of the padded DATA frame the peer sends. Test-only.
const padded_data_len: usize = 100;
const padding_len: u8 = 50;

test "§6.1: a held stream gets a DATA frame's padding back at once, and holds its data" {
    try open_held_stream();
    // RFC 9113 §6.1: the Pad Length octet, the data, then the padding.
    var payload: [1 + padded_data_len + padding_len]u8 = @splat(0);
    payload[0] = padding_len;
    const bytes = try support.frame_bytes(&support.test_input, constants.protocol.frame_type_data, constants.protocol.flag_padded, 1, &payload);
    const data = (try support.feed(bytes)).?.data;
    try testing.expectEqual(padded_data_len, data.payload.len);
    const record = test_connection.streams.lookup(1).live;
    try testing.expectEqual(padded_data_len, record.receive.unreleased);
    test_connection.release_stream(1, padded_data_len);
    try testing.expectEqual(0, record.receive.unreleased);
}

test "§6.8: a connection that failed queues none of the credit a full queue kept back" {
    try fill_reply_queue();
    test_connection.release_stream(1, 2 * full_payload.len);
    try testing.expectEqual(error.ConnectionFailed, test_connection.fail(constants.protocol.error_internal_error));
    try testing.expectEqual(0, try updates_on(write_queued(), 1));
    try testing.expect(!test_connection.owes_window_update());
}

test "§6.9: credit a full queue kept back is still owed once a reset empties the queue" {
    try fill_reply_queue();
    // Only the connection's WINDOW_UPDATE fits, so the queue stays full of stream 3's.
    const update_len = constants.protocol.frame_header_len + constants.protocol.window_update_len;
    _ = test_connection.write_replies(support.test_output[0..update_len]);
    try testing.expectEqual(0, test_connection.replies.connection_increment);
    test_connection.release_stream(1, 2 * full_payload.len);
    // RFC 9113 §5.1: the caller's reset closes stream 3, and its WINDOW_UPDATE frames go.
    try test_connection.reset_stream(3, constants.protocol.error_cancel);
    try testing.expectEqual(0, test_connection.replies.stream_reply_count);
    try testing.expect(test_connection.owes_window_update());
    try testing.expectEqual(1, try updates_on(write_queued(), 1));
    try testing.expect(!test_connection.owes_window_update());
}
