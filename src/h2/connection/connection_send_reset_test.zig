//! The tests of a RST_STREAM the caller asks for (`connection_send.zig`): the stream's record owes
//! it, so it needs no slot in the reply queue. A caller may reset every stream it holds between two
//! writes, whatever the queue holds, and each frame goes out once (decision 113). Split out of
//! `connection_send.zig` for length.
const std = @import("std");
const core = @import("core");
const constants = @import("../constants.zig");
const frame = @import("../frame/frame.zig");
const connection = @import("connection.zig");
const support = @import("connection_test_support.zig");

const testing = std.testing;
const test_connection = &support.test_connection;
const test_input = &support.test_input;
const test_output = &support.test_output;

/// Octets of one RST_STREAM frame: a header and an error code (RFC 9113 §6.4). Test-only.
const rst_stream_frame_len = constants.frame_header_len + constants.rst_stream_len;

/// A request with every pseudo-header field RFC 9113 §8.3.1 requires. Test-only.
const test_request: connection.Request_ = .{ .method = "GET", .scheme = "https", .path = "/", .authority = "example.com" };

/// The identifier of the `index`th stream a client opens, counting from 0 (RFC 9113 §5.1.1).
/// Test-only.
fn client_id(index: usize) u32 {
    return constants.stream_id_client_first + constants.stream_id_step * @as(u32, @intCast(index));
}

/// Feeds the requests that open the first `count` streams a client opens, none ending its stream.
/// Test-only.
fn open_streams(count: usize) !void {
    for (0..count) |index| _ = try support.feed_request(client_id(index), "/", false);
}

/// Resets the first `count` streams a client opens, with CANCEL. Test-only.
fn reset_streams(count: usize) !void {
    for (0..count) |index| try test_connection.reset_stream(client_id(index), constants.error_cancel);
}

/// The stream identifiers of the RST_STREAM frames in `written`, in the order they were written,
/// each required to carry CANCEL. Test-only.
fn reset_ids(written: []const u8, ids: []u32) ![]const u32 {
    var reader = core.Reader.init(written);
    var count: usize = 0;
    for (0..written.len) |_| {
        if (reader.remaining_len() == 0) break;
        const header = try frame.read_header(&reader);
        const payload = try reader.take(header.length);
        if (header.type != constants.frame_type_rst_stream) continue;
        try testing.expectEqual(constants.error_cancel, std.mem.readInt(u32, payload[0..constants.rst_stream_len], .big));
        ids[count] = header.stream_id;
        count += 1;
    }
    return ids[0..count];
}

/// The RST_STREAM frames the connection has owed since the last write, written out. Test-only.
fn written_resets(ids: []u32) ![]const u32 {
    return reset_ids(support.write_queued(), ids);
}

test "a caller resets every stream it holds between two writes, and each RST_STREAM goes out once" {
    try support.start_server();
    try open_streams(constants.concurrent_streams_max);
    // More resets than the reply queue has slots, and nothing written between them.
    try testing.expect(constants.concurrent_streams_max > constants.stream_replies_max);
    try reset_streams(constants.concurrent_streams_max);
    try testing.expect(test_connection.has_pending());
    var ids: [constants.concurrent_streams_max]u32 = undefined;
    const written = try written_resets(&ids);
    try testing.expectEqual(constants.concurrent_streams_max, written.len);
    // The records are written in slot order, which here is the order the streams opened.
    for (written, 0..) |stream_id, index| try testing.expectEqual(client_id(index), stream_id);
    try testing.expect(!test_connection.has_pending());
    try testing.expectEqual(0, support.write_queued().len);
}

test "a caller's reset needs no slot in a queue the peer's DATA filled with WINDOW_UPDATE frames" {
    try support.start_server();
    try open_streams(2);
    // Every second full frame reaches the threshold and owes stream 1 a WINDOW_UPDATE (§6.9.1).
    var payload: [constants.frame_size_max]u8 = @splat('x');
    const data = try support.frame_bytes(test_input, constants.frame_type_data, 0, client_id(0), &payload);
    for (0..2 * constants.stream_replies_max) |_| _ = try support.feed(data);
    try testing.expect(test_connection.replies.is_full());
    try testing.expectEqual(0, (try test_connection.receive(data, 0)).consumed);
    try test_connection.reset_stream(client_id(1), constants.error_cancel);
    const written = support.write_queued();
    var ids: [1]u32 = undefined;
    try testing.expectEqualSlices(u32, &.{client_id(1)}, try reset_ids(written, &ids));
    // The queued WINDOW_UPDATE frames go first, then the RST_STREAM the record owes.
    try testing.expectEqual(constants.frame_type_rst_stream, written[written.len - rst_stream_frame_len + constants.frame_length_len]);
    try testing.expect(!test_connection.has_pending());
}

test "a server whose every slot holds a stream still owed its RST_STREAM reads no frame until the caller writes" {
    try support.start_server();
    try open_streams(constants.concurrent_streams_max);
    try reset_streams(constants.concurrent_streams_max);
    // The next stream needs a slot, and no record may be dropped before its frame is written.
    var block: [constants.frame_size_max]u8 = undefined;
    const next = client_id(constants.concurrent_streams_max);
    const fragment = try support.request_block(&block, "/");
    const request = try support.frame_bytes(test_input, constants.frame_type_headers, constants.flag_end_headers, next, fragment);
    try testing.expectEqual(0, (try test_connection.receive(request, 0)).consumed);
    try testing.expect(test_connection.has_pending());
    var ids: [constants.concurrent_streams_max]u32 = undefined;
    try testing.expectEqual(constants.concurrent_streams_max, (try written_resets(&ids)).len);
    try testing.expectEqual(next, (try support.feed(request)).?.request.stream_id);
}

test "an open drops the oldest closed record whose RST_STREAM is not owed, and never one that is" {
    try support.start_server();
    try open_streams(constants.concurrent_streams_max);
    // Every stream but the last closes by the caller's reset, before the last closes by END_STREAM.
    const resets = constants.concurrent_streams_max - 1;
    try reset_streams(resets);
    const last = client_id(resets);
    _ = try support.feed(try support.frame_bytes(test_input, constants.frame_type_data, constants.flag_end_stream, last, ""));
    _ = try test_connection.write_response(test_output, last, 200, &.{}, true);
    // The pool is full, and the one record it may drop is the stream that ended.
    _ = try support.feed_request(client_id(constants.concurrent_streams_max), "/", false);
    try testing.expect(test_connection.streams.lookup(last) != .live);
    var ids: [constants.concurrent_streams_max]u32 = undefined;
    try testing.expectEqual(resets, (try written_resets(&ids)).len);
    try testing.expect(!test_connection.has_pending());
}

test "a client opens no stream while every slot holds a stream still owed its RST_STREAM" {
    try support.start_client();
    for (0..constants.concurrent_streams_max) |_| {
        const sent = try test_connection.write_request(test_output, test_request, &.{}, &.{}, false);
        try test_connection.reset_stream(sent.stream_id, constants.error_cancel);
    }
    try testing.expectError(error.Full, test_connection.write_request(test_output, test_request, &.{}, &.{}, false));
    var ids: [constants.concurrent_streams_max]u32 = undefined;
    try testing.expectEqual(constants.concurrent_streams_max, (try written_resets(&ids)).len);
    const sent = try test_connection.write_request(test_output, test_request, &.{}, &.{}, false);
    try testing.expectEqual(client_id(constants.concurrent_streams_max), sent.stream_id);
}

test "a client reads its open stream's response while every other slot owes a RST_STREAM" {
    try support.start_client();
    const kept = try test_connection.write_request(test_output, test_request, &.{}, &.{}, true);
    for (1..constants.concurrent_streams_max) |_| {
        const sent = try test_connection.write_request(test_output, test_request, &.{}, &.{}, false);
        try test_connection.reset_stream(sent.stream_id, constants.error_cancel);
    }
    // A response opens no stream at a client (decision 17), so nothing waits for a slot.
    const event = (try support.feed_response(kept.stream_id, "200", true)).?;
    try testing.expectEqual(kept.stream_id, event.response.stream_id);
    var ids: [constants.concurrent_streams_max]u32 = undefined;
    try testing.expectEqual(constants.concurrent_streams_max - 1, (try written_resets(&ids)).len);
}

test "a RST_STREAM that does not fit stays owed, and the GOAWAY waits for every one (§6.8)" {
    try support.start_server();
    try open_streams(2);
    try reset_streams(2);
    test_connection.shutdown(constants.error_no_error);
    // Room for one RST_STREAM and part of the next: one is written, whole.
    const room = rst_stream_frame_len + constants.frame_header_len;
    try testing.expectEqual(rst_stream_frame_len, test_connection.write_pending(test_output[0..room], 0));
    try testing.expect(test_connection.has_pending());
    const rest = support.write_queued();
    var ids: [1]u32 = undefined;
    try testing.expectEqualSlices(u32, &.{client_id(1)}, try reset_ids(rest, &ids));
    // RFC 9113 §6.8: the GOAWAY is the last frame, after the RST_STREAM frames owed before it.
    try testing.expectEqual(constants.frame_type_goaway, rest[rst_stream_frame_len + constants.frame_length_len]);
    try testing.expectEqual(rst_stream_frame_len + constants.frame_header_len + constants.goaway_len_min, rest.len);
    try testing.expect(!test_connection.has_pending());
}
