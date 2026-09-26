//! What the caller asks the connection to send: a response at a server, the DATA that follows it, a RST_STREAM that ends one stream and the GOAWAY that ends the connection.
//! Every one writes into the caller's buffer and returns the octets it wrote (design §4.1); none
//! of them touches a socket.
//!
//! A field section is encoded into the connection's own block buffer and then cut into a HEADERS
//! frame and as many CONTINUATION frames as it needs, each at most the peer's
//! SETTINGS_MAX_FRAME_SIZE (RFC 9113 §4.2, §6.10). The buffer is `send_block_len_max` octets,
//! which the section limit colibri advertises bounds.
//!
//! DATA is bounded by four things at once: what the connection's send window holds, what the
//! stream's holds (§6.9.1), what one frame carries and what the caller's buffer has room for. The
//! call writes what all four allow and says how much of the payload that was, so a caller loops
//! until the whole payload is sent or a call sends nothing, and waits for a WINDOW_UPDATE when a
//! call sends nothing.
//!
//! The state machine decides every send before a frame is written (§5.1): a frame colibri may not
//! send on a stream is `error.StreamNotSendable` and writes nothing, which is the `illegal` verdict
//! `stream.zig` names. Nothing here ends the connection: only the peer's frames do that.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const http = @import("http");
const hpack = @import("hpack");
const constants = @import("../constants.zig");
const frame = @import("../frame/frame.zig");
const stream = @import("../stream/stream.zig");
const streams_table = @import("../stream/streams.zig");
const connection = @import("connection.zig");

const Connection = connection.Connection;
const Stream = streams_table.Stream;
const Writer = core.Writer;

/// Why a send did not happen. Both leave the connection and the caller's buffer as they were.
pub const Error = error{
    /// RFC 9113 §5.1 does not let colibri send this frame on this stream, or the stream is not one
    /// colibri holds a record for.
    StreamNotSendable,
    /// The caller's buffer is too small for the frame, or the field section does not fit the connection's `send_block_len_max` buffer. A larger caller buffer sends the same frame only in the first case; a section past the buffer is refused whole (RFC 9113 §4.3).
    OutputTooSmall,
    /// The status is not a three-digit code RFC 9110 §15 defines.
    StatusInvalid,
};

/// What `write_data` did: the octets of the payload it sent, and the octets it wrote.
pub const DataWritten = struct {
    /// Octets of the caller's payload that went into frames. 0 means no window or no room.
    consumed: usize,
    /// Octets written into the caller's buffer, headers included.
    written: usize,
};

/// Writes the response field section for `stream_id`: a `:status` pseudo-header field and the
/// field lines after it (RFC 9113 §8.3.2). A server's call.
pub fn write_response(
    target: *Connection,
    output: []u8,
    stream_id: u32,
    status: u16,
    fields: []const hpack.Field,
    end_stream: bool,
) Error!usize {
    assert(target.role == .server);
    const record = try sendable(target, stream_id, .headers, end_stream);
    const block = try encode_response(target, status, fields);
    const written = try write_block(target, output, stream_id, block, end_stream);
    const verdict = stream.on_send(record.state, record.closed, .headers, end_stream, target.role, record.peer_initiated);
    target.streams.transition(record, verdict, .send, .headers, end_stream);
    return written;
}

/// Writes as much of `payload` as the windows, one frame and the caller's buffer allow, as DATA on
/// `stream_id` (RFC 9113 §6.1). END_STREAM is set only on the frame that carries the last octet.
pub fn write_data(
    target: *Connection,
    output: []u8,
    stream_id: u32,
    payload: []const u8,
    end_stream: bool,
) Error!DataWritten {
    const record = try sendable(target, stream_id, .data, end_stream);
    const room = sendable_len(target, record, output, payload.len);
    // A frame that carries nothing and ends nothing is one RFC 9113 §6.1 has no use for.
    if (room == 0 and !(payload.len == 0 and end_stream)) return .{ .consumed = 0, .written = 0 };
    const last = room == payload.len;
    const flag = end_stream and last;
    var writer = Writer.init(output);
    // RFC 9113 §4.1: a frame is its header and its whole payload, so a buffer that holds less
    // holds no frame at all.
    frame.write_data(&writer, stream_id, payload[0..room], flag, 0) catch return error.OutputTooSmall;
    spend_windows(target, record, @intCast(room));
    const verdict = stream.on_send(record.state, record.closed, .data, flag, target.role, record.peer_initiated);
    target.streams.transition(record, verdict, .send, .data, flag);
    return .{ .consumed = room, .written = writer.written().len };
}

/// Ends one stream with a RST_STREAM the caller asked for (RFC 9113 §6.4). The frame is queued
/// with the connection's other replies, and `write_pending` writes it.
pub fn reset(target: *Connection, stream_id: u32, error_code: u32) Error!void {
    const record = try sendable(target, stream_id, .rst_stream, false);
    const verdict = stream.on_send(record.state, record.closed, .rst_stream, false, target.role, record.peer_initiated);
    target.streams.transition(record, verdict, .send, .rst_stream, false);
    // RFC 9113 §5.1: the RST_STREAM closes the stream, so no WINDOW_UPDATE may go out after it.
    target.replies.drop_window_updates(stream_id);
    target.replies.push_stream_reply(.{ .stream_id = stream_id, .kind = .rst_stream, .value = error_code });
}

/// Ends the connection gracefully: the GOAWAY of RFC 9113 §6.8 naming the last stream colibri
/// acted on, queued for `write_pending`. The connection goes on reading the streams below it.
pub fn shutdown(target: *Connection, error_code: u32) void {
    const last_stream_id = target.streams.last_peer_stream_id();
    target.streams.record_goaway_sent(last_stream_id);
    target.replies.set_goaway(.{ .last_stream_id = last_stream_id, .error_code = error_code });
}

/// The record of `stream_id`, when RFC 9113 §5.1 lets colibri send a frame of `kind` on it.
fn sendable(target: *Connection, stream_id: u32, kind: stream.Kind, end_stream: bool) Error!*Stream {
    const found = target.streams.lookup(stream_id);
    // RFC 9113 §5.1: a stream the table holds no record for is idle or closed, and colibri sends
    // nothing on either; a stream it opens goes through the table first.
    if (found != .live) return error.StreamNotSendable;
    const record = found.live;
    const verdict = stream.on_send(record.state, record.closed, kind, end_stream, target.role, record.peer_initiated);
    // RFC 9113 §5.1: a frame the state does not permit is one colibri never puts on the wire.
    if (verdict != .state) return error.StreamNotSendable;
    return record;
}

/// Encodes the response's field section into the connection's block buffer (RFC 9113 §8.3.2).
fn encode_response(target: *Connection, status: u16, fields: []const hpack.Field) Error![]const u8 {
    var writer = Writer.init(&target.send_block);
    // RFC 7541 §4.2: a block may open with the size updates the encoder owes, and a buffer that
    // cannot hold them holds no block. The buffer is `send_block_len_max` (design §7).
    target.encoder.begin_block(&writer) catch return error.OutputTooSmall;
    var digits: [http.constants.status_digits_len]u8 = undefined;
    // RFC 9110 §15: a status code is a three-digit integer between 100 and 599.
    const code = http.status.Status.from_code(status) catch return error.StatusInvalid;
    const status_text = code.write_digits(&digits);
    // RFC 9113 §8.3.2: a response carries the `:status` pseudo-header field, and it comes first.
    target.encoder.write_field(&writer, ":status", status_text, .without_indexing) catch return error.OutputTooSmall;
    for (fields) |field_line| {
        target.encoder.write_field(&writer, field_line.name, field_line.value, .without_indexing) catch {
            // RFC 9113 §4.3: a field block is one sequence, so a section past the buffer is
            // refused whole rather than cut.
            return error.OutputTooSmall;
        };
    }
    // RFC 7541 §4.2: the block is whole, so the capacity its updates named is the peer's now.
    target.encoder.commit_block();
    return writer.written();
}

/// Cuts `block` into a HEADERS frame and the CONTINUATION frames it needs, each at most the peer's
/// SETTINGS_MAX_FRAME_SIZE (RFC 9113 §4.2, §6.10).
pub fn write_block(target: *Connection, output: []u8, stream_id: u32, block: []const u8, end_stream: bool) Error!usize {
    var writer = Writer.init(output);
    var offset: usize = 0;
    const limit = target.peer.max_frame_size;
    for (0..constants.continuation_count_max + 1) |index| {
        const end = @min(offset + limit, block.len);
        const last = end == block.len;
        const fragment = block[offset..end];
        if (index == 0) {
            frame.write_headers(&writer, stream_id, fragment, end_stream, last, 0, null) catch {
                // RFC 9113 §6.2: the block opens in a HEADERS frame, whole or not at all.
                return error.OutputTooSmall;
            };
        } else {
            // RFC 9113 §6.10: the rest of the block is sent in CONTINUATION frames.
            frame.write_continuation(&writer, stream_id, fragment, last) catch return error.OutputTooSmall;
        }
        offset = end;
        if (last) return writer.written().len;
    }
    // The block is bounded by `send_block_len_max` and a frame carries at least
    // `max_frame_size_min`, so it never needs more frames than `continuation_count_max` allows.
    unreachable;
}

/// The octets of a payload the two windows, one frame and the caller's buffer allow.
fn sendable_len(target: *const Connection, record: *const Stream, output: []const u8, payload_len: usize) usize {
    // RFC 9113 §6.9.1: a sender spends both the stream's window and the connection's.
    const windows = @min(target.send_window.sendable(), record.send_window.sendable());
    const room = if (output.len > constants.frame_header_len) output.len - constants.frame_header_len else 0;
    return @min(@min(windows, target.peer.max_frame_size), @min(room, payload_len));
}

/// Takes `len` octets out of both send windows (RFC 9113 §6.9.1).
fn spend_windows(target: *Connection, record: *Stream, len: u32) void {
    // `sendable_len` took the smaller of the two windows, so neither can be exceeded here.
    target.send_window.consume(len) catch unreachable;
    record.send_window.consume(len) catch unreachable;
}

const testing = std.testing;
const test_connection = &connection.test_connection;
const feed = connection.feed;
const feed_request = connection.feed_request;
const frame_bytes = connection.frame_bytes;
const start_server = connection.start_server;
const write_queued = connection.write_queued;
const test_input = &connection.test_input;
const test_output = &connection.test_output;

/// A response body the tests send. Test-only.
const test_body = "hello";

/// Where the tests that send more than one frame write: the largest block and the frame headers
/// that cut it. Test-only.
var test_large_output: [constants.send_block_len_max + constants.frame_size_max]u8 = @splat(0);

test "a response ends the stream, and a HEADERS frame on it afterwards is STREAM_CLOSED (http2/5.1/12)" {
    try start_server();
    _ = try feed_request(1, "/", true);
    const written = try write_response(test_connection, test_output, 1, 200, &.{}, true);
    try testing.expectEqual(constants.frame_type_headers, test_output[3]);
    try testing.expectEqual(constants.flag_end_stream | constants.flag_end_headers, test_output[4]);
    try testing.expect(written > constants.frame_header_len);
    const record = test_connection.streams.lookup(1).live;
    try testing.expectEqual(stream.State.closed, record.state);
    try testing.expectEqual(stream.Closed.end_stream, record.closed.?);
    try testing.expectEqual(0, test_connection.streams.peer_active);
    // The table still holds the record, so the frame the peer sends late is judged by §5.1.
    var block: [constants.frame_size_max]u8 = undefined;
    const fragment = try connection.request_block(&block, "/");
    const flags = constants.flag_end_headers | constants.flag_end_stream;
    const late = try frame_bytes(test_input, constants.frame_type_headers, flags, 1, fragment);
    try testing.expectEqual(error.ConnectionFailed, test_connection.receive(late, 0));
    try testing.expectEqual(constants.error_stream_closed, test_connection.failure.?);
}

test "a response and its body: the DATA frame carries END_STREAM and spends both windows" {
    try start_server();
    _ = try feed_request(1, "/", true);
    const head_len = try write_response(test_connection, test_output, 1, 200, &.{
        .{ .name = "content-type", .value = "text/plain" },
    }, false);
    const sent = try write_data(test_connection, test_output[head_len..], 1, test_body, true);
    try testing.expectEqual(test_body.len, sent.consumed);
    try testing.expectEqual(constants.frame_header_len + test_body.len, sent.written);
    const data = test_output[head_len..][0..sent.written];
    try testing.expectEqual(constants.frame_type_data, data[3]);
    try testing.expectEqual(constants.flag_end_stream, data[4]);
    try testing.expectEqualStrings(test_body, data[constants.frame_header_len..]);
    const spent: i64 = constants.initial_window_size_initial - test_body.len;
    try testing.expectEqual(spent, test_connection.send_window.available);
    const record = test_connection.streams.lookup(1).live;
    try testing.expectEqual(stream.State.closed, record.state);
}

test "write_data sends what the windows allow and no more, and says how much that was" {
    try start_server();
    _ = try feed_request(1, "/", true);
    _ = try write_response(test_connection, test_output, 1, 200, &.{}, false);
    const record = test_connection.streams.lookup(1).live;
    record.send_window = @import("../window.zig").Window.init(2);
    var body: [8]u8 = @splat('x');
    const first = try write_data(test_connection, test_output, 1, &body, true);
    try testing.expectEqual(2, first.consumed);
    // The window is empty, so the next call writes nothing and the stream stays open.
    const stalled = try write_data(test_connection, test_output, 1, body[2..], true);
    try testing.expectEqual(0, stalled.consumed);
    try testing.expectEqual(0, stalled.written);
    try testing.expectEqual(stream.State.half_closed_remote, record.state);
    // A WINDOW_UPDATE from the peer lets the rest be sent, with END_STREAM on the last frame.
    const update = try frame_bytes(test_input, constants.frame_type_window_update, 0, 1, "\x00\x00\x00\x06");
    _ = try feed(update);
    const rest = try write_data(test_connection, test_output, 1, body[2..], true);
    try testing.expectEqual(6, rest.consumed);
    try testing.expectEqual(constants.flag_end_stream, test_output[4]);
    try testing.expectEqual(stream.State.closed, record.state);
}

test "the connection's window bounds a send as the stream's does (§6.9.1)" {
    try start_server();
    _ = try feed_request(1, "/", true);
    _ = try write_response(test_connection, test_output, 1, 200, &.{}, false);
    // The stream has room for the whole body and the connection has room for three octets.
    test_connection.send_window = @import("../window.zig").Window.init(3);
    var body: [8]u8 = @splat('x');
    const sent = try write_data(test_connection, test_output, 1, &body, true);
    try testing.expectEqual(3, sent.consumed);
    try testing.expectEqual(0, test_connection.send_window.available);
    const record = test_connection.streams.lookup(1).live;
    try testing.expectEqual(constants.initial_window_size_initial - 3, record.send_window.available);
    const stalled = try write_data(test_connection, test_output, 1, body[3..], true);
    try testing.expectEqual(0, stalled.consumed);
}

test "a field block longer than one frame is cut into a HEADERS frame and a CONTINUATION" {
    try start_server();
    _ = try feed_request(1, "/", true);
    // Values Huffman coding would not shorten, so the block is as long as its octets.
    var values: [5][4000]u8 = undefined;
    for (&values, 0..) |*value, index| value.* = @splat(@intCast(0x80 + index));
    var fields: [5]hpack.Field = undefined;
    const names = [_][]const u8{ "x-a", "x-b", "x-c", "x-d", "x-e" };
    for (&fields, names, &values) |*field_line, name, *value| {
        field_line.* = .{ .name = name, .value = value };
    }
    const written = try write_response(test_connection, &test_large_output, 1, 200, &fields, false);
    try testing.expect(written > constants.frame_size_max);
    // The HEADERS frame is a whole frame without END_HEADERS, and the CONTINUATION ends the block.
    try testing.expectEqual(constants.frame_type_headers, test_large_output[3]);
    try testing.expectEqual(0, test_large_output[4] & constants.flag_end_headers);
    const second = test_large_output[constants.frame_header_len + constants.frame_size_max ..];
    try testing.expectEqual(constants.frame_type_continuation, second[3]);
    try testing.expectEqual(constants.flag_end_headers, second[4]);
}

test "a send RFC 9113 §5.1 forbids writes nothing, and so does a buffer with no room" {
    try start_server();
    _ = try feed_request(1, "/", true);
    _ = try write_response(test_connection, test_output, 1, 200, &.{}, true);
    // The stream is closed, so nothing else may be sent on it.
    try testing.expectError(error.StreamNotSendable, write_response(test_connection, test_output, 1, 200, &.{}, true));
    try testing.expectError(error.StreamNotSendable, write_data(test_connection, test_output, 1, test_body, true));
    try testing.expectError(error.StreamNotSendable, reset(test_connection, 1, constants.error_cancel));
    // A stream the table never held is not sendable either.
    try testing.expectError(error.StreamNotSendable, write_response(test_connection, test_output, 7, 200, &.{}, true));
    _ = try feed_request(3, "/", true);
    var cramped: [2]u8 = undefined;
    try testing.expectError(error.OutputTooSmall, write_response(test_connection, &cramped, 3, 200, &.{}, true));
    try testing.expectError(error.StatusInvalid, write_response(test_connection, test_output, 3, 99, &.{}, true));
}

test "a RST_STREAM the caller asks for closes the stream and is queued with the other replies" {
    try start_server();
    _ = try feed_request(1, "/", false);
    try reset(test_connection, 1, constants.error_cancel);
    const record = test_connection.streams.lookup(1).live;
    try testing.expectEqual(stream.Closed.rst_stream_sent, record.closed.?);
    try testing.expectEqual(0, test_connection.streams.peer_active);
    const queued = write_queued();
    try testing.expectEqualStrings("\x00\x00\x04\x03\x00\x00\x00\x00\x01\x00\x00\x00\x08", queued);
}

test "shutdown queues a GOAWAY naming the last stream colibri acted on (§6.8)" {
    try start_server();
    _ = try feed_request(1, "/", true);
    _ = try feed_request(3, "/", true);
    shutdown(test_connection, constants.error_no_error);
    const queued = write_queued();
    try testing.expectEqualStrings("\x00\x00\x08\x07\x00\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x00", queued);
    // The connection is not failed: it goes on reading the streams below that identifier.
    try testing.expect(!test_connection.has_failed());
    const ping = try frame_bytes(test_input, constants.frame_type_ping, 0, 0, "12345678");
    try testing.expectEqual(null, try feed(ping));
    // RFC 9113 §6.8: a stream above the identifier the GOAWAY named is not opened, and its field
    // block is still decoded, so the connection can go on reading the streams below it.
    try testing.expectEqual(3, test_connection.streams.goaway_sent_last_id.?);
    const active_before = test_connection.streams.peer_active;
    try testing.expectEqual(null, try feed_request(5, "/", true));
    try testing.expectEqual(active_before, test_connection.streams.peer_active);
    try testing.expect(test_connection.streams.lookup(5) != .live);
    try testing.expect(!test_connection.has_failed());
}

test "RFC 7541 §4.2: a table-size change is declared once and not repeated on the next response" {
    try start_server();
    _ = try feed_request(1, "/", true);
    // RFC 9113 §6.5.2: SETTINGS_HEADER_TABLE_SIZE is the limit the peer sets on colibri's encoder.
    const settings = try frame_bytes(test_input, constants.frame_type_settings, 0, 0, "\x00\x01\x00\x00\x00\x64");
    _ = try connection.feed(settings);
    _ = try write_response(test_connection, test_output, 1, 200, &.{}, true);
    // RFC 7541 §4.2: the block opens with the size update the change owes, which for 100 is two
    // octets, the prefix full and the remainder 69.
    try testing.expectEqual(0x3f, test_output[constants.frame_header_len]);
    try testing.expectEqual(0x45, test_output[constants.frame_header_len + 1]);
    _ = try feed_request(3, "/", true);
    _ = try write_response(test_connection, test_output, 3, 200, &.{}, true);
    // The first block reached the peer, so the second owes nothing.
    try testing.expect(test_output[constants.frame_header_len] != 0x3f);
}
