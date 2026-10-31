//! The DATA frame whose data the caller writes itself (decision 138): colibri writes the frame's
//! header and charges both flow-control windows, as `write_data` does, and the caller writes the
//! data after the header from its own buffer, with no copy through colibri.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const frame = @import("../frame/frame.zig");
const stream = @import("../stream/stream.zig");
const connection = @import("connection.zig");
const connection_send = @import("connection_send.zig");
const connection_send_window = @import("connection_send_window.zig");

const Connection = connection.Connection;
const Writer = core.Writer;
const Error = connection_send.Error;
const DataWritten = connection_send.DataWritten;

/// Writes into `output` the header of the DATA frame on `stream_id` that carries the next
/// `consumed` octets of a payload `payload_len` long, as many as `write_data` would send into
/// `output`. The caller writes those octets right after the header, in `output`, before any other
/// octet of the connection. `written` counts the header alone. END_STREAM is set only on the
/// frame that carries the last octet.
pub fn write_data_header(
    target: *Connection,
    output: []u8,
    stream_id: u32,
    payload_len: usize,
    end_stream: bool,
) Error!DataWritten {
    const record = try connection_send.sendable(target, stream_id, .data, end_stream);
    // RFC 9113 §8.1: a message's DATA frames follow its final header section, so a server sends
    // none before its final response.
    if (!record.final_sent) return error.SectionOutOfOrder;
    const next = connection_send_window.sendable(target, record, output.len, payload_len);
    const room = next.len;
    // A frame that carries nothing and ends nothing is one RFC 9113 §6.1 has no use for.
    if (room == 0 and !(payload_len == 0 and end_stream)) return .{ .consumed = 0, .written = 0, .short_by = next.short_by };
    const flag = end_stream and room == payload_len;
    var writer = Writer.init(output);
    // RFC 9113 §4.1: a frame is its header and its whole payload, so a buffer that holds less
    // holds no frame at all.
    frame.write_data_header(&writer, stream_id, @intCast(room), flag) catch return error.OutputTooSmall;
    // `sendable` left room for the data after the header.
    assert(output.len >= writer.written().len + room);
    connection_send.spend_windows(target, record, @intCast(room));
    const verdict = stream.on_send(record.state, record.closed, .data, flag, target.role, record.peer_initiated);
    target.streams.transition(record, verdict, .send, .data, flag);
    return .{ .consumed = room, .written = writer.written().len, .short_by = next.short_by };
}

const testing = std.testing;
const constants = @import("../constants.zig");
const support = @import("connection_test_support.zig");
const test_connection = &support.test_connection;
const test_output = &support.test_output;

/// The octets of the test's payload, and the status of its response. Test-only.
const test_payload_len: usize = 100;
const ok: u16 = 200;
const payload: [test_payload_len]u8 = @splat('x');
/// The octets of one frame that carries the whole payload. Test-only.
const frame_len: usize = constants.protocol.frame_header_len + test_payload_len;

/// A server that has read a request on stream 1 and answered it with a head. Test-only.
fn start() !void {
    try support.start_server();
    _ = try support.feed_request(1, "/", true);
    _ = try connection_send.write_response(test_connection, test_output, 1, ok, &.{}, false);
}

test "decision 138: the header and the caller's data are the frame write_data writes, and spend as much" {
    // Where `write_data_header` and the caller write a frame, and where `write_data` writes the
    // frame it is compared with.
    var split: [frame_len]u8 = undefined;
    var whole: [frame_len]u8 = undefined;
    try start();
    const window_before = test_connection.send_window.sendable();
    const sent = try write_data_header(test_connection, &split, 1, test_payload_len, true);
    try testing.expectEqual(test_payload_len, sent.consumed);
    try testing.expectEqual(constants.protocol.frame_header_len, sent.written);
    try testing.expectEqual(window_before - test_payload_len, test_connection.send_window.sendable());
    @memcpy(split[sent.written..][0..sent.consumed], &payload);
    try start();
    const frame_written = try connection_send.write_data(test_connection, &whole, 1, &payload, true);
    try testing.expectEqual(whole.len, frame_written.written);
    // Each call ended the stream (RFC 9113 §6.1), so the record is gone after both.
    try testing.expectEqualSlices(u8, &whole, &split);
}

test "decision 138: a short output carries part of the data, without END_STREAM, and none past a frame" {
    try start();
    const room = constants.protocol.frame_header_len + test_payload_len / 2;
    const sent = try write_data_header(test_connection, test_output[0..room], 1, test_payload_len, true);
    try testing.expectEqual(test_payload_len / 2, sent.consumed);
    try testing.expectEqual(.room, sent.short_by);
    // RFC 9113 §6.1: END_STREAM is on the frame of the last octet, which is still to come.
    var reader = core.Reader.init(test_output[0..sent.written]);
    try testing.expect(!frame.has_flag(try frame.read_header(&reader), constants.protocol.flag_end_stream));
    const none = try write_data_header(test_connection, test_output[0..constants.protocol.frame_header_len], 1, test_payload_len, true);
    try testing.expectEqual(0, none.consumed);
    try testing.expectEqual(0, none.written);
    // RFC 9113 §5.1: a stream that ended takes no more DATA.
    const rest = try write_data_header(test_connection, test_output, 1, test_payload_len / 2, true);
    try testing.expectEqual(test_payload_len / 2, rest.consumed);
    try testing.expectError(error.StreamNotSendable, write_data_header(test_connection, test_output, 1, 1, true));
}

test "RFC 9113 §8.1: a server's DATA header before its final response is SectionOutOfOrder" {
    try support.start_server();
    _ = try support.feed_request(1, "/", true);
    try testing.expectError(error.SectionOutOfOrder, write_data_header(test_connection, test_output, 1, test_payload_len, true));
}
