//! DATA frames (RFC 9113 §6.1) and the flow control they spend (§6.9). Split off
//! `connection_stream.zig`, which decides which stream the frame names.
//!
//! One DATA frame is counted twice, against the connection's window and against the stream's, and
//! the two are not the same error: §6.9.1 makes the connection's a connection error of
//! FLOW_CONTROL_ERROR and the stream's a stream error of the same code. Both windows count the
//! whole payload, padding included (§6.1, §10.7), and both are released as soon as the frame is
//! handed to the caller, because colibri holds no octet of it (design §4.1).
//!
//! A DATA frame on a stream colibri has already closed still costs connection window, which §5.1
//! requires: the peer sent it before it read the close, and a receiver that did not count it would
//! stall the connection.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const frame = @import("../frame/frame.zig");
const streams_table = @import("../stream/streams.zig");
const connection = @import("connection.zig");
const stream_frames = @import("connection_stream.zig");

const Connection = connection.Connection;
const Event = connection.Event;
const Error = connection.Error;
const Stream = streams_table.Stream;

/// Reads one DATA frame.
pub fn on_data(target: *Connection, header: frame.Header, payload: frame.Data, now_ns: u64) Error!?Event {
    try count_connection_window(target, header.length);
    const found = try stream_frames.find(target, header.stream_id, .data, payload.end_stream, now_ns);
    switch (found) {
        .refused => |event| return event,
        .discard => return null,
        // Only a HEADERS frame opens a stream (RFC 9113 §5.1), so DATA never finds an idle one.
        .open => unreachable,
        .act => |acting| {
            const record = acting.record;
            if (try count_stream_window(target, header, record, now_ns)) |refused| return refused;
            // RFC 9113 §8.1: a message begins with the HEADERS frame of its field section, and at a
            // client zero or more interim responses come before it. DATA that arrives before the
            // final field section belongs to no message, which §8.1.1 makes a stream error of
            // PROTOCOL_ERROR. Both windows have counted it by now, as §6.9 requires of every DATA
            // frame.
            if (record.sections_received != .final) {
                return try stream_frames.reset_stream(target, header.stream_id, constants.error_protocol_error, now_ns);
            }
            record.data_received_len += payload.data.len;
            if (try check_content_length(target, header.stream_id, record, payload.end_stream, now_ns)) |refused| {
                return refused;
            }
            target.streams.transition(record, acting.verdict, .receive, .data, payload.end_stream);
            // RFC 9113 §5.1: the peer ended its side, so the stream's credit is never needed and
            // no WINDOW_UPDATE may follow once it closes.
            if (payload.end_stream) target.replies.drop_window_updates(header.stream_id);
            return .{ .data = .{
                .stream_id = header.stream_id,
                .payload = payload.data,
                .end_stream = payload.end_stream,
            } };
        },
    }
}

/// Counts the whole payload against the connection's receive window and releases it at once.
fn count_connection_window(target: *Connection, payload_len: u32) Error!void {
    target.receive_window.receive(payload_len) catch {
        // RFC 9113 §6.9.1: a receiver that is sent more than its connection window is a connection
        // error of FLOW_CONTROL_ERROR.
        return target.fail(constants.error_flow_control_error);
    };
    // RFC 9113 §6.9.1: the receiver gives the space back with a WINDOW_UPDATE once enough has been
    // consumed to be worth a frame, which `window.Receiver` decides.
    if (target.receive_window.release(payload_len)) |increment| {
        target.replies.add_connection_increment(increment);
    }
}

/// Counts the whole payload against the stream's receive window and releases it. The event it
/// returns is the stream's refusal, when the peer sent more than the window held.
fn count_stream_window(target: *Connection, header: frame.Header, record: *Stream, now_ns: u64) Error!?Event {
    record.receive.receive(header.length) catch {
        // RFC 9113 §6.9.1: a stream sent more than its window is a stream error of
        // FLOW_CONTROL_ERROR.
        return try stream_frames.reset_stream(target, header.stream_id, constants.error_flow_control_error, now_ns);
    };
    if (record.receive.release(header.length)) |increment| {
        target.replies.push_stream_reply(.{
            .stream_id = header.stream_id,
            .kind = .window_update,
            .value = increment,
        });
    }
    return null;
}

/// Compares the octets received with the Content-Length the message declared, once the peer says
/// it has sent them all (RFC 9113 §8.1.1).
fn check_content_length(
    target: *Connection,
    id: u32,
    record: *const Stream,
    end_stream: bool,
    now_ns: u64,
) Error!?Event {
    if (!end_stream) return null;
    const declared = record.content_length orelse return null;
    if (declared == record.data_received_len) return null;
    // RFC 9113 §8.1.1: a message whose content-length does not equal the sum of its DATA payload
    // lengths is malformed, and a malformed message is a stream error of PROTOCOL_ERROR.
    return try stream_frames.reset_stream(target, id, constants.error_protocol_error, now_ns);
}

const testing = std.testing;
const core = @import("core");
const window = @import("../window.zig");
const Writer = core.Writer;
const test_connection = &connection.test_connection;
const feed = connection.feed;
const feed_request = connection.feed_request;
const frame_bytes = connection.frame_bytes;
const start_server = connection.start_server;
const start_client = connection.start_client;
const feed_response = connection.feed_response;
const write_queued = connection.write_queued;
const test_input = &connection.test_input;

/// Feeds a POST request declaring `content_length` on `stream_id`. Test-only.
fn feed_post(stream_id: u32, content_length: []const u8) !?Event {
    var block: [constants.frame_size_max]u8 = undefined;
    connection.test_encoder.init(constants.header_table_size_initial, .never);
    var writer = Writer.init(&block);
    try connection.test_encoder.begin_block(&writer);
    try connection.test_encoder.write_field(&writer, ":method", "POST", .without_indexing);
    try connection.test_encoder.write_field(&writer, ":scheme", "http", .without_indexing);
    try connection.test_encoder.write_field(&writer, ":path", "/", .without_indexing);
    try connection.test_encoder.write_field(&writer, ":authority", "example.com", .without_indexing);
    try connection.test_encoder.write_field(&writer, "content-length", content_length, .without_indexing);
    connection.test_encoder.commit_block();
    const bytes = try frame_bytes(test_input, constants.frame_type_headers, constants.flag_end_headers, stream_id, writer.written());
    return feed(bytes);
}

/// Feeds one DATA frame of `payload` on `stream_id`. Test-only.
fn feed_data(stream_id: u32, payload: []const u8, end_stream: bool) !?Event {
    const flags: u8 = if (end_stream) constants.flag_end_stream else 0;
    const bytes = try frame_bytes(test_input, constants.frame_type_data, flags, stream_id, payload);
    return feed(bytes);
}

test "DATA on an open stream is reported, and counted against both windows" {
    try start_server();
    _ = try feed_request(1, "/", false);
    const event = (try feed_data(1, "test", false)).?;
    try testing.expectEqualStrings("test", event.data.payload);
    try testing.expectEqual(1, event.data.stream_id);
    try testing.expect(!event.data.end_stream);
    // Every octet is handed to the caller at once, so nothing is held back (design §4.1).
    try testing.expectEqual(0, test_connection.receive_window.unreleased);
    try testing.expectEqual("test".len, test_connection.receive_window.released);
    const record = test_connection.streams.lookup(1).live;
    try testing.expectEqual("test".len, record.data_received_len);
    try testing.expectEqual("test".len, record.receive.released);
}

test "a WINDOW_UPDATE goes back to the peer once half the window has been consumed (§6.9.1)" {
    try start_server();
    _ = try feed_request(1, "/", false);
    // The threshold is more than one frame carries, so it takes two frames to reach it.
    var payload: [constants.frame_size_max]u8 = @splat('x');
    _ = try feed_data(1, &payload, false);
    try testing.expectEqual(0, write_queued().len);
    _ = try feed_data(1, &payload, false);
    const queued = write_queued();
    const credited = 2 * constants.frame_size_max;
    try testing.expect(credited >= constants.window_update_threshold);
    var expected: [2 * (constants.frame_header_len + constants.window_update_len)]u8 = undefined;
    var writer = Writer.init(&expected);
    try frame.write_window_update(&writer, constants.connection_stream_id, credited);
    try frame.write_window_update(&writer, 1, credited);
    try testing.expectEqualSlices(u8, writer.written(), queued);
}

test "§6.9.1: DATA past the connection window ends the connection, and past a stream window ends the stream" {
    try start_server();
    _ = try feed_request(1, "/", false);
    // The window is set to what the peer has left to fill, so the next frame passes it.
    test_connection.receive_window = window.Receiver.init(constants.window_update_threshold);
    var payload: [constants.frame_size_max]u8 = @splat('x');
    // The first frame fits in what is left of that window and the second does not.
    _ = try feed_data(1, &payload, false);
    const bytes = try frame_bytes(test_input, constants.frame_type_data, 0, 1, &payload);
    try testing.expectEqual(error.ConnectionFailed, test_connection.receive(bytes, 0));
    try testing.expectEqual(constants.error_flow_control_error, test_connection.failure.?);
    try start_server();
    _ = try feed_request(1, "/", false);
    const record = test_connection.streams.lookup(1).live;
    record.receive = window.Receiver.init(constants.window_update_threshold);
    _ = try feed_data(1, &payload, false);
    const refused = (try feed_data(1, &payload, false)).?;
    try testing.expectEqual(1, refused.stream_refused.stream_id);
    try testing.expectEqual(constants.error_flow_control_error, refused.stream_refused.error_code);
}

test "http2/8.1.1: a content-length that differs from the DATA received is a stream error" {
    try start_server();
    _ = try feed_post(1, "5");
    const refused = (try feed_data(1, "test", true)).?;
    try testing.expectEqual(constants.error_protocol_error, refused.stream_refused.error_code);
    // The same request whose octets match is reported and ends the stream.
    try start_server();
    _ = try feed_post(1, "4");
    const event = (try feed_data(1, "test", true)).?;
    try testing.expectEqualStrings("test", event.data.payload);
    try testing.expect(event.data.end_stream);
}

test "§5.1: DATA on a stream colibri reset still costs the connection window" {
    try start_server();
    _ = try feed_request(1, "/", false);
    const zero = try frame_bytes(test_input, constants.frame_type_window_update, 0, 1, "\x00\x00\x00\x00");
    _ = try feed(zero);
    _ = write_queued();
    const released = test_connection.receive_window.released;
    try testing.expectEqual(null, try feed_data(1, "test", false));
    try testing.expectEqual(released + "test".len, test_connection.receive_window.released);
}

test "the padding of a DATA frame costs window and is not part of the payload (§6.1, §10.7)" {
    try start_server();
    _ = try feed_request(1, "/", false);
    // Pad Length 4, then "ab", then four padding octets.
    const padded = try frame_bytes(test_input, constants.frame_type_data, constants.flag_padded, 1, "\x04ab\x00\x00\x00\x00");
    const event = (try feed(padded)).?;
    try testing.expectEqualStrings("ab", event.data.payload);
    try testing.expectEqual(7, test_connection.receive_window.released);
    const record = test_connection.streams.lookup(1).live;
    try testing.expectEqual(2, record.data_received_len);
}

/// Opens stream 1 at a client with a request that ends the client's side. Test-only.
fn open_stream_1() !void {
    try start_client();
    const request: connection.Request_ = .{ .method = "GET", .scheme = "https", .path = "/", .authority = "example.com" };
    const sent = try test_connection.write_request(&connection.test_output, request, &.{}, &.{}, true);
    try testing.expectEqual(1, sent.stream_id);
}

test "§8.1: DATA before the response's field section is a stream error of PROTOCOL_ERROR" {
    try open_stream_1();
    const released = test_connection.receive_window.released;
    const event = (try feed_data(1, "test", true)).?;
    try testing.expectEqual(1, event.stream_refused.stream_id);
    try testing.expectEqual(constants.error_protocol_error, event.stream_refused.error_code);
    // RFC 9113 §6.9: the refused frame still cost the connection window, and gave it back.
    try testing.expectEqual(released + "test".len, test_connection.receive_window.released);
    try testing.expect(!test_connection.has_failed());
}

test "§8.1: DATA after an interim response alone is refused, and after the final one is read" {
    try open_stream_1();
    _ = try feed_response(1, "103", false);
    const early = (try feed_data(1, "test", false)).?;
    try testing.expectEqual(constants.error_protocol_error, early.stream_refused.error_code);

    try open_stream_1();
    _ = try feed_response(1, "103", false);
    _ = try feed_response(1, "200", false);
    const event = (try feed_data(1, "test", true)).?;
    try testing.expectEqualStrings("test", event.data.payload);
}

/// Owes stream 1 of a request a WINDOW_UPDATE, with the connection's, and leaves both queued.
/// Test-only.
fn owe_stream_credit() !void {
    try start_server();
    _ = try feed_request(1, "/", false);
    var payload: [constants.frame_size_max]u8 = @splat('x');
    _ = try feed_data(1, &payload, false);
    _ = try feed_data(1, &payload, false);
}

/// How many WINDOW_UPDATE frames in `queued` name stream `stream_id`. Test-only.
fn updates_on(queued: []const u8, stream_id: u32) !usize {
    var reader = core.reader.Reader.init(queued);
    var count: usize = 0;
    for (0..queued.len) |_| {
        if (reader.remaining_len() == 0) return count;
        const header = try frame.frame_header.read(&reader);
        _ = try reader.take(header.length);
        if (header.type == constants.frame_type_window_update and header.stream_id == stream_id) count += 1;
    }
    return count;
}

/// A trailer section of one field, which ends the request (RFC 9113 §8.1). Test-only.
fn trailers_frame() ![]const u8 {
    var block: [constants.frame_size_max]u8 = undefined;
    connection.test_encoder.init(constants.header_table_size_initial, .never);
    var writer = Writer.init(&block);
    try connection.test_encoder.begin_block(&writer);
    try connection.test_encoder.write_field(&writer, "x-checked", "yes", .without_indexing);
    connection.test_encoder.commit_block();
    const flags = constants.flag_end_headers | constants.flag_end_stream;
    return frame_bytes(test_input, constants.frame_type_headers, flags, 1, writer.written());
}

test "§5.1: once the peer ends a stream, or either side resets it, its owed WINDOW_UPDATE is dropped" {
    // spec/tla/h2_flow_control's path: credit owed on the stream, then the peer ends its side.
    try owe_stream_credit();
    _ = try feed_data(1, "", true);
    var queued = write_queued();
    try testing.expectEqual(0, try updates_on(queued, 1));
    // The connection's credit is still owed: the connection goes on.
    try testing.expectEqual(1, try updates_on(queued, constants.connection_stream_id));
    try owe_stream_credit();
    _ = try feed(try trailers_frame());
    try testing.expectEqual(0, try updates_on(write_queued(), 1));
    // RFC 9113 §6.4: a RST_STREAM from the peer closes the stream at once.
    try owe_stream_credit();
    const cancel = [_]u8{ 0, 0, 0, @intCast(constants.error_cancel) };
    _ = try feed(try frame_bytes(test_input, constants.frame_type_rst_stream, 0, 1, &cancel));
    try testing.expectEqual(0, try updates_on(write_queued(), 1));
    // colibri's own reset closes it too, and its RST_STREAM still goes out.
    try owe_stream_credit();
    try test_connection.reset_stream(1, constants.error_cancel);
    queued = write_queued();
    try testing.expectEqual(0, try updates_on(queued, 1));
    try testing.expect(std.mem.indexOfScalar(u8, queued, constants.frame_type_rst_stream) != null);
    // colibri's own refusal of the stream resets it too, here DATA past its window (§6.9.1).
    try owe_stream_credit();
    test_connection.streams.lookup(1).live.receive = window.Receiver.init(constants.window_update_threshold);
    var payload: [constants.frame_size_max]u8 = @splat('x');
    _ = try feed_data(1, &payload, false);
    try testing.expectEqual(1, (try feed_data(1, &payload, false)).?.stream_refused.stream_id);
    try testing.expectEqual(0, try updates_on(write_queued(), 1));
    // Credit the peer can still use is sent as before.
    try owe_stream_credit();
    try testing.expectEqual(1, try updates_on(write_queued(), 1));
}
