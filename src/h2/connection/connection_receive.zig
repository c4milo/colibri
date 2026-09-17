//! The receive path of the connection, split off `connection.zig` for length: the octets the
//! caller read become at most one frame, and that frame becomes at most one event (decision 39).
//!
//! `receive` checks in this order (invariant 7):
//!   1. the connection has not already failed, and the replies have room for what a frame may owe;
//!   2. at a server, the 24 octets of the client connection preface (RFC 9113 §3.4);
//!   3. a whole frame header, and a Length at or below what colibri advertised, or a connection
//!      error of FRAME_SIZE_ERROR (§4.2), which is decided before the payload is waited for;
//!   4. the whole payload is in the slice, or nothing is consumed;
//!   5. the first frame the peer sends is a SETTINGS frame that is not an acknowledgment (§3.4);
//!   6. a field block in progress takes only a CONTINUATION frame on its own stream, or a
//!      connection error of PROTOCOL_ERROR (§4.3, invariant 14);
//!   7. the payload parses, or the verdict `frame.verdict` gives it (§4.2, §6);
//!   8. the frame's own rules, in `connection_control.zig` for the frames that name no stream and
//!      in `connection_stream.zig` for the rest.
//!
//! A frame is consumed whole whatever it meant, so the caller's next call starts at a frame
//! boundary, and a connection error consumes it too: the octets are read and the GOAWAY is queued.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("../constants.zig");
const frame = @import("../frame/frame.zig");
const connection = @import("connection.zig");
const control = @import("connection_control.zig");
const stream_frames = @import("connection_stream.zig");

const Connection = connection.Connection;
const Received = connection.Received;
const Error = connection.Error;
const Reader = core.Reader;

/// Consumes at most one whole frame of `input`. See `connection.zig` for what a count of 0 means.
pub fn receive(target: *Connection, input: []const u8, now_ns: u64) Error!Received {
    // RFC 9113 §5.4.1: after a connection error the endpoint reads no more frames.
    if (target.has_failed()) return error.ConnectionFailed;
    // A frame may owe a reply, and a full queue has no slot for it: the caller writes first.
    if (target.replies.is_full()) return nothing();
    if (try read_preface(target, input)) |consumed| return .{ .consumed = consumed, .event = null };
    var reader = Reader.init(input);
    const header = frame.read_header(&reader) catch return nothing();
    // RFC 9113 §4.2: a frame larger than the receiver's SETTINGS_MAX_FRAME_SIZE is an error, and
    // it is an error before the rest of the frame arrives, which colibri never waits for.
    if (header.length > target.local.max_frame_size) return target.fail(constants.error_frame_size_error);
    if (reader.remaining_len() < header.length) return nothing();
    const payload = reader.take(header.length) catch unreachable;
    const event = try dispatch(target, header, payload, now_ns);
    return .{ .consumed = constants.frame_header_len + header.length, .event = event };
}

/// Nothing was consumed and nothing happened: the slice holds no whole frame, or the caller must
/// write the replies first.
fn nothing() Received {
    return .{ .consumed = 0, .event = null };
}

/// The octets of the client connection preface this call consumed, at a server that has not read
/// it yet, or null once it is read (RFC 9113 §3.4). The preface is not a frame and takes calls of
/// its own: it may be cut anywhere, so what arrives is matched, consumed and remembered, and the
/// call after the one that completes it reads the first frame.
fn read_preface(target: *Connection, input: []const u8) Error!?usize {
    if (target.role == .client or target.preface_read_len == constants.client_preface_len) return null;
    const wanted = constants.client_preface_len - target.preface_read_len;
    const taken = @min(wanted, input.len);
    const expected = constants.client_preface[target.preface_read_len..][0..taken];
    // RFC 9113 §3.4: a server that does not read the preface MUST end the connection, and §5.4.1
    // makes a connection error of PROTOCOL_ERROR the way to say so.
    if (!std.mem.eql(u8, expected, input[0..taken])) return target.fail(constants.error_protocol_error);
    target.preface_read_len += @intCast(taken);
    assert(target.preface_read_len <= constants.client_preface_len);
    return taken;
}

/// Gives the frame to the rules of its type.
fn dispatch(target: *Connection, header: frame.Header, payload: []const u8, now_ns: u64) Error!?connection.Event {
    try check_first_frame(target, header);
    try check_field_block(target, header);
    const parsed = frame.parse(header, payload) catch |failure| {
        return refuse_parse(target, header, failure, now_ns);
    };
    return switch (parsed) {
        .settings => |values| control.on_settings(target, values),
        .ping => |ping| control.on_ping(target, ping),
        .goaway => |goaway| control.on_goaway(target, goaway),
        // RFC 9113 §6.9: a WINDOW_UPDATE on stream 0 moves the connection's window and one on any
        // other stream moves that stream's, which are different windows and different errors.
        .window_update => |update| if (header.stream_id == constants.connection_stream_id)
            control.on_window_update(target, update)
        else
            stream_frames.on_stream_frame(target, header, parsed, now_ns),
        // RFC 9113 §4.1 and §5.5: a frame of an unknown type is discarded, whatever it carries.
        .unknown => null,
        else => stream_frames.on_stream_frame(target, header, parsed, now_ns),
    };
}

/// The verdict `frame.verdict` gives a payload that did not parse: a connection error ends the
/// connection, and a stream error queues a RST_STREAM (RFC 9113 §5.4).
fn refuse_parse(target: *Connection, header: frame.Header, failure: frame.ParseError, now_ns: u64) Error!?connection.Event {
    const verdict = frame.verdict(failure, @enumFromInt(header.type), header.stream_id);
    switch (verdict.kind) {
        .connection => return target.fail(verdict.code),
        .stream => return stream_frames.refuse_stream(target, header.stream_id, verdict.code, now_ns),
    }
}

/// RFC 9113 §3.4: the first frame each endpoint sends after the preface is a SETTINGS frame, and
/// an acknowledgment is not that frame.
fn check_first_frame(target: *Connection, header: frame.Header) Error!void {
    if (target.first_frame_read) return;
    const is_settings = header.type == constants.frame_type_settings;
    const is_ack = frame.has_flag(header, constants.flag_ack);
    if (!is_settings or is_ack) return target.fail(constants.error_protocol_error);
    target.first_frame_read = true;
}

/// RFC 9113 §4.3: the frames of a field block are contiguous, so while one is in progress the only
/// frame that may arrive is a CONTINUATION on its stream. Anything else, an unknown type included,
/// ends the connection (invariant 14, h2spec http2/4.3/2, /3 and http2/5.5/2).
fn check_field_block(target: *Connection, header: frame.Header) Error!void {
    const in_progress = target.block.stream_id() orelse {
        // A CONTINUATION with no block in progress has no HEADERS to continue (§6.10).
        if (header.type == constants.frame_type_continuation) return target.fail(constants.error_protocol_error);
        return;
    };
    if (header.type != constants.frame_type_continuation or header.stream_id != in_progress) {
        return target.fail(constants.error_protocol_error);
    }
}

const testing = std.testing;
const test_connection = &connection.test_connection;
const feed = connection.feed;
const frame_bytes = connection.frame_bytes;
const start_server = connection.start_server;
const write_queued = connection.write_queued;
const test_input = &connection.test_input;

test "a server reads the client preface, in pieces, and refuses the first octet that differs" {
    test_connection.init(.server);
    const half = constants.client_preface_len / 2;
    try testing.expectEqual(null, try feed(constants.client_preface[0..half]));
    try testing.expectEqual(half, test_connection.preface_read_len);
    try testing.expectEqual(null, try feed(constants.client_preface[half..]));
    try testing.expectEqual(constants.client_preface_len, test_connection.preface_read_len);
    // RFC 9113 §3.4: a preface that is not those octets ends the connection.
    test_connection.init(.server);
    try testing.expectEqual(error.ConnectionFailed, test_connection.receive("PRI * HTTP/3.0\r\n", 0));
    try testing.expectEqual(constants.error_protocol_error, test_connection.failure.?);
}

test "http2/3.5: the first frame the peer sends is a SETTINGS frame that is not an acknowledgment" {
    test_connection.init(.server);
    try testing.expectEqual(null, try feed(constants.client_preface));
    const ping = try frame_bytes(test_input, constants.frame_type_ping, 0, 0, "12345678");
    try testing.expectEqual(error.ConnectionFailed, test_connection.receive(ping, 0));
    try testing.expectEqual(constants.error_protocol_error, test_connection.failure.?);
    // RFC 9113 §3.4: an acknowledgment is not the SETTINGS frame the preface asks for.
    test_connection.init(.server);
    try testing.expectEqual(null, try feed(constants.client_preface));
    const ack = try frame_bytes(test_input, constants.frame_type_settings, constants.flag_ack, 0, "");
    try testing.expectEqual(error.ConnectionFailed, test_connection.receive(ack, 0));
    try testing.expectEqual(constants.error_protocol_error, test_connection.failure.?);
}

test "http2/4.2/2: a frame longer than SETTINGS_MAX_FRAME_SIZE fails before its payload arrives" {
    try start_server();
    // Only the header is fed: the Length alone decides it.
    const header = "\x00\x40\x01\x00\x00\x00\x00\x00\x01";
    try testing.expectEqual(constants.frame_size_max + 1, (0x40 << @bitSizeOf(u8)) | 0x01);
    try testing.expectEqual(error.ConnectionFailed, test_connection.receive(header, 0));
    try testing.expectEqual(constants.error_frame_size_error, test_connection.failure.?);
}

test "a frame is consumed only once its whole payload is in the slice" {
    try start_server();
    const ping = try frame_bytes(test_input, constants.frame_type_ping, 0, 0, "12345678");
    for (0..ping.len) |len| {
        const received = try test_connection.receive(ping[0..len], 0);
        try testing.expectEqual(0, received.consumed);
        try testing.expectEqual(null, received.event);
    }
    const whole = try test_connection.receive(ping, 0);
    try testing.expectEqual(ping.len, whole.consumed);
    // A slice holding two frames gives up one frame per call (decision 39).
    var two: [2 * (constants.frame_header_len + constants.ping_len)]u8 = undefined;
    @memcpy(two[0..ping.len], ping);
    @memcpy(two[ping.len..], ping);
    const first = try test_connection.receive(&two, 0);
    try testing.expectEqual(ping.len, first.consumed);
}

test "http2/4.3/2, http2/4.3/3 and http2/5.5/2: nothing comes between the frames of a field block" {
    // A PRIORITY frame inside the block, on the same stream.
    try start_server();
    try expect_block_interrupted(constants.frame_type_priority, 1, "\x00\x00\x00\x00\x00");
    // A HEADERS frame on another stream.
    try start_server();
    try expect_block_interrupted(constants.frame_type_headers, 3, "\x82");
    // A frame of an unknown type, which is ignored everywhere else.
    try start_server();
    try expect_block_interrupted(0x16, 0, "12345678");
    // A CONTINUATION on another stream.
    try start_server();
    try expect_block_interrupted(constants.frame_type_continuation, 3, "\x82");
}

/// Opens a field block on stream 1 and feeds one frame that may not interrupt it. Test-only.
fn expect_block_interrupted(frame_type: u8, stream_id: u32, payload: []const u8) !void {
    var opening: [constants.frame_size_max]u8 = undefined;
    const headers = try frame_bytes(&opening, constants.frame_type_headers, 0, 1, "\x82");
    try testing.expectEqual(null, try feed(headers));
    try testing.expect(test_connection.block.is_in_progress());
    const interruption = try frame_bytes(test_input, frame_type, 0, stream_id, payload);
    try testing.expectEqual(error.ConnectionFailed, test_connection.receive(interruption, 0));
    try testing.expectEqual(constants.error_protocol_error, test_connection.failure.?);
}

test "http2/6.10: a CONTINUATION with no field block in progress ends the connection" {
    try start_server();
    const orphan = try frame_bytes(test_input, constants.frame_type_continuation, constants.flag_end_headers, 1, "\x82");
    try testing.expectEqual(error.ConnectionFailed, test_connection.receive(orphan, 0));
    try testing.expectEqual(constants.error_protocol_error, test_connection.failure.?);
}

test "http2/4.1/1 and http2/5.5/1: a frame of an unknown type is ignored, and the next frame is read" {
    try start_server();
    const unknown = try frame_bytes(test_input, 0x16, 0x0f, 0, "12345678");
    try testing.expectEqual(null, try feed(unknown));
    try testing.expect(!test_connection.has_pending());
    var buffer: [constants.frame_size_max]u8 = undefined;
    const ping = try frame_bytes(&buffer, constants.frame_type_ping, 0, 0, "h2spec\x00\x00");
    try testing.expectEqual(null, try feed(ping));
    try testing.expectEqualStrings("\x00\x00\x08\x06\x01\x00\x00\x00\x00h2spec\x00\x00", write_queued());
}

test "a connection that has failed reads nothing more, and writes its GOAWAY once" {
    try start_server();
    try testing.expectEqual(error.ConnectionFailed, test_connection.fail(constants.error_internal_error));
    const ping = try frame_bytes(test_input, constants.frame_type_ping, 0, 0, "12345678");
    try testing.expectEqual(error.ConnectionFailed, test_connection.receive(ping, 0));
    const goaway = write_queued();
    try testing.expectEqual(constants.frame_header_len + constants.goaway_len_min, goaway.len);
    try testing.expectEqual(constants.frame_type_goaway, goaway[3]);
    try testing.expectEqual(0, write_queued().len);
}

test "a full reply queue stops the connection reading until the caller writes" {
    try start_server();
    var buffer: [constants.frame_size_max]u8 = undefined;
    const ping = try frame_bytes(&buffer, constants.frame_type_ping, 0, 0, "12345678");
    for (0..constants.ping_ack_pending_max) |_| try testing.expectEqual(null, try feed(ping));
    try testing.expect(test_connection.replies.is_full());
    const stalled = try test_connection.receive(ping, 0);
    try testing.expectEqual(0, stalled.consumed);
    try testing.expect(test_connection.has_pending());
    _ = write_queued();
    try testing.expectEqual(null, try feed(ping));
}
