//! What the tests of decision 110's deadlines share (`connection_deadline_test.zig`,
//! `connection_bodies_test.zig`): octets read and sent at an instant, and the h2 frames a test
//! sends or looks for in what the connection sent. Test-only.
const std = @import("std");
const h2 = @import("h2");
const support = @import("connection_test_support.zig");
const h2_support = @import("connection_h2_test_support.zig");

const testing = std.testing;
const connection = &support.connection;
const constants = h2.constants;

/// An instant well inside every deadline, at which a test's peer sends its first octets.
pub const early_ns: u64 = 1_000_000;

/// The status each answer carries: 204 (No Content), RFC 9110 §15.3.5.
pub const no_content: u16 = 204;

/// Reads `octets` at `now_ns`.
pub fn receive_at(octets: []const u8, now_ns: u64) !support.Received {
    @memcpy(support.input[0..octets.len], octets);
    return connection.receive(support.input[0..octets.len], now_ns);
}

/// What the connection sends at `now_ns`.
pub fn send_at(now_ns: u64) []const u8 {
    const written = connection.send(&support.output, now_ns);
    return support.output[0..written];
}

/// Answers the request `receive_at` read with a 204, sends the answer at `now_ns`, and reads the
/// request's `done` event (decision 103).
pub fn answer_at(received: support.Received, now_ns: u64) !void {
    const id = received.event.?.request.id;
    try connection.respond(id, .{ .status = no_content, .end = true });
    _ = send_at(now_ns);
    const done = try connection.receive(&.{}, now_ns);
    try testing.expectEqual(id, done.event.?.done.id);
}

/// The payload of the first frame of `frame_type` on `stream_id` in `sent`, or null.
pub fn find_frame(sent: []const u8, frame_type: u8, stream_id: u32) ?[]const u8 {
    var offset: usize = 0;
    // Bounded: each pass skips one whole frame.
    for (0..sent.len) |_| {
        if (offset + constants.frame_header_len > sent.len) return null;
        const frame = sent[offset..];
        const id = std.mem.readInt(u32, frame[stream_id_index..][0..@sizeOf(u32)], .big) & constants.stream_id_max;
        if (frame[h2_support.type_index] == frame_type and id == stream_id) {
            return frame[constants.frame_header_len..h2_support.frame_len(frame)];
        }
        offset += h2_support.frame_len(frame);
    }
    return null;
}

/// Where a frame header's stream identifier lies, after its length, type and flags (RFC 9113
/// §4.1).
const stream_id_index: usize = h2_support.flags_index + 1;

/// The error code of the GOAWAY frame in `sent`, which a test requires to be there.
pub fn goaway_code(sent: []const u8) !u32 {
    const payload = find_frame(sent, constants.frame_type_goaway, constants.connection_stream_id) orelse return error.TestUnexpectedResult;
    return std.mem.readInt(u32, payload[goaway_code_start..][0..@sizeOf(u32)], .big);
}

/// Where a GOAWAY's error code lies, after its last stream identifier (RFC 9113 §6.8).
const goaway_code_start: usize = 4;

/// The error code of the RST_STREAM frame on `stream_id` in `sent`, which a test requires.
pub fn reset_code(sent: []const u8, stream_id: u32) !u32 {
    const payload = find_frame(sent, constants.frame_type_rst_stream, stream_id) orelse return error.TestUnexpectedResult;
    return std.mem.readInt(u32, payload[0..constants.rst_stream_len], .big);
}

/// Decodes the field blocks of `sent` in order, as the first the connection sent, and returns
/// the status of the response on `stream_id`, which a test requires to be there.
pub fn response_status(sent: []const u8, stream_id: u32) !u16 {
    decoder.init(constants.header_table_size_initial);
    var status: ?u16 = null;
    var offset: usize = 0;
    // Bounded: each pass reads one whole frame.
    for (0..sent.len) |_| {
        if (offset + constants.frame_header_len > sent.len) break;
        const frame_end = offset + h2_support.frame_len(sent[offset..]);
        if (frame_end > sent.len) break;
        const frame = sent[offset..frame_end];
        offset = frame_end;
        if (frame[h2_support.type_index] != constants.frame_type_headers) continue;
        const id = std.mem.readInt(u32, frame[stream_id_index..][0..@sizeOf(u32)], .big) & constants.stream_id_max;
        var lines = decoder.block(frame[constants.frame_header_len..]);
        for (0..frame.len) |_| {
            const line = (try lines.next()) orelse break;
            if (id == stream_id and std.mem.eql(u8, line.name, ":status")) status = try std.fmt.parseInt(u16, line.value, decimal);
        }
    }
    return status orelse error.TestUnexpectedResult;
}

pub var decoder: h2.hpack.Decoder align(@alignOf(h2.hpack.Decoder)) = undefined;
const decimal: u8 = 10;

/// A DATA frame carrying `octets` on `stream_id`, with `padding_len` octets of padding.
pub fn data_frame(stream_id: u32, octets: []const u8, end: bool, padding_len: u8) ![]const u8 {
    var writer = h2.core.Writer.init(&data_frames);
    try h2.frame.write_data(&writer, stream_id, octets, end, padding_len);
    return writer.written();
}

pub var data_frames: [support.input_len]u8 = undefined;

/// A PING frame that asks for an acknowledgment (RFC 9113 §6.7).
pub fn ping_frame() ![constants.frame_header_len + constants.ping_len]u8 {
    var frame: [constants.frame_header_len + constants.ping_len]u8 = undefined;
    var writer = h2.core.Writer.init(&frame);
    try h2.frame.write_ping(&writer, @splat(0), false);
    return frame;
}
