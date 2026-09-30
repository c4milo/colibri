//! What the server's h2 tests share: a connection that has read the client's preface, and the
//! frames a client sends it (RFC 9113 §3.4, §6.2). Test-only.
const std = @import("std");
const h2 = @import("h2");
const support = @import("connection_test_support.zig");

const testing = std.testing;
const constants = h2.constants;

/// The client connection preface, then an empty SETTINGS frame (RFC 9113 §3.4), and the
/// acknowledgment of the server's SETTINGS, which the server wrote before it read a frame.
pub const client_preface = constants.client_preface ++ "\x00\x00\x00\x04\x00\x00\x00\x00\x00" ++ settings_ack;
pub const settings_ack = "\x00\x00\x00\x04\x01\x00\x00\x00\x00";

/// Where a test builds the frames the client sends. Test-only.
pub var frames: [support.input_len]u8 = undefined;

/// A frame's header: a length of three octets, big-endian, then its type and its flags (RFC 9113
/// §4.1).
const length_len: usize = 3;
pub const type_index: usize = length_len;
pub const flags_index: usize = length_len + 1;

/// A connection that has read the client's preface and sent its own. Test-only.
pub fn start() !void {
    try support.start_cleartext(.h2);
    try start_preface();
}

/// The connection `support` started reads the client's preface and sends its own. Test-only.
pub fn start_preface() !void {
    const received = try support.receive_copy(client_preface);
    try testing.expectEqual(client_preface.len, received.consumed);
    try testing.expectEqual(null, received.event);
    const sent = support.drain();
    // RFC 9113 §3.4: the server's connection preface is a SETTINGS frame, sent first.
    try testing.expectEqual(constants.frame_type_settings, sent[type_index]);
}

/// A HEADERS frame carrying a GET for `path` on `stream_id`, ending the stream when `end`.
/// Test-only.
pub fn request_frame(stream_id: u32, path: []const u8, end: bool) ![]const u8 {
    const accept = [_]support.Field{.{ .name = "accept", .value = "*/*" }};
    return request_frame_with(stream_id, "GET", path, &accept, end);
}

/// A HEADERS frame carrying a `method` request for `path` with `fields` on `stream_id`, ending the
/// stream when `end`. Test-only.
pub fn request_frame_with(stream_id: u32, method: []const u8, path: []const u8, fields: []const support.Field, end: bool) ![]const u8 {
    var block: [constants.frame_size_max]u8 = undefined;
    var encoder: h2.hpack.Encoder = undefined;
    encoder.init(constants.header_table_size_initial, .never);
    var block_writer = h2.core.Writer.init(&block);
    try encoder.begin_block(&block_writer);
    try encoder.write_field(&block_writer, ":method", method, .without_indexing);
    try encoder.write_field(&block_writer, ":scheme", "http", .without_indexing);
    try encoder.write_field(&block_writer, ":path", path, .without_indexing);
    try encoder.write_field(&block_writer, ":authority", "example.com", .without_indexing);
    for (fields) |field| try encoder.write_field(&block_writer, field.name, field.value, .without_indexing);
    encoder.commit_block();
    var writer = h2.core.Writer.init(&frames);
    const end_flag: u8 = if (end) constants.flag_end_stream else 0;
    try h2.frame.write_header(&writer, .{
        .length = @intCast(block_writer.written().len),
        .type = constants.frame_type_headers,
        .flags = constants.flag_end_headers | end_flag,
        .stream_id = stream_id,
    });
    try writer.write_bytes(block_writer.written());
    return writer.written();
}

/// The length of the frame at the front of `octets`. Test-only.
pub fn frame_len(octets: []const u8) usize {
    return constants.frame_header_len + std.mem.readInt(u24, octets[0..length_len], .big);
}
