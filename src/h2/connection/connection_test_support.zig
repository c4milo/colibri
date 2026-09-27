//! The fixtures and helpers the tests of `connection.zig` and of the other files of this directory
//! share: the connection they run on, the buffers they read and write, and the frames a peer would
//! send. Test-only. They sit in their own file because a fixture several files share is a plain
//! global, and `tools/lint/global_state.zig` refuses one in a library file.
const std = @import("std");
const core = @import("core");
const hpack = @import("hpack");
const constants = @import("../constants.zig");
const frame = @import("../frame/frame.zig");
const connection = @import("connection.zig");

const Connection = connection.Connection;
const Event = connection.Event;
const Writer = core.Writer;
const testing = std.testing;

/// The connection the tests run on, placed outside any stack frame. Test-only, and the other
/// files of this directory run their tests on it too.
pub var test_connection: Connection align(@alignOf(Connection)) = undefined;

/// Where the tests write frames. Test-only.
pub var test_output: [constants.frame_header_len + constants.frame_size_max]u8 = @splat(0);

/// The encoder the tests build the peer's field blocks with, which is the peer's and not
/// colibri's. Test-only.
pub var test_encoder: hpack.Encoder align(@alignOf(hpack.Encoder)) = undefined;

/// Where the tests build the frames they feed: one header and the largest payload. Test-only.
pub var test_input: [constants.frame_header_len + constants.frame_size_max]u8 = @splat(0);

/// A SETTINGS frame with no settings in it, which RFC 9113 §3.4 lets an endpoint send. Test-only.
pub const empty_settings = "\x00\x00\x00\x04\x00\x00\x00\x00\x00";

/// Writes one frame into `buffer` and returns it. Test-only.
pub fn frame_bytes(buffer: []u8, frame_type: u8, flags: u8, stream_id: u32, payload: []const u8) ![]const u8 {
    var writer = Writer.init(buffer);
    try frame.write_header(&writer, .{
        .length = @intCast(payload.len),
        .type = frame_type,
        .flags = flags,
        .stream_id = stream_id,
    });
    try writer.write_bytes(payload);
    return writer.written();
}

/// Encodes the field section of a GET request for `path` into `buffer`, as a peer would. Test-only.
pub fn request_block(buffer: []u8, path: []const u8) ![]const u8 {
    test_encoder.init(constants.header_table_size_initial, .never);
    var writer = Writer.init(buffer);
    try test_encoder.begin_block(&writer);
    try test_encoder.write_field(&writer, ":method", "GET", .without_indexing);
    try test_encoder.write_field(&writer, ":scheme", "http", .without_indexing);
    try test_encoder.write_field(&writer, ":path", path, .without_indexing);
    try test_encoder.write_field(&writer, ":authority", "example.com", .without_indexing);
    test_encoder.commit_block();
    return writer.written();
}

/// Feeds `input` whole and requires the connection to consume all of it. Test-only.
pub fn feed(input: []const u8) !?Event {
    const received = try test_connection.receive(input, 0);
    try testing.expectEqual(input.len, received.consumed);
    return received.event;
}

/// Starts a server that has written its preface and read the client's, with nothing else read.
/// Test-only.
pub fn start_server() !void {
    test_connection.init(.server);
    _ = test_connection.write_pending(&test_output, 0);
    try testing.expectEqual(null, try feed(constants.client_preface));
    try testing.expectEqual(Event.settings_applied, (try feed(empty_settings)).?);
    // The acknowledgment of that SETTINGS frame is written, so the queues start empty.
    _ = test_connection.write_pending(&test_output, 0);
    try testing.expect(!test_connection.has_pending());
}

/// Starts a client that has written its preface and read the server's, with nothing else read.
/// Test-only.
pub fn start_client() !void {
    test_connection.init(.client);
    _ = test_connection.write_pending(&test_output, 0);
    try testing.expectEqual(Event.settings_applied, (try feed(empty_settings)).?);
    _ = test_connection.write_pending(&test_output, 0);
    try testing.expect(!test_connection.has_pending());
}

/// Encodes the field section of a response carrying `status`, as a peer would. Test-only.
pub fn response_block(buffer: []u8, status: []const u8) ![]const u8 {
    test_encoder.init(constants.header_table_size_initial, .never);
    var writer = Writer.init(buffer);
    try test_encoder.begin_block(&writer);
    try test_encoder.write_field(&writer, ":status", status, .without_indexing);
    test_encoder.commit_block();
    return writer.written();
}

/// Feeds a HEADERS frame carrying a response with `status` on `stream_id`. Test-only.
pub fn feed_response(stream_id: u32, status: []const u8, end_stream: bool) !?Event {
    var block: [constants.frame_size_max]u8 = undefined;
    const fragment = try response_block(&block, status);
    const flags = constants.flag_end_headers | @as(u8, if (end_stream) constants.flag_end_stream else 0);
    const bytes = try frame_bytes(&test_input, constants.frame_type_headers, flags, stream_id, fragment);
    return feed(bytes);
}

/// Feeds a HEADERS frame carrying a GET request for `path` on `stream_id`. Test-only.
pub fn feed_request(stream_id: u32, path: []const u8, end_stream: bool) !?Event {
    var block: [constants.frame_size_max]u8 = undefined;
    const fragment = try request_block(&block, path);
    const flags = constants.flag_end_headers | @as(u8, if (end_stream) constants.flag_end_stream else 0);
    const bytes = try frame_bytes(&test_input, constants.frame_type_headers, flags, stream_id, fragment);
    return feed(bytes);
}

/// The frames the connection has queued, written out. Test-only.
pub fn write_queued() []const u8 {
    const queued_len = test_connection.write_pending(&test_output, 0);
    return test_output[0..queued_len];
}
