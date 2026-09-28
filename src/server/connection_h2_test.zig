//! The tests of the server's h2 half (`connection_h2.zig`) over cleartext with prior knowledge
//! (RFC 9113 §3.3): h2's events arrive as the server's, and responses go out through h2's send
//! path.
const std = @import("std");
const h2 = @import("h2");
const support = @import("connection_test_support.zig");

const testing = std.testing;
const connection = &support.connection;
const constants = h2.constants;

const content_type = [_]support.Field{.{ .name = "content-type", .value = "text/plain" }};
const ok: u16 = 200;
/// The client connection preface, then an empty SETTINGS frame (RFC 9113 §3.4).
const client_preface = constants.client_preface ++ "\x00\x00\x00\x04\x00\x00\x00\x00\x00";

/// Where a test builds the frames the client sends, and decodes what the server sent. Test-only.
var frames: [support.input_len]u8 = undefined;
var decoder: h2.hpack.Decoder align(@alignOf(h2.hpack.Decoder)) = undefined;

/// A frame's header: a length of three octets, big-endian, then its type and its flags (RFC 9113
/// §4.1).
const length_len: usize = 3;
const type_index: usize = length_len;
const flags_index: usize = length_len + 1;
/// Octets of the error code that ends an RST_STREAM frame (RFC 9113 §6.4).
const error_code_len: usize = 4;

/// A connection that has read the client's preface and sent its own. Test-only.
fn start() !void {
    try support.start_cleartext(.h2);
    const received = try support.receive_copy(client_preface);
    try testing.expectEqual(client_preface.len, received.consumed);
    try testing.expectEqual(null, received.event);
    const sent = support.drain();
    // RFC 9113 §3.4: the server's connection preface is a SETTINGS frame, sent first.
    try testing.expectEqual(constants.frame_type_settings, sent[type_index]);
}

/// A HEADERS frame carrying a GET for `path` on `stream_id`, ending the stream when `end`.
/// Test-only.
fn request_frame(stream_id: u32, path: []const u8, end: bool) ![]const u8 {
    var block: [constants.frame_size_max]u8 = undefined;
    var encoder: h2.hpack.Encoder = undefined;
    encoder.init(constants.header_table_size_initial, .never);
    var block_writer = h2.core.Writer.init(&block);
    try encoder.begin_block(&block_writer);
    try encoder.write_field(&block_writer, ":method", "GET", .without_indexing);
    try encoder.write_field(&block_writer, ":scheme", "http", .without_indexing);
    try encoder.write_field(&block_writer, ":path", path, .without_indexing);
    try encoder.write_field(&block_writer, ":authority", "example.com", .without_indexing);
    try encoder.write_field(&block_writer, "accept", "*/*", .without_indexing);
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
fn frame_len(octets: []const u8) usize {
    return constants.frame_header_len + std.mem.readInt(u24, octets[0..length_len], .big);
}

test "RFC 9113 §8.3.1: a request's pseudo-header fields arrive as its parts, and its fields after" {
    try start();
    const received = try support.receive_copy(try request_frame(1, "/index.html", true));
    const head = received.event.?.request;
    try testing.expectEqual(1, head.id);
    try testing.expectEqualStrings("GET", head.method);
    try testing.expectEqualStrings("http", head.scheme.?);
    try testing.expectEqualStrings("example.com", head.authority.?);
    try testing.expectEqualStrings("/index.html", head.path.?);
    try testing.expect(head.end);
    // RFC 9113 §8.3: the pseudo-header fields are not among the regular ones.
    try testing.expectEqual(1, head.fields.len());
    var lines = head.fields.iterator();
    try testing.expectEqualStrings("accept", lines.next().?.name);
    try testing.expectEqualStrings("*/*", head.fields.find("accept").?.value);
}

test "RFC 9113 §8.1: a response is a HEADERS frame, then DATA whose last frame ends the stream" {
    try start();
    _ = try support.receive_copy(try request_frame(1, "/", true));
    try connection.respond(1, ok, &content_type, false);
    // No octets and no end write nothing, not even an empty frame (RFC 9113 §6.1).
    try testing.expectEqual(0, try connection.write_body(1, "", false));
    try testing.expectEqual(5, try connection.write_body(1, "hello", true));
    const sent = support.drain();
    try testing.expectEqual(constants.frame_type_headers, sent[type_index]);
    try testing.expectEqual(constants.flag_end_headers, sent[flags_index]);
    const head_len = frame_len(sent);
    decoder.init(constants.header_table_size_initial);
    var block = decoder.block(sent[constants.frame_header_len..head_len]);
    const status = (try block.next()).?;
    try testing.expectEqualStrings(":status", status.name);
    try testing.expectEqualStrings("200", status.value);
    try testing.expectEqualStrings("text/plain", (try block.next()).?.value);
    const data = sent[head_len..];
    try testing.expectEqual(constants.frame_type_data, data[type_index]);
    try testing.expectEqual(constants.flag_end_stream, data[flags_index]);
    try testing.expectEqualStrings("hello", data[constants.frame_header_len..]);
    try testing.expect(!connection.should_close());
}

test "RFC 9113 §8.1: a request's DATA arrives as body events, the last ending it" {
    try start();
    _ = try support.receive_copy(try request_frame(1, "/", false));
    var writer = h2.core.Writer.init(&frames);
    try h2.frame.write_data(&writer, 1, "hello", true, 0);
    const received = try support.receive_copy(writer.written());
    const body = received.event.?.body;
    try testing.expectEqual(1, body.id);
    try testing.expectEqualStrings("hello", body.octets);
    try testing.expect(body.end);
}

test "RFC 9113 §6.4: cancel resets the stream with CANCEL" {
    try start();
    _ = try support.receive_copy(try request_frame(1, "/", false));
    connection.cancel(1);
    const sent = support.drain();
    try testing.expectEqual(constants.frame_type_rst_stream, sent[type_index]);
    const code = sent[constants.frame_header_len..][0..error_code_len];
    try testing.expectEqual(constants.error_cancel, std.mem.readInt(u32, code, .big));
    // The stream is closed, so nothing more is written on it.
    try testing.expectError(error.RequestUnknown, connection.respond(1, ok, &.{}, true));
}

test "RFC 9113 §6.4: a stream the peer resets arrives as its cancellation" {
    try start();
    _ = try support.receive_copy(try request_frame(1, "/", false));
    var writer = h2.core.Writer.init(&frames);
    try h2.frame.write_rst_stream(&writer, 1, constants.error_cancel);
    const received = try support.receive_copy(writer.written());
    try testing.expectEqual(1, received.event.?.cancelled.id);
}

test "RFC 9113 §5.1.1: an id no client stream can have names no request" {
    try start();
    _ = try support.receive_copy(try request_frame(1, "/", true));
    try testing.expectError(error.RequestUnknown, connection.respond(2, ok, &.{}, true));
    try testing.expectError(error.RequestUnknown, connection.respond(0, ok, &.{}, true));
    try testing.expectError(error.RequestUnknown, connection.respond(3, ok, &.{}, true));
    // RFC 9113 §8.1: content follows the final response's head.
    try testing.expectError(error.SectionOutOfOrder, connection.write_body(1, "x", true));
}

/// Content past the initial window of RFC 9113 §6.9.2. Test-only.
const window_initial: usize = 65_535;
var large_body: [window_initial + 1]u8 = @splat('x');

test "RFC 9113 §6.9: content past the stream's window waits, and write_body says so" {
    try start();
    _ = try support.receive_copy(try request_frame(1, "/", true));
    try connection.respond(1, ok, &.{}, false);
    var taken: usize = 0;
    // Bounded: each pass takes what the output holds, until the window closes.
    for (0..large_body.len) |_| {
        const consumed = connection.write_body(1, large_body[taken..], true) catch |failure| {
            try testing.expectEqual(error.Blocked, failure);
            break;
        };
        taken += consumed;
        _ = support.drain();
    }
    try testing.expectEqual(window_initial, taken);
    try testing.expectError(error.Blocked, connection.write_body(1, large_body[taken..], true));
}

test "RFC 9113 §4.1: a response head waits when the output has no room for its frame" {
    try start();
    _ = try support.receive_copy(try request_frame(1, "/", true));
    const short_room: usize = 4;
    connection.output_len = support.server_constants.output_len - short_room;
    try testing.expectError(error.NoSpaceLeft, connection.respond(1, ok, &.{}, true));
    connection.output_len = 0;
    try connection.respond(1, ok, &.{}, true);
}

test "RFC 9113 §6.8: a shutdown sends GOAWAY, and the connection closes once its streams end" {
    try start();
    _ = try support.receive_copy(try request_frame(1, "/", true));
    connection.shutdown();
    try testing.expect(!connection.should_close());
    try connection.respond(1, ok, &.{}, true);
    const sent = support.drain();
    try testing.expect(std.mem.indexOfScalar(u8, &.{ sent[type_index], sent[frame_len(sent) + type_index] }, constants.frame_type_goaway) != null);
    try testing.expect(connection.should_close());
}

test "RFC 9113 §5.4.1: a connection error fails the connection, and its GOAWAY goes out" {
    try start();
    // RFC 9113 §5.1: a DATA frame on an idle stream is a connection error.
    var writer = h2.core.Writer.init(&frames);
    try h2.frame.write_data(&writer, 1, "x", false, 0);
    try testing.expectError(error.ConnectionFailed, support.receive_copy(writer.written()));
    try testing.expect(!connection.should_close());
    const sent = support.drain();
    try testing.expectEqual(constants.frame_type_goaway, sent[type_index]);
    try testing.expect(connection.should_close());
    try testing.expectError(error.ConnectionClosed, connection.respond(1, ok, &.{}, true));
}

test "RFC 9113 §8.1: a request's trailer section arrives as its trailers, and ends it" {
    try start();
    _ = try support.receive_copy(try request_frame(1, "/", false));
    var block: [constants.frame_size_max]u8 = undefined;
    var encoder: h2.hpack.Encoder = undefined;
    encoder.init(constants.header_table_size_initial, .never);
    var block_writer = h2.core.Writer.init(&block);
    try encoder.begin_block(&block_writer);
    try encoder.write_field(&block_writer, "grpc-status", "0", .without_indexing);
    encoder.commit_block();
    var writer = h2.core.Writer.init(&frames);
    try h2.frame.write_header(&writer, .{
        .length = @intCast(block_writer.written().len),
        .type = constants.frame_type_headers,
        .flags = constants.flag_end_headers | constants.flag_end_stream,
        .stream_id = 1,
    });
    try writer.write_bytes(block_writer.written());
    const received = try support.receive_copy(writer.written());
    const trailers = received.event.?.trailers;
    try testing.expectEqual(1, trailers.id);
    try testing.expectEqualStrings("0", trailers.fields.find("grpc-status").?.value);
}

test "RFC 9113 §5.1.1: an id past the largest stream identifier names no request" {
    try start();
    _ = try support.receive_copy(try request_frame(1, "/", true));
    const past: u64 = @as(u64, constants.stream_id_max) + 2;
    try testing.expectError(error.RequestUnknown, connection.respond(past, ok, &.{}, true));
}

/// One field line more than a section may carry, and values that fill more than the encoder's
/// buffer. Test-only.
const field_count_max = h2.core.constants.field_count_max;
var too_many: [field_count_max + 1]support.Field align(@alignOf(support.Field)) = @splat(.{ .name = "x-a", .value = "b" });
var long_value: [h2.core.constants.field_value_len_max]u8 = @splat('x');
/// Lines of the longest value whose section is larger than `send_block_len_max`.
const long_lines: usize = constants.send_block_len_max / h2.core.constants.field_value_len_max + 1;
var long_fields: [long_lines]support.Field align(@alignOf(support.Field)) = undefined;

test "RFC 9113 §4.3: a section past what colibri sends in one field block is refused whole" {
    try start();
    _ = try support.receive_copy(try request_frame(1, "/", true));
    try testing.expectError(error.SectionTooLarge, connection.respond(1, ok, &too_many, true));
    for (&long_fields) |*line| line.* = .{ .name = "x-long", .value = &long_value };
    try testing.expectError(error.SectionTooLarge, connection.respond(1, ok, &long_fields, true));
    try testing.expectEqual(0, connection.output_len);
    try connection.respond(1, ok, &.{}, true);
}

test "RFC 9113 §6.7: the PING acknowledgments h2 owes go out, and the request after them is read" {
    try start();
    var writer = h2.core.Writer.init(&frames);
    // One more PING than h2 holds acknowledgments for, so it stops reading until they are written.
    for (0..h2.constants.ping_ack_pending_max + 1) |_| try h2.frame.write_ping(&writer, @splat(0), false);
    const pings_len = writer.written().len;
    @memcpy(support.input[0..pings_len], frames[0..pings_len]);
    const request = try request_frame(1, "/", true);
    @memcpy(support.input[pings_len..][0..request.len], request);
    const received = try connection.receive(support.input[0 .. pings_len + request.len], support.now_ns);
    try testing.expectEqual(pings_len + request.len, received.consumed);
    try testing.expectEqual(1, received.event.?.request.id);
}

test "RFC 9113 §6.8: nothing h2 owes goes out once the transport closed" {
    try start();
    _ = try support.receive_copy(try request_frame(1, "/", true));
    connection.shutdown();
    connection.transport_closed();
    try testing.expectEqual(0, connection.send(&support.output, support.now_ns));
    try testing.expect(connection.should_close());
}

test "RFC 9110 §10.1.1: an h2 request expecting 100-continue gets a 100 HEADERS frame" {
    try start();
    var block: [constants.frame_size_max]u8 = undefined;
    var encoder: h2.hpack.Encoder = undefined;
    encoder.init(constants.header_table_size_initial, .never);
    var block_writer = h2.core.Writer.init(&block);
    try encoder.begin_block(&block_writer);
    try encoder.write_field(&block_writer, ":method", "PUT", .without_indexing);
    try encoder.write_field(&block_writer, ":scheme", "http", .without_indexing);
    try encoder.write_field(&block_writer, ":path", "/f", .without_indexing);
    try encoder.write_field(&block_writer, ":authority", "example.com", .without_indexing);
    try encoder.write_field(&block_writer, "expect", "100-continue", .without_indexing);
    encoder.commit_block();
    var writer = h2.core.Writer.init(&frames);
    try h2.frame.write_header(&writer, .{
        .length = @intCast(block_writer.written().len),
        .type = constants.frame_type_headers,
        .flags = constants.flag_end_headers,
        .stream_id = 1,
    });
    try writer.write_bytes(block_writer.written());
    const head = (try support.receive_copy(writer.written())).event.?.request;
    try testing.expectEqual(2, head.version.major);
    try testing.expectEqualStrings("/f", head.target);
    const sent = support.drain();
    try testing.expectEqual(constants.frame_type_headers, sent[type_index]);
    decoder.init(constants.header_table_size_initial);
    var lines = decoder.block(sent[constants.frame_header_len..frame_len(sent)]);
    try testing.expectEqualStrings("100", (try lines.next()).?.value);
}
