//! The tests of the server's h2 half (`connection_h2.zig`) over cleartext with prior knowledge
//! (RFC 9113 §3.3): h2's events arrive as the server's, and responses go out through h2's send
//! path.
const std = @import("std");
const h2 = @import("h2");
const support = @import("connection_test_support.zig");
const h2_support = @import("connection_h2_test_support.zig");

const testing = std.testing;
const connection = &support.connection;
const constants = h2.constants;

const content_type = [_]support.Field{.{ .name = "content-type", .value = "text/plain" }};
const ok: u16 = 200;
const early_hints: u16 = 103;

const start = h2_support.start;
const request_frame = h2_support.request_frame;
const frame_len = h2_support.frame_len;
const frames = &h2_support.frames;
const type_index = h2_support.type_index;
const flags_index = h2_support.flags_index;

/// Where a test decodes what the server sent. Test-only.
var decoder: h2.hpack.Decoder align(@alignOf(h2.hpack.Decoder)) = undefined;

/// Octets of the error code that ends an RST_STREAM frame (RFC 9113 §6.4).
const error_code_len: usize = 4;

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

test "RFC 9113 §3.4: the server's SETTINGS goes first, before a response to a request read with the preface" {
    try support.start_cleartext(.h2);
    // A client need not wait for the server's preface, so its own, its SETTINGS and a request can
    // arrive in one read (RFC 9113 §3.4).
    const preface = h2_support.client_preface;
    const request = try request_frame(1, "/", true);
    var flight: [preface.len + request_len_max]u8 = undefined;
    @memcpy(flight[0..preface.len], preface);
    @memcpy(flight[preface.len..][0..request.len], request);
    const received = try support.receive_copy(flight[0 .. preface.len + request.len]);
    try testing.expectEqual(1, received.event.?.request.id);
    try connection.respond(1, .{ .status = ok, .end = true });
    const sent = support.drain();
    // RFC 9113 §3.4: the SETTINGS frame "MUST be the first frame the server sends".
    try testing.expectEqual(constants.frame_type_settings, sent[type_index]);
    try testing.expectEqual(0, sent[flags_index]);
}

/// The most octets `request_frame` writes for the paths these tests use.
const request_len_max: usize = 256;

test "RFC 9113 §8.1: a response is a HEADERS frame, then DATA whose last frame ends the stream" {
    try start();
    _ = try support.receive_copy(try request_frame(1, "/", true));
    try connection.respond(1, .{ .status = ok, .fields = &content_type, .end = false });
    // No octets and no end write nothing, not even an empty frame (RFC 9113 §6.1).
    try testing.expectEqual(0, try connection.write_body(1, .{ .octets = "", .end = false }));
    try testing.expectEqual(5, try connection.write_body(1, .{ .octets = "hello", .end = true }));
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

test "RFC 9113 §8.1: an interim response ends no stream, whatever `end` asks, and the final one does" {
    try start();
    _ = try support.receive_copy(try request_frame(1, "/", true));
    try connection.respond(1, .{ .status = early_hints, .end = true });
    try connection.respond(1, .{ .status = ok, .end = true });
    const sent = support.drain();
    try testing.expectEqual(constants.frame_type_headers, sent[type_index]);
    try testing.expectEqual(constants.flag_end_headers, sent[flags_index]);
    const final = sent[frame_len(sent)..];
    try testing.expectEqual(constants.frame_type_headers, final[type_index]);
    try testing.expectEqual(constants.flag_end_headers | constants.flag_end_stream, final[flags_index]);
}

test "RFC 9113 §8.1: a request's DATA arrives as body events, the last ending it" {
    try start();
    _ = try support.receive_copy(try request_frame(1, "/", false));
    var writer = h2.core.Writer.init(frames);
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
    try testing.expectError(error.RequestUnknown, connection.respond(1, .{ .status = ok, .end = true }));
}

test "RFC 9113 §6.4: a stream the peer resets arrives as its cancellation" {
    try start();
    _ = try support.receive_copy(try request_frame(1, "/", false));
    var writer = h2.core.Writer.init(frames);
    try h2.frame.write_rst_stream(&writer, 1, constants.error_cancel);
    const received = try support.receive_copy(writer.written());
    try testing.expectEqual(1, received.event.?.cancelled.id);
}

test "RFC 9113 §5.1.1: an id no client stream can have names no request" {
    try start();
    _ = try support.receive_copy(try request_frame(1, "/", true));
    try testing.expectError(error.RequestUnknown, connection.respond(2, .{ .status = ok, .end = true }));
    try testing.expectError(error.RequestUnknown, connection.respond(0, .{ .status = ok, .end = true }));
    try testing.expectError(error.RequestUnknown, connection.respond(3, .{ .status = ok, .end = true }));
    // RFC 9113 §8.1: content follows the final response's head.
    try testing.expectError(error.SectionOutOfOrder, connection.write_body(1, .{ .octets = "x", .end = true }));
}

/// Content past the initial window of RFC 9113 §6.9.2. Test-only.
const window_initial: usize = 65_535;
var large_body: [window_initial + 1]u8 = @splat('x');

test "RFC 9113 §6.9: content past the stream's window waits, and write_body says so" {
    try start();
    _ = try support.receive_copy(try request_frame(1, "/", true));
    try connection.respond(1, .{ .status = ok, .end = false });
    var taken: usize = 0;
    // Bounded: each pass takes what the output holds, until the window closes.
    for (0..large_body.len) |_| {
        const consumed = connection.write_body(1, .{ .octets = large_body[taken..], .end = true }) catch |failure| {
            try testing.expectEqual(error.Blocked, failure);
            break;
        };
        taken += consumed;
        _ = support.drain();
    }
    try testing.expectEqual(window_initial, taken);
    try testing.expectError(error.Blocked, connection.write_body(1, .{ .octets = large_body[taken..], .end = true }));
}

test "RFC 9113 §4.1: a response head waits when the output has no room for its frame" {
    try start();
    _ = try support.receive_copy(try request_frame(1, "/", true));
    const short_room: usize = 4;
    connection.output_len = support.server_constants.output_len - short_room;
    try testing.expectError(error.NoSpaceLeft, connection.respond(1, .{ .status = ok, .end = true }));
    connection.output_len = 0;
    try connection.respond(1, .{ .status = ok, .end = true });
}

test "RFC 9113 §6.8: a shutdown sends GOAWAY, and the connection closes once its streams end" {
    try start();
    _ = try support.receive_copy(try request_frame(1, "/", true));
    connection.shutdown();
    try testing.expect(!connection.should_close());
    try connection.respond(1, .{ .status = ok, .end = true });
    const sent = support.drain();
    try testing.expect(std.mem.indexOfScalar(u8, &.{ sent[type_index], sent[frame_len(sent) + type_index] }, constants.frame_type_goaway) != null);
    try testing.expect(connection.should_close());
}

test "RFC 9113 §5.4.1: a connection error fails the connection, and its GOAWAY goes out" {
    try start();
    // RFC 9113 §5.1: a DATA frame on an idle stream is a connection error.
    var writer = h2.core.Writer.init(frames);
    try h2.frame.write_data(&writer, 1, "x", false, 0);
    try testing.expectError(error.ConnectionFailed, support.receive_copy(writer.written()));
    try testing.expect(!connection.should_close());
    const sent = support.drain();
    try testing.expectEqual(constants.frame_type_goaway, sent[type_index]);
    try testing.expect(connection.should_close());
    try testing.expectError(error.ConnectionClosed, connection.respond(1, .{ .status = ok, .end = true }));
    // The peer broke the protocol, and passed no limit.
    try testing.expectEqual(null, connection.close_reason());
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
    var writer = h2.core.Writer.init(frames);
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
    try testing.expectError(error.RequestUnknown, connection.respond(past, .{ .status = ok, .end = true }));
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
    try testing.expectError(error.SectionTooLarge, connection.respond(1, .{ .status = ok, .fields = &too_many, .end = true }));
    for (&long_fields) |*line| line.* = .{ .name = "x-long", .value = &long_value };
    try testing.expectError(error.SectionTooLarge, connection.respond(1, .{ .status = ok, .fields = &long_fields, .end = true }));
    try testing.expectEqual(0, connection.output_len);
    try connection.respond(1, .{ .status = ok, .end = true });
}

test "RFC 9113 §6.7: the PING acknowledgments h2 owes go out, and the request after them is read" {
    try start();
    var writer = h2.core.Writer.init(frames);
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
    var writer = h2.core.Writer.init(frames);
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

test "decision 110: the server advertises 100 concurrent streams, refuses the next, and a configuration lowers it" {
    try support.start_cleartext(.h2);
    _ = try support.receive_copy(h2_support.client_preface);
    const sent = support.drain();
    // RFC 9113 §6.5.2: SETTINGS_MAX_CONCURRENT_STREAMS carries the limit.
    try testing.expect(lists_streams_max(sent, support.server_constants.h2_streams_max));
    try expect_refused_after(support.server_constants.h2_streams_max);
    support.config = .{ .cleartext = .h2, .h2_streams_max = lowered_streams_max };
    try connection.init(&support.config, support.stream.random(), 0, 0);
    _ = try support.receive_copy(h2_support.client_preface);
    try testing.expect(lists_streams_max(support.drain(), lowered_streams_max));
    try expect_refused_after(lowered_streams_max);
}

/// The streams a configuration lowers the limit to.
const lowered_streams_max: u32 = 2;

/// Opens `limit` streams, each a request whose body is still to come, and requires the next to be
/// refused with REFUSED_STREAM (RFC 9113 §5.1.2).
fn expect_refused_after(limit: u32) !void {
    for (0..limit) |index| {
        const stream_id: u32 = @intCast(constants.stream_id_client_first + constants.stream_id_step * index);
        try testing.expectEqual(stream_id, (try support.receive_copy(try h2_support.request_frame(stream_id, "/", false))).event.?.request.id);
    }
    const refused_id = constants.stream_id_client_first + constants.stream_id_step * limit;
    const cancelled = (try support.receive_copy(try h2_support.request_frame(refused_id, "/", false))).event.?.cancelled;
    try testing.expectEqual(refused_id, cancelled.id);
    try testing.expect(cancelled.reason == .refused);
}

/// Whether the server's SETTINGS frame at the front of `sent` lists SETTINGS_MAX_CONCURRENT_STREAMS
/// as `limit`: each entry is an identifier of two octets and a value of four (RFC 9113 §6.5.1).
fn lists_streams_max(sent: []const u8, limit: u32) bool {
    const length = std.mem.readInt(u24, sent[0..constants.frame_length_len], .big);
    const entries = sent[constants.frame_header_len..][0..length];
    for (0..length / constants.setting_len) |index| {
        const entry = entries[index * constants.setting_len ..][0..constants.setting_len];
        if (std.mem.readInt(u16, entry[0..@sizeOf(u16)], .big) != constants.setting_max_concurrent_streams) continue;
        return std.mem.readInt(u32, entry[@sizeOf(u16)..][0..@sizeOf(u32)], .big) == limit;
    }
    return false;
}

test "decision 110: a peer that resets streams past peer_reset_rate_max ends the connection, and the limit is named" {
    try start();
    var id: u32 = 1;
    for (0..constants.peer_reset_rate_max) |_| {
        try open_and_reset(id);
        id += 2;
    }
    try testing.expectEqual(null, connection.close_reason());
    // RFC 9113 §10.5: the reset past the limit is excess use, and ends the connection.
    try testing.expectError(error.ConnectionFailed, open_and_reset(id));
    try testing.expectEqual(.peer_resets, connection.close_reason().?.limit);
}

/// Opens stream `id` with a whole request, then resets it, as a Rapid Reset peer does
/// (CVE-2023-44487). Test-only.
fn open_and_reset(id: u32) !void {
    const opened = try support.receive_copy(try request_frame(id, "/", true));
    try testing.expectEqual(id, opened.event.?.request.id);
    var writer = h2.core.Writer.init(frames);
    try h2.frame.write_rst_stream(&writer, id, constants.error_cancel);
    const reset = try support.receive_copy(writer.written());
    try testing.expectEqual(id, reset.event.?.cancelled.id);
}
