//! The tests of content codings over h2 (`connection_coding.zig`, decision 101): a coded response
//! goes out in DATA frames that h2's windows admit, `send` moves each stream's coded octets on as
//! the windows open, and a stream the peer resets gives its encoder back.
const std = @import("std");
const h2 = @import("h2");
const http = @import("http");
const support = @import("connection_test_support.zig");
const h2_support = @import("connection_h2_test_support.zig");

const testing = std.testing;
const connection = &support.connection;
const constants = h2.constants;
const Field = support.Field;

const ok: u16 = 200;
const encoders_all: usize = 2;
const accepts_deflate = [_]Field{.{ .name = "accept-encoding", .value = "deflate" }};
const accepts_gzip = [_]Field{.{ .name = "accept-encoding", .value = "gzip" }};

/// Where a test gathers what the connection sent, one stream's content, and the decoder of the
/// response heads. Test-only.
threadlocal var test_sent: [support.coded_len_max]u8 = undefined;
threadlocal var test_content: [support.coded_len_max]u8 = undefined;
threadlocal var test_decoder: h2.hpack.Decoder align(@alignOf(h2.hpack.Decoder)) = undefined;

/// What one stream of a response carried.
const Gathered = struct {
    /// The coding its head's Content-Encoding names, or null.
    coding: ?http.content_coding.Coding = null,
    vary: bool = false,
    content: []const u8 = &.{},
    /// A DATA frame carried END_STREAM, and the octets of the last DATA frame.
    ended: bool = false,
    last_len: usize = 0,
};

/// The head and the content `sent` carries on `stream_id`. The heads decode in order, so `sent`
/// holds everything the connection sent since `start`.
fn gather(sent: []const u8, stream_id: u32) !Gathered {
    var gathered: Gathered = .{};
    var content_len: usize = 0;
    var at: usize = 0;
    test_decoder.init(constants.header_table_size_initial);
    // Bounded: each pass steps over a whole frame.
    for (0..sent.len) |_| {
        if (at == sent.len) break;
        const frame = sent[at..][0..h2_support.frame_len(sent[at..])];
        at += frame.len;
        const payload = frame[constants.frame_header_len..];
        const on_stream = std.mem.readInt(u32, frame[stream_id_at..constants.frame_header_len], .big) & constants.stream_id_max;
        // Every head decodes, whatever its stream, so the decoder's table stays the encoder's.
        if (frame[h2_support.type_index] == constants.frame_type_headers) try read_head(payload, on_stream == stream_id, &gathered);
        if (on_stream != stream_id or frame[h2_support.type_index] != constants.frame_type_data) continue;
        @memcpy(test_content[content_len..][0..payload.len], payload);
        content_len += payload.len;
        gathered.ended = frame[h2_support.flags_index] & constants.flag_end_stream != 0;
        gathered.last_len = payload.len;
    }
    gathered.content = test_content[0..content_len];
    return gathered;
}

/// Decodes a HEADERS frame's block, and keeps its coding fields when it is the stream's.
fn read_head(payload: []const u8, keep: bool, gathered: *Gathered) !void {
    var block = test_decoder.block(payload);
    // Bounded by the block's field lines, each one octet at least.
    for (0..payload.len) |_| {
        const line = (try block.next()) orelse return;
        if (!keep) continue;
        if (std.mem.eql(u8, line.name, "content-encoding")) gathered.coding = http.content_coding.from_name(line.value);
        if (std.mem.eql(u8, line.name, "vary")) gathered.vary = std.mem.eql(u8, line.value, "accept-encoding");
    }
}

/// Where a frame header's stream identifier starts: its last four octets (RFC 9113 §4.1).
const stream_id_at: usize = constants.frame_header_len - @sizeOf(u32);

/// Everything the connection owes, sent after what `test_sent` holds from `sent_len`.
fn send_more(sent_len: *usize) void {
    sent_len.* += connection.send(test_sent[sent_len.*..], support.now_ns);
}

test "decision 101: an h2 response is coded into DATA frames, and the last one ends the stream" {
    try support.start_coding(.h2);
    try h2_support.start_preface();
    _ = try support.receive_copy(try h2_support.request_frame_with(1, "GET", "/", &accepts_deflate, true));
    try connection.respond(1, .{ .status = ok, .end = false, .codable = true });
    try testing.expectEqual(11, try connection.write_body(1, .{ .octets = "hello world", .end = true }));
    var sent_len: usize = 0;
    send_more(&sent_len);
    const gathered = try gather(test_sent[0..sent_len], 1);
    try testing.expectEqual(http.content_coding.Coding.deflate, gathered.coding.?);
    try testing.expect(gathered.vary and gathered.ended);
    // The frame that ends the stream carries the last coded octets, and no empty one follows.
    try testing.expect(gathered.last_len > 0);
    try testing.expectEqualStrings("hello world", try support.decode(.deflate, gathered.content));
    try support.expect_done(1);
    try testing.expectEqual(encoders_all, support.pool.free_count());
}

test "decision 101: two coded streams go past the connection's window, and on as WINDOW_UPDATE opens it" {
    support.fill_incompressible();
    try support.start_coding(.h2);
    try h2_support.start_preface();
    const content = support.incompressible[0..stream_content_len];
    var sent_len: usize = 0;
    for ([_]u32{ 1, 3 }) |stream_id| {
        _ = try support.receive_copy(try h2_support.request_frame_with(stream_id, "GET", "/", &accepts_gzip, true));
        try connection.respond(stream_id, .{ .status = ok, .end = false, .codable = true });
        try testing.expectEqual(content.len, try connection.write_body(stream_id, .{ .octets = content, .end = true }));
        // One call writes every frame the room takes, so the next head waits for a send.
        send_more(&sent_len);
    }
    try testing.expectEqual(0, support.pool.free_count());
    // RFC 9113 §6.9.1: the connection's window of 65,535 octets stops the second stream partway.
    send_more(&sent_len);
    send_more(&sent_len);
    try testing.expect(!(try gather(test_sent[0..sent_len], 3)).ended);
    var writer = h2.core.Writer.init(&h2_support.frames);
    try h2.frame.write_window_update(&writer, 0, window_increment);
    try h2.frame.write_window_update(&writer, 3, window_increment);
    const updates = writer.written();
    const received = try support.receive_copy(updates);
    try testing.expectEqual(null, received.event);
    // Bounded: each round's `send` moves the second stream's coded octets on.
    for (0..rounds_max) |_| {
        send_more(&sent_len);
        if (support.pool.free_count() == encoders_all) break;
    }
    for ([_]u32{ 1, 3 }) |stream_id| {
        const gathered = try gather(test_sent[0..sent_len], stream_id);
        try testing.expect(gathered.ended);
        try testing.expectEqualSlices(u8, content, try support.decode(.gzip, gathered.content));
    }
    try testing.expectEqual(encoders_all, support.pool.free_count());
}

/// Octets of each stream's content: together more than the connection's first window.
const stream_content_len: usize = 49_152;
/// What a WINDOW_UPDATE adds: as much again as the first window (RFC 9113 §6.9.2).
const window_increment: u32 = 65_535;
const rounds_max: usize = 64;

test "decision 101: a stream the peer resets gives its encoder back, and its octets go nowhere" {
    support.fill_incompressible();
    try support.start_coding(.h2);
    try h2_support.start_preface();
    _ = try support.receive_copy(try h2_support.request_frame_with(1, "GET", "/", &accepts_gzip, true));
    try connection.respond(1, .{ .status = ok, .end = false, .codable = true });
    _ = try connection.write_body(1, .{ .octets = support.incompressible[0..], .end = false });
    try testing.expectEqual(encoders_all - 1, support.pool.free_count());
    var writer = h2.core.Writer.init(&h2_support.frames);
    try h2.frame.write_rst_stream(&writer, 1, constants.error_cancel);
    const received = try support.receive_copy(writer.written());
    try testing.expectEqual(1, received.event.?.cancelled.id.number);
    try testing.expectEqual(encoders_all, support.pool.free_count());
    try testing.expectError(error.RequestUnknown, connection.write_body(1, .{ .octets = "x", .end = true }));
    // The frames stream 1 wrote fill the output, so the next head waits for a send.
    _ = support.drain();
    // A stream the caller cancels gives its encoder back too (RFC 9113 §6.4).
    _ = try support.receive_copy(try h2_support.request_frame_with(3, "GET", "/", &accepts_gzip, true));
    try connection.respond(3, .{ .status = ok, .end = false, .codable = true });
    _ = try connection.write_body(3, .{ .octets = support.incompressible[0..], .end = false });
    connection.cancel(3);
    try testing.expectEqual(encoders_all, support.pool.free_count());
}

test "RFC 9113 §5.4.1: a connection that failed writes no coded octets after its GOAWAY" {
    support.fill_incompressible();
    try support.start_coding(.h2);
    try h2_support.start_preface();
    _ = try support.receive_copy(try h2_support.request_frame_with(1, "GET", "/", &accepts_gzip, true));
    try connection.respond(1, .{ .status = ok, .end = false, .codable = true });
    // The window takes the coded content, and the output holds less, so the ring keeps the rest.
    _ = try connection.write_body(1, .{ .octets = support.incompressible[0..stream_content_len], .end = true });
    var writer = h2.core.Writer.init(&h2_support.frames);
    // RFC 9113 §6.1: a DATA frame on stream 0 is a connection error. h2's writer sends none, so
    // the test writes its header itself.
    try h2.frame.write_header(&writer, .{ .length = 1, .type = constants.frame_type_data, .flags = 0, .stream_id = 0 });
    try writer.write_bytes("x");
    try testing.expectError(error.ConnectionFailed, support.receive_copy(writer.written()));
    var sent_len: usize = 0;
    // Bounded: each round's `send` writes what the output holds, until the connection closes.
    for (0..rounds_max) |_| {
        send_more(&sent_len);
        if (connection.should_close()) break;
    }
    try testing.expect(connection.should_close());
    try testing.expect(!data_after_goaway(test_sent[0..sent_len]));
    connection.transport_closed();
    try testing.expectEqual(encoders_all, support.pool.free_count());
}

/// Whether a DATA frame follows a GOAWAY frame in `sent`.
fn data_after_goaway(sent: []const u8) bool {
    var at: usize = 0;
    var goaway_seen = false;
    // Bounded: each pass steps over a whole frame.
    for (0..sent.len) |_| {
        if (at == sent.len) break;
        const frame_type = sent[at + h2_support.type_index];
        if (goaway_seen and frame_type == constants.frame_type_data) return true;
        if (frame_type == constants.frame_type_goaway) goaway_seen = true;
        at += h2_support.frame_len(sent[at..]);
    }
    return false;
}
