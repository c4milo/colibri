//! The tests of a response to HEAD over TCP, in h11 and h2 (RFC 9110 §9.3.2): the program writes
//! the answer it writes for GET, and the connection takes the content and writes none of it. The
//! Content-Length the program states goes out as the program states it.
const std = @import("std");
const h2 = @import("h2");
const support = @import("connection_test_support.zig");
const h2_support = @import("connection_h2_test_support.zig");

const testing = std.testing;
const connection = &support.connection;
const constants = h2.constants;
const Field = support.Field;

const ok: u16 = 200;
const content = "hello";
/// Where the program cuts `content` in two calls.
const cut: usize = 3;
const head_fields = [_]Field{
    .{ .name = "content-type", .value = "text/plain" },
    .{ .name = "content-length", .value = "5" },
};
const accepts_gzip = [_]Field{.{ .name = "accept-encoding", .value = "gzip" }};

const head_request = "HEAD /index.html HTTP/1.1\r\nHost: example.test\r\n\r\n";
const get_request = "GET /index.html HTTP/1.1\r\nHost: example.test\r\n\r\n";

/// Where a test decodes the head of an h2 response. Test-only.
threadlocal var test_decoder: h2.hpack.Decoder align(@alignOf(h2.hpack.Decoder)) = undefined;

/// Reads `request` and expects its head, with the id `id`.
fn expect_request(request: []const u8, id: u64) !void {
    const received = try support.receive_copy(request);
    try testing.expectEqual(request.len, received.consumed);
    try testing.expectEqual(id, received.event.?.request.id.number);
}

/// Writes `content` as the program writes it for GET: in two calls, the second with the end.
fn write_content(id: u64) !void {
    try testing.expectEqual(cut, try connection.write_body(id, .{ .bytes = content[0..cut], .end = false }));
    try testing.expectEqual(content.len - cut, try connection.write_body(id, .{ .bytes = content[cut..], .end = true }));
}

test "RFC 9110 §9.3.2: h11 takes the content of a response to HEAD and writes none" {
    try support.start_cleartext(.h11);
    try expect_request(head_request, 1);
    // RFC 9110 §6.4.1: content follows the final response, so none is taken before it.
    try testing.expectError(error.SectionOutOfOrder, connection.write_body(1, .{ .bytes = content, .end = true }));
    try connection.respond(1, .{ .status = ok, .headers = &head_fields, .end = false });
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 5\r\n\r\n", support.drain());
    try write_content(1);
    try testing.expectEqual(0, support.drain().len);
    try support.expect_done(1);
    // A GET on the same connection gets its content.
    try expect_request(get_request, 2);
    try connection.respond(2, .{ .status = ok, .headers = &head_fields, .end = false });
    try write_content(2);
    try testing.expectEqualStrings("HTTP/1.1 200 OK\r\ncontent-type: text/plain\r\ncontent-length: 5\r\n\r\nhello", support.drain());
}

/// Reads the HEADERS frame at the front of `sent` on `stream_id`, expects the program's
/// Content-Length in it, and returns the octets after it.
fn expect_head(sent: []const u8, stream_id: u32) ![]const u8 {
    try testing.expectEqual(constants.frame_type_headers, sent[h2_support.type_index]);
    try testing.expectEqual(stream_id, std.mem.readInt(u32, sent[stream_id_at..constants.frame_header_len], .big));
    const head_len = h2_support.frame_len(sent);
    var block = test_decoder.block(sent[constants.frame_header_len..head_len]);
    var length: ?[]const u8 = null;
    // Bounded by the block's field lines, each one octet at least.
    for (0..head_len) |_| {
        const line = (try block.next()) orelse break;
        if (std.mem.eql(u8, line.name, "content-length")) length = line.value;
    }
    // RFC 9113 §8.1.1: a response to HEAD can carry a non-zero content-length.
    try testing.expectEqualStrings("5", length.?);
    return sent[head_len..];
}

/// Expects `sent` to be one DATA frame on `stream_id` that carries no octet and ends the stream.
fn expect_empty_end(sent: []const u8, stream_id: u32) !void {
    try testing.expectEqual(constants.frame_header_len, sent.len);
    try testing.expectEqual(constants.frame_type_data, sent[h2_support.type_index]);
    try testing.expectEqual(constants.flag_end_stream, sent[h2_support.flags_index]);
    try testing.expectEqual(stream_id, std.mem.readInt(u32, sent[stream_id_at..constants.frame_header_len], .big));
}

/// Where a frame header's stream identifier starts: its last four octets (RFC 9113 §4.1).
const stream_id_at: usize = constants.frame_header_len - @sizeOf(u32);

test "RFC 9113 §8.1.1: h2 takes the content of a response to HEAD and writes no DATA octet" {
    try h2_support.start();
    test_decoder.init(constants.header_table_size_initial);
    _ = try support.receive_copy(try h2_support.request_frame_with(1, "HEAD", "/", &.{}, true));
    // RFC 9113 §8.1: DATA follows the final response's HEADERS frame.
    try testing.expectError(error.SectionOutOfOrder, connection.write_body(1, .{ .bytes = content, .end = true }));
    try connection.respond(1, .{ .status = ok, .headers = &head_fields, .end = false });
    try testing.expectEqual(0, (try expect_head(support.drain(), 1)).len);
    try testing.expectEqual(cut, try connection.write_body(1, .{ .bytes = content[0..cut], .end = false }));
    try testing.expectEqual(0, support.drain().len);
    try testing.expectEqual(content.len - cut, try connection.write_body(1, .{ .bytes = content[cut..], .end = true }));
    try expect_empty_end(support.drain(), 1);
    try support.expect_done(1);
    // A GET on the same connection gets its content.
    _ = try support.receive_copy(try h2_support.request_frame(3, "/", true));
    try connection.respond(3, .{ .status = ok, .headers = &head_fields, .end = false });
    try testing.expectEqual(content.len, try connection.write_body(3, .{ .bytes = content, .end = true }));
    const data = try expect_head(support.drain(), 3);
    try testing.expectEqualStrings(content, data[constants.frame_header_len..]);
    try testing.expectEqual(0, connection.coding.used);
}

test "RFC 9110 §9.3.2: an h2 response to HEAD that ends with its head, or that the program cancels, holds no entry" {
    try h2_support.start();
    _ = try support.receive_copy(try h2_support.request_frame_with(1, "HEAD", "/", &.{}, true));
    try connection.respond(1, .{ .status = ok, .headers = &head_fields, .end = true });
    try testing.expectEqual(0, connection.coding.used);
    _ = support.drain();
    try support.expect_done(1);
    _ = try support.receive_copy(try h2_support.request_frame_with(3, "HEAD", "/", &.{}, true));
    try connection.respond(3, .{ .status = ok, .headers = &head_fields, .end = false });
    try testing.expectEqual(1, connection.coding.used);
    connection.cancel(3);
    try testing.expectEqual(0, connection.coding.used);
}

test "RFC 9110 §9.3.2: an h2 connection that codes content takes the content of a response to HEAD and writes none" {
    try support.start_coding(.h2);
    try h2_support.start_preface();
    test_decoder.init(constants.header_table_size_initial);
    _ = try support.receive_copy(try h2_support.request_frame_with(1, "HEAD", "/", &accepts_gzip, true));
    try connection.respond(1, .{ .status = ok, .headers = &head_fields, .end = false, .codable = true });
    try write_content(1);
    const sent = support.drain();
    // Decision 101: a coded representation loses Content-Length, so the head names none here.
    try testing.expectEqual(constants.frame_type_headers, sent[h2_support.type_index]);
    try expect_empty_end(sent[h2_support.frame_len(sent)..], 1);
    try support.expect_done(1);
    try testing.expectEqual(0, connection.coding.used);
    try testing.expectEqual(2, support.pool.free_count());
}
