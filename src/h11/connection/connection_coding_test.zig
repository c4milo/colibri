//! The tests of the `gzip` and `deflate` transfer codings on an h11 connection (decisions 91 and
//! 98), split out because a hand-written source file stays at or under 500 lines with its tests
//! included (CLAUDE.md).
const std = @import("std");
const core = @import("core");
const http = @import("http");
const gzip = @import("gzip");
const zlib = @import("zlib");
const coding = @import("../coding.zig");
const connection = @import("connection.zig");

const testing = std.testing;
const Connection = connection.Connection;
const Field = http.field.Field;

/// The connection, the pool of one decoder, the encoders and the buffers the tests use, placed
/// outside any stack frame.
var test_connection: Connection align(@alignOf(Connection)) = undefined;
var test_pool: coding.Pool(1) align(@alignOf(coding.Pool(1))) = undefined;
var test_gzip: gzip.Encoder(.{ .level = 1 }) align(@alignOf(gzip.Encoder(.{ .level = 1 }))) = undefined;
var test_zlib: zlib.Encoder(.{ .level = 1 }) align(@alignOf(zlib.Encoder(.{ .level = 1 }))) = undefined;
var test_input: [test_input_len]u8 = undefined;
var test_output: [test_output_len]u8 = undefined;
const test_input_len = 4096;
const test_output_len = 512;

/// Copies of the sentence in `test_text`: enough for DEFLATE to use back-references.
const test_text_repeats = 12;
/// The body the tests code.
const test_text = "a coded body decodes to the octets it was coded from. " ** test_text_repeats;
/// RFC 1952 §2.3: a member ends with CRC32 and ISIZE, four octets each.
const crc32_offset_from_end = 8;
/// Octets of the hex chunk-size of a test chunk, which is under 16^2.
const chunk_size_digits_max = 2;
/// Octets of coded data each chunk of a test body carries.
const test_chunk_len = 37;
/// Calls `read_all` makes past one per octet decoded: the heads, the owed end, and the last call.
const test_calls_past_len = 4;

const host: []const Field = &.{.{ .name = "Host", .value = "h" }};
const request_head = "POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: gzip, chunked\r\n\r\n";
const deflate_request_head = "POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: deflate, chunked\r\n\r\n";

fn pool() coding.Storage {
    const storage = test_pool.storage();
    storage.reset(coding.Features.none());
    return storage;
}

fn gzip_of(text: []const u8, output: []u8) ![]const u8 {
    test_gzip.init(coding.Features.none());
    return output[0..try test_gzip.encode_all(text, output)];
}

fn zlib_of(text: []const u8, output: []u8) ![]const u8 {
    test_zlib.init(coding.Features.none());
    return output[0..try test_zlib.encode_all(text, output)];
}

/// `head`, then `coded` in chunks of `test_chunk_len`, then the last chunk (RFC 9112 §7.1).
fn chunked_message(head: []const u8, coded: []const u8) ![]const u8 {
    var writer = core.Writer.init(&test_input);
    try writer.write_bytes(head);
    var offset: usize = 0;
    // Bounded by the coded octets.
    while (offset < coded.len) {
        const piece = coded[offset..@min(coded.len, offset + test_chunk_len)];
        var size: [chunk_size_digits_max]u8 = undefined;
        try writer.write_bytes(try std.fmt.bufPrint(&size, "{x}", .{piece.len}));
        try writer.write_bytes("\r\n");
        try writer.write_bytes(piece);
        try writer.write_bytes("\r\n");
        offset += piece.len;
    }
    try writer.write_bytes("0\r\n\r\n");
    return writer.written();
}

/// What `read_all` saw: the octets consumed, the data the events carried, and whether `end` came.
const Whole = struct { consumed: usize, body: []const u8, ended: bool };

/// Receives from `input` with `room` octets for decoding, until nothing is consumed, gathering
/// every data event's octets into `body`.
fn read_all(target: *Connection, input: []const u8, room: usize, body: []u8) !Whole {
    var decoded: [test_text.len]u8 = undefined;
    var offset: usize = 0;
    var gathered: usize = 0;
    var ended = false;
    for (0..input.len + test_text.len + test_calls_past_len) |_| {
        const received = try target.receive(input[offset..], decoded[0..room]);
        offset += received.consumed;
        if (received.event) |event| switch (event) {
            .data => |data| {
                @memcpy(body[gathered..][0..data.len], data);
                gathered += data.len;
            },
            .end => ended = true,
            else => {},
        };
        if (received.consumed == 0 and received.event == null) break;
    }
    return .{ .consumed = offset, .body = body[0..gathered], .ended = ended };
}

/// Requires the connection to have failed on `input`, owing `status`, with the decoder back.
fn expect_refused(storage: coding.Storage, input: []const u8, status: u16) !void {
    test_connection.init(.server, .{ .decoders = storage });
    var body: [test_text.len]u8 = undefined;
    try testing.expectError(error.ConnectionFailed, read_all(&test_connection, input, test_text.len, &body));
    try testing.expectEqual(status, test_connection.reply_status.?);
    try expect_pool_free(storage);
}

/// The pool's one decoder is free: a message can take it.
fn expect_pool_free(storage: coding.Storage) !void {
    var decoding: coding.Decoding = .{};
    try coding.start(&decoding, storage, .gzip);
    coding.release(&decoding, storage);
}

test "decision 98: a gzip, chunked request decodes into whatever room the caller gives" {
    const storage = pool();
    var coded_room: [test_input_len]u8 = undefined;
    const input = try chunked_message(request_head, try gzip_of(test_text, &coded_room));
    for ([_]usize{ 1, 7, test_text.len }) |room| {
        test_connection.init(.server, .{ .decoders = storage });
        var body: [test_text.len]u8 = undefined;
        const whole = try read_all(&test_connection, input, room, &body);
        try testing.expectEqual(input.len, whole.consumed);
        try testing.expectEqualStrings(test_text, whole.body);
        try testing.expect(whole.ended);
        try testing.expectEqual(connection.Phase.waiting, test_connection.phase);
        try expect_pool_free(storage);
    }
}

test "RFC 9112 §6.1: a server with no decoders answers a coded request 501, and one whose are taken 503" {
    var coded_room: [test_input_len]u8 = undefined;
    const input = try chunked_message(request_head, try gzip_of(test_text, &coded_room));
    test_connection.init(.server, .{});
    try testing.expectError(error.ConnectionFailed, test_connection.receive(input, &.{}));
    try testing.expectEqual(501, test_connection.reply_status.?);
    // RFC 9110 §15.6.4: every decoder taken is a temporary overload.
    const storage = pool();
    var holder: coding.Decoding = .{};
    try coding.start(&holder, storage, .deflate);
    test_connection.init(.server, .{ .decoders = storage });
    try testing.expectError(error.ConnectionFailed, test_connection.receive(input, &.{}));
    try testing.expectEqual(503, test_connection.reply_status.?);
    coding.release(&holder, storage);
}

test "decision 91: a corrupt body is a 400, a refused feature a 501, and each gives its decoder back" {
    const storage = pool();
    var coded_room: [test_input_len]u8 = undefined;
    const coded = try gzip_of(test_text, &coded_room);
    var corrupt: [test_input_len]u8 = undefined;
    @memcpy(corrupt[0..coded.len], coded);
    // RFC 1952 §2.3.1: the CRC32 in the trailer, one bit off.
    corrupt[coded.len - crc32_offset_from_end] ^= 1;
    try expect_refused(storage, try chunked_message(request_head, corrupt[0..coded.len]), 400);
    // RFC 1950 §2.2: FDICT, a preset dictionary, which stdx refuses.
    try expect_refused(storage, try chunked_message(deflate_request_head, "\x78\xbb\x00\x00\x00\x01"), 501);
    // RFC 1952 §2.3: a body that ends before its stream's trailer.
    try expect_refused(storage, try chunked_message(request_head, coded[0 .. coded.len - 1]), 400);
}

test "decision 91: octets after a deflate stream, inside the body, are a 400" {
    const storage = pool();
    var coded_room: [test_input_len]u8 = undefined;
    const coded = try zlib_of(test_text, &coded_room);
    coded_room[coded.len] = 'x';
    try expect_refused(storage, try chunked_message(deflate_request_head, coded_room[0 .. coded.len + 1]), 400);
}

test "RFC 9112 §7.4: a client with decoders sends TE and reads a gzip response; one without refuses it" {
    const storage = pool();
    test_connection.init(.client, .{ .decoders = storage });
    const written = try test_connection.write_request(&test_output, "GET", "/", host);
    try testing.expectEqualStrings("GET / HTTP/1.1\r\nHost: h\r\nTE: gzip, deflate\r\nConnection: TE\r\n\r\n", test_output[0..written]);
    var coded_room: [test_input_len]u8 = undefined;
    const input = try chunked_message("HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n", try gzip_of(test_text, &coded_room));
    var body: [test_text.len]u8 = undefined;
    const whole = try read_all(&test_connection, input, 11, &body);
    try testing.expectEqualStrings(test_text, whole.body);
    try testing.expect(whole.ended);
    try expect_pool_free(storage);
    test_connection.init(.client, .{});
    const plain = try test_connection.write_request(&test_output, "GET", "/", host);
    try testing.expectEqualStrings("GET / HTTP/1.1\r\nHost: h\r\n\r\n", test_output[0..plain]);
    try testing.expectError(error.ConnectionFailed, test_connection.receive(input, &.{}));
    try testing.expectEqual(error.CodingUndecoded, test_connection.failure.?);
}

test "RFC 9112 §6.3 rule 4: a gzip response that runs until the close ended only if its stream did" {
    const storage = pool();
    var coded_room: [test_input_len]u8 = undefined;
    const coded = try gzip_of(test_text, &coded_room);
    for ([_]bool{ true, false }) |whole_stream| {
        test_connection.init(.client, .{ .decoders = storage });
        _ = try test_connection.write_request(&test_output, "GET", "/", host);
        const head = "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n";
        @memcpy(test_input[0..head.len], head);
        const sent = if (whole_stream) coded else coded[0 .. coded.len - 1];
        @memcpy(test_input[head.len..][0..sent.len], sent);
        var body: [test_text.len]u8 = undefined;
        _ = try read_all(&test_connection, test_input[0 .. head.len + sent.len], test_text.len, &body);
        const closed = test_connection.transport_closed();
        try testing.expectEqual(whole_stream, closed.ended_body);
        try testing.expectEqual(!whole_stream, closed.incomplete);
        try expect_pool_free(storage);
    }
}

test "RFC 9112 §9.3: a server that answers before a coded body ends closes, and gives its decoder back" {
    const storage = pool();
    var coded_room: [test_input_len]u8 = undefined;
    const input = try chunked_message(request_head, try gzip_of(test_text, &coded_room));
    test_connection.init(.server, .{ .decoders = storage });
    const head = try test_connection.receive(input, &.{});
    try testing.expect(head.event.? == .request);
    try testing.expectError(error.DecodersExhausted, expect_pool_free(storage));
    const written = try test_connection.write_response(&test_output, 413, "Content Too Large", &.{.{ .name = "Content-Length", .value = "0" }});
    try testing.expect(written > 0);
    try testing.expect(test_connection.should_close());
    try expect_pool_free(storage);
}
