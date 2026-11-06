//! The tests of a streamed request body on a TCP connection (decision 153, design §8 step 39e):
//! the pieces go out over h11, chunked or with the length the request states, in cleartext and
//! over TLS, and over h2 in DATA frames with END_STREAM on the last piece alone. Each piece's
//! `body_taken` event comes once the piece went out, and the server reads the body whole.
const std = @import("std");
const support = @import("connection_test_support.zig");
const tls_support = @import("connection_tls_test_support.zig");

const testing = std.testing;
const connection = &support.connection;
const Exchange = support.Exchange;

var body: [body_len]u8 = undefined;
const body_len: usize = 1024;
const ok: u16 = 200;
/// RFC 9110 §8.6: a response that states it has no content, which ends with its head.
const empty_length: []const support.Header = &.{.{ .name = "Content-Length", .value = "0" }};

/// Three pieces: the second is 26 octets, whose chunk size reads differently in hex and in
/// decimal, and the whole body. Test-only.
const first = "hello";
const second = "abcdefghijklmnopqrstuvwxyz";
const third = "!";
const pieces = [_][]const u8{ first, second, third };
const whole = first ++ second ++ third;
/// RFC 9112 §7.1: each piece as one chunk, then the last chunk and an empty trailer section.
const chunked_whole = "5\r\nhello\r\n1a\r\nabcdefghijklmnopqrstuvwxyz\r\n1\r\n!\r\n0\r\n\r\n";
/// The end of a request head (RFC 9112 §2.1).
const head_end = "\r\n\r\n";

/// What the server read of a request's body, and how many times the body ended. Test-only.
var read_body: [body_len]u8 = undefined;
var read_len: usize = 0;
var read_ends: usize = 0;

/// A streamed POST, with `request_len` stated or none.
fn streamed_post(request_len: ?u64) Exchange {
    return .{ .request = .{ .method = "POST", .path = "/upload", .streamed = .{ .request = true, .request_len = request_len } }, .response = .{ .body = &body } };
}

/// Hands each piece in turn, the last one ending the body, and sends what the connection owes
/// after each. Each piece's `body_taken` event comes before the next is handed.
fn send_pieces(id: u64, receive: bool) !void {
    for (pieces, 1..) |piece, handed| {
        try connection.write_body(id, piece, handed == pieces.len);
        support.client_send();
        if (receive) try support.client_receive();
        try testing.expectEqual(handed, support.count(.body_taken));
        try testing.expectEqual(id, support.find(.body_taken).?.body_taken);
    }
}

/// The h11 server reads the request in `octets`, and keeps its body.
fn h11_server_read(octets: []const u8) !void {
    read_len = 0;
    read_ends = 0;
    var consumed: usize = 0;
    // Bounded: each pass consumes an octet or reports an event, and both are finite.
    for (0..octets.len + support.events_max) |_| {
        const received = try support.peer_h11.receive(octets[consumed..], &.{});
        consumed += received.consumed;
        switch (received.event orelse break) {
            .request => {},
            .data => |data| {
                @memcpy(read_body[read_len..][0..data.len], data);
                read_len += data.len;
            },
            .end => read_ends += 1,
            .interim, .response, .tunnel => return error.TestUnexpectedResult,
        }
    }
    try testing.expectEqual(octets.len, consumed);
}

/// The octets after the request head in what the client sent.
fn after_head(octets: []const u8) []const u8 {
    const end = std.mem.indexOf(u8, octets, head_end).?;
    return octets[end + head_end.len ..];
}

test "RFC 9112 §7.1: a streamed request that states no length goes out chunked, a piece a chunk, with no copy" {
    try support.start_cleartext(.h11);
    var post = streamed_post(null);
    const id = try connection.request(&post.request, &post.response);
    support.client_send();
    try send_pieces(id, true);
    const sent = support.to_peer[0..support.to_peer_len];
    try testing.expect(std.mem.indexOf(u8, sent, "Transfer-Encoding: chunked\r\n") != null);
    try testing.expectEqual(null, std.mem.indexOf(u8, sent, "Content-Length"));
    try testing.expectEqualStrings(chunked_whole, after_head(sent));
    try h11_server_read(sent);
    try testing.expectEqualStrings(whole, read_body[0..read_len]);
    try testing.expectEqual(1, read_ends);
    try testing.expectEqual(whole.len, post.response.body_sent);
    // The server answers, and the exchange ends whole.
    try support.peer_h11_answer(ok, empty_length, "");
    try support.client_receive();
    try testing.expectEqual(.response, post.response.result);
}

test "RFC 9110 §8.6: a streamed request that states its length sends Content-Length and no chunk" {
    try support.start_cleartext(.h11);
    var post = streamed_post(whole.len);
    const id = try connection.request(&post.request, &post.response);
    support.client_send();
    try send_pieces(id, true);
    const sent = support.to_peer[0..support.to_peer_len];
    try testing.expect(std.mem.indexOf(u8, sent, "Content-Length: 32\r\n") != null);
    try testing.expectEqual(null, std.mem.indexOf(u8, sent, "Transfer-Encoding"));
    try testing.expectEqualStrings(whole, after_head(sent));
    try h11_server_read(sent);
    try testing.expectEqualStrings(whole, read_body[0..read_len]);
    try testing.expectEqual(1, read_ends);
}

test "decision 153: a piece handed before the head goes out after it, and the next waits for its take" {
    try support.start_cleartext(.h11);
    var post = streamed_post(null);
    const id = try connection.request(&post.request, &post.response);
    // Nothing goes out of the body until a piece is handed, and the connection owes no octet.
    support.client_send();
    try testing.expect(!connection.owes_octets());
    const head_len = support.to_peer_len;
    try connection.write_body(id, pieces[0], false);
    try testing.expect(connection.owes_octets());
    support.client_send();
    try testing.expect(support.to_peer_len > head_len);
    try support.client_receive();
    try testing.expectEqual(1, support.count(.body_taken));
    // An empty piece that does not end the body is taken with nothing written.
    const before_empty = support.to_peer_len;
    try connection.write_body(id, "", false);
    support.client_send();
    try support.client_receive();
    try testing.expectEqual(2, support.count(.body_taken));
    try testing.expectEqual(before_empty, support.to_peer_len);
    // An empty last piece writes the last chunk alone.
    try connection.write_body(id, "", true);
    support.client_send();
    try support.client_receive();
    try testing.expectEqual(3, support.count(.body_taken));
    try h11_server_read(support.to_peer[0..support.to_peer_len]);
    try testing.expectEqualStrings(pieces[0], read_body[0..read_len]);
    try testing.expectEqual(1, read_ends);
}

test "RFC 9112 §9.5: a final response that ends while a streamed body is open fails the connection" {
    try support.start_cleartext(.h11);
    var post = streamed_post(null);
    const id = try connection.request(&post.request, &post.response);
    try connection.write_body(id, pieces[0], false);
    support.client_send();
    try support.client_receive();
    // Decision 124 ruling 2: the response ends before the body does.
    try h11_server_read(support.to_peer[0..support.to_peer_len]);
    try support.peer_h11_answer(ok, empty_length, "");
    try support.client_receive();
    // The response arrived whole, and the rest of the body is not written.
    try testing.expectEqual(.response, post.response.result);
    try testing.expectEqual(pieces[0].len, post.response.body_sent);
    try testing.expect(connection.failed);
}

test "decision 139: streamed pieces go out over TLS chunked, and the server opens the body whole" {
    try tls_support.prepare_tls(&support.protocols_h11, &support.protocols_h11, "localhost", false);
    try tls_support.run_handshake();
    try tls_support.server_open();
    tls_support.peer_plain_len = 0;
    support.peer_h11.init(.server, .{});
    var post = streamed_post(null);
    const id = try connection.request(&post.request, &post.response);
    support.client_send();
    try send_pieces(id, true);
    try tls_support.server_open();
    const opened = tls_support.peer_plain[0..tls_support.peer_plain_len];
    try testing.expectEqualStrings(chunked_whole, after_head(opened));
    try h11_server_read(opened);
    try testing.expectEqualStrings(whole, read_body[0..read_len]);
    try testing.expectEqual(1, read_ends);
}

/// The h2 server reads every whole frame the client sent, keeps the request's body, and counts
/// the frames that ended the stream.
fn h2_server_read() !void {
    var consumed: usize = 0;
    // Bounded: each pass consumes an octet or writes what the server owes, and both are finite.
    for (0..support.to_peer_len + support.events_max) |_| {
        const received = try support.peer_h2.receive(support.to_peer[consumed..support.to_peer_len], support.now_ns);
        if (received.consumed == 0) {
            if (!support.peer_h2.has_pending()) break;
            support.peer_h2_owe();
            continue;
        }
        consumed += received.consumed;
        const data = switch (received.event orelse continue) {
            .data => |data| data,
            .request => |request| {
                read_ends += @intFromBool(request.end_stream);
                continue;
            },
            else => continue,
        };
        @memcpy(read_body[read_len..][0..data.payload.len], data.payload);
        read_len += data.payload.len;
        read_ends += @intFromBool(data.end_stream);
    }
    support.to_peer_len = 0;
    support.peer_h2_owe();
}

test "RFC 9113 §8.1: streamed pieces go out in DATA frames, and END_STREAM goes on the last piece alone" {
    try support.start_cleartext(.h2);
    try support.pump_h2();
    read_len = 0;
    read_ends = 0;
    var post = streamed_post(null);
    const id = try connection.request(&post.request, &post.response);
    support.client_send();
    for (pieces, 1..) |piece, handed| {
        try connection.write_body(id, piece, handed == pieces.len);
        support.client_send();
        try h2_server_read();
        try support.client_receive();
        try testing.expectEqual(handed, support.count(.body_taken));
        // RFC 9113 §6.1: the stream ends with the last piece, and with no piece before it.
        try testing.expectEqual(@intFromBool(handed == pieces.len), read_ends);
    }
    try testing.expectEqualStrings(whole, read_body[0..read_len]);
    try support.peer_h2_answer(1, ok, &.{}, "");
    try support.client_receive();
    try testing.expectEqual(.response, post.response.result);
    try testing.expectEqual(whole.len, post.response.body_sent);
}

test "RFC 9113 §8.1: a streamed request whose only piece is an empty last one ends its stream with its HEADERS frame" {
    try support.start_cleartext(.h2);
    try support.pump_h2();
    read_len = 0;
    read_ends = 0;
    var post = streamed_post(null);
    const id = try connection.request(&post.request, &post.response);
    try connection.write_body(id, "", true);
    support.client_send();
    try h2_server_read();
    try support.client_receive();
    try testing.expectEqual(1, read_ends);
    try testing.expectEqual(0, read_len);
    try testing.expectEqual(1, support.count(.body_taken));
}
