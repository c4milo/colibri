//! The tests of the client over QUIC (`quic_connection.zig`, `quic_connection_h3.zig`): exchanges
//! go out as h3 request streams to an h3 server over QUIC in the same process, and what it answers
//! comes back as each exchange's outcome.
const std = @import("std");
const h3 = @import("h3");
const support = @import("quic_test_support.zig");
const event = @import("event.zig");

const testing = std.testing;
const connection = &support.connection;
const Exchange = support.Exchange;

const ok: u16 = 200;

/// Where the tests' exchanges put their responses, outside any stack frame. Test-only.
var bodies: [bodies_count][body_len]u8 = undefined;
var values: [values_len]u8 = undefined;
const bodies_count: usize = 2;
const body_len: usize = 1024;
const values_len: usize = 64;

test "RFC 9114 §4.1: a GET goes out on stream 0, and its response fills the exchange" {
    try support.start(&support.alpn_h3, &support.alpn_h3, false);
    var wanted = [_]event.Wanted{.{ .name = "content-type" }};
    var exchange: Exchange = .{ .method = "GET", .path = "/dns-query", .body = &bodies[0], .wanted = &wanted, .values = &values };
    _ = try connection.request(&exchange);
    try support.pump(support.rounds_default);
    try testing.expectEqual(event.Protocol.h3, support.find(.connected).?.connected);
    try testing.expectEqual(.response, exchange.outcome);
    try testing.expectEqual(ok, exchange.status);
    try testing.expectEqualStrings("hello", exchange.content_received());
    try testing.expectEqualStrings("application/dns-message", wanted[0].value.?);
    // RFC 9000 §2.1: the client's first bidirectional stream is 0.
    try testing.expectEqual(0, support.answers[0].id);
    try testing.expectEqualStrings("/dns-query", support.answers[0].path[0..support.answers[0].path_len]);
    _ = h3;
}

/// Content past the server's stream window, so it goes out only as the server grants more (RFC
/// 9000 §4.1). Test-only.
var upload: [upload_len]u8 = undefined;
const upload_len: usize = 600_000;

test "RFC 9000 §4.1: a POST's content goes out whole as the server grants more, and it is answered" {
    try support.start(&support.alpn_h3, &support.alpn_h3, false);
    @memset(&upload, 'x');
    var post: Exchange = .{ .method = "POST", .path = "/upload", .content = &upload, .body = &bodies[0] };
    _ = try connection.request(&post);
    try support.pump(support.rounds_default * 4);
    try testing.expectEqual(upload_len, support.answers[0].received);
    // RFC 9110 §8.6: the client names the content's length; RFC 9114 §4.3.1: over h3, https.
    try testing.expectEqual(upload_len, support.answers[0].content_length.?);
    try testing.expect(support.answers[0].https);
    try testing.expectEqual(.response, post.outcome);
    try testing.expectEqual(upload_len, post.content_sent);
}

test "RFC 9000 §3.1: an answered exchange is not reported while its stream may still send its content" {
    try support.start(&support.alpn_h3, &support.alpn_h3, false);
    support.answer_early = true;
    @memset(&upload, 'y');
    var post: Exchange = .{ .method = "POST", .path = "/upload", .content = &upload, .body = &bodies[0] };
    _ = try connection.request(&post);
    var answered_while_live = false;
    for (0..support.rounds_default * 4) |_| {
        try support.pump(1);
        const live = connection.transport.streams.lookup(.{ .value = 0 }) == .live;
        if (post.status == ok and live) answered_while_live = true;
        // The caller's content is read until the stream closes, so no event frees it sooner.
        if (live) try testing.expectEqual(null, support.find(.finished));
    }
    try testing.expect(answered_while_live);
    try testing.expectEqual(&post, support.find(.finished).?.finished.exchange);
}

test "RFC 9114 §4.1.1: H3_REQUEST_REJECTED ends an exchange refused, and another code ends it reset" {
    try support.start(&support.alpn_h3, &support.alpn_h3, false);
    support.server_answers = false;
    var first: Exchange = .{ .method = "GET", .path = "/a", .body = &bodies[0] };
    var second: Exchange = .{ .method = "GET", .path = "/b", .body = &bodies[1] };
    _ = try connection.request(&first);
    _ = try connection.request(&second);
    try support.pump(support.rounds_default);
    support.server_h3.cancel(&support.server, 0, h3.constants.error_request_rejected);
    support.server_h3.cancel(&support.server, 4, h3.constants.error_internal);
    try support.pump(support.rounds_default);
    try testing.expectEqual(.refused, first.outcome);
    try testing.expectEqual(.reset, second.outcome);
    try testing.expectEqual(h3.constants.error_internal, second.error_code);
}

test "RFC 9114 §5.2: a GOAWAY refuses the exchanges at or past its stream, and the connection drains" {
    try support.start(&support.alpn_h3, &support.alpn_h3, false);
    support.server_answers = false;
    var first: Exchange = .{ .method = "GET", .path = "/a", .body = &bodies[0] };
    _ = try connection.request(&first);
    try support.pump(support.rounds_default);
    // The server took stream 0 alone, so its GOAWAY names stream 4, which the second exchange
    // then opens or would open: the server processes none of it.
    try support.server_h3.shutdown(&support.server);
    var second: Exchange = .{ .method = "GET", .path = "/b", .body = &bodies[1] };
    _ = try connection.request(&second);
    try support.pump(support.rounds_default);
    try testing.expect(support.find(.draining) != null);
    try testing.expectEqual(.refused, second.outcome);
    var third: Exchange = .{ .method = "GET", .path = "/c", .body = &bodies[1] };
    try testing.expectError(error.Draining, connection.request(&third));
    // The exchange the server took is still answered.
    support.server_answers = true;
    try support.pump(support.rounds_default);
    try testing.expectEqual(.response, first.outcome);
}

test "RFC 9114 §4.1: interim responses are counted, and the final one gives the status" {
    try support.start(&support.alpn_h3, &support.alpn_h3, false);
    support.answer_interims = 2;
    var exchange: Exchange = .{ .method = "GET", .path = "/", .body = &bodies[0] };
    _ = try connection.request(&exchange);
    try support.pump(support.rounds_default);
    try testing.expectEqual(2, exchange.interims);
    try testing.expectEqual(ok, exchange.status);
    try testing.expectEqualStrings("hello", exchange.content_received());
}

test "RFC 9114 §4.1.2: content shorter than its content-length is malformed, and ends the exchange so" {
    try support.start(&support.alpn_h3, &support.alpn_h3, false);
    support.answer_malformed = true;
    var exchange: Exchange = .{ .method = "GET", .path = "/", .body = &bodies[0] };
    _ = try connection.request(&exchange);
    try support.pump(support.rounds_default);
    // The content arrived before the stream's end showed its length was wrong, so the outcome,
    // not the content, says what the response was.
    try testing.expectEqual(.malformed, exchange.outcome);
}

test "RFC 9000 §4.6: an exchange past the server's stream limit waits for its MAX_STREAMS" {
    try support.start(&support.alpn_h3, &support.alpn_h3, false);
    support.server_streams_bidi = 1;
    var first: Exchange = .{ .method = "GET", .path = "/a", .body = &bodies[0] };
    var second: Exchange = .{ .method = "GET", .path = "/b", .body = &bodies[1] };
    _ = try connection.request(&first);
    _ = try connection.request(&second);
    try support.pump(support.rounds_default * 2);
    try testing.expectEqual(.response, first.outcome);
    try testing.expectEqual(.response, second.outcome);
    // RFC 9000 §2.1: the second opened stream 4 once the server allowed a second stream.
    try testing.expectEqual(4, support.answers[1].id);
}
