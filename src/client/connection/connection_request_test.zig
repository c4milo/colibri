//! The tests of what `Connection` decides for either protocol (`connection.zig`): the exchanges
//! `request` refuses, the order of the events, a cancel before anything was written, and what the
//! transport's close leaves each exchange.
const std = @import("std");
const h2 = @import("h2");
const support = @import("connection_test_support.zig");
const event = @import("../event.zig");

const testing = std.testing;
const connection = &support.connection;
const HttpExchange = support.HttpExchange;
const Field = support.Field;

const ok: u16 = 200;
const empty_fields = [_]Field{.{ .name = "Content-Length", .value = "0" }};

/// Where the tests' exchanges put their responses, outside any stack frame. Test-only.
var bodies: [bodies_count][body_len]u8 = undefined;
const bodies_count: usize = 2;
const body_len: usize = 64;

test "RFC 9113 §8.2.2: a request naming a field the client writes, or a connection-specific one, is refused" {
    try support.start_cleartext(.h2);
    const names = [_][]const u8{ "Host", "content-length", "Connection", "Keep-Alive", "Proxy-Connection", "Transfer-Encoding", "Upgrade" };
    for (names) |name| {
        const fields = [_]Field{.{ .name = name, .value = "x" }};
        var exchange: HttpExchange = .{ .method = "GET", .path = "/", .fields = &fields };
        try testing.expectError(error.FieldReserved, connection.request(&exchange));
    }
    // A field the client does not write goes out as the caller named it.
    const accept = [_]Field{.{ .name = "accept", .value = "application/dns-message" }};
    var exchange: HttpExchange = .{ .method = "GET", .path = "/", .fields = &accept };
    _ = try connection.request(&exchange);
}

test "RFC 9110 §9.3.6: CONNECT, an empty method and an empty path are refused" {
    try support.start_cleartext(.h11);
    var connect: HttpExchange = .{ .method = "CONNECT", .path = "example.com:443" };
    try testing.expectError(error.RequestUnsupported, connection.request(&connect));
    var no_method: HttpExchange = .{ .method = "", .path = "/" };
    try testing.expectError(error.RequestUnsupported, connection.request(&no_method));
    var no_path: HttpExchange = .{ .method = "GET", .path = "" };
    try testing.expectError(error.RequestUnsupported, connection.request(&no_path));
}

test "every slot taken refuses the next request, until a finished event frees one" {
    try support.start_cleartext(.h11);
    var exchanges: [support.events_max]HttpExchange = @splat(.{ .method = "GET", .path = "/" });
    for (exchanges[0..@import("../constants.zig").exchanges_max]) |*exchange| _ = try connection.request(exchange);
    try testing.expectError(error.Full, connection.request(&exchanges[support.events_max - 1]));
}

test "the connected event comes first, and a finished one after it" {
    try support.start_cleartext(.h11);
    var exchange: HttpExchange = .{ .method = "GET", .path = "/", .body = &bodies[0] };
    _ = try connection.request(&exchange);
    support.client_send();
    try support.peer_h11_read();
    try support.peer_h11_answer(ok, &empty_fields, "");
    try support.client_receive();
    try testing.expect(support.events_len >= 2);
    try testing.expectEqual(.connected, std.meta.activeTag(support.events[0]));
    try testing.expectEqual(.finished, std.meta.activeTag(support.events[1]));
}

test "the connected event comes first, even before an exchange that ended as it was written" {
    try support.start_cleartext(.h11);
    // RFC 9110 §9.1: a method is a token, which a space breaks, so h11 refuses to write it.
    var bad: HttpExchange = .{ .method = "G ET", .path = "/", .body = &bodies[0] };
    _ = try connection.request(&bad);
    support.client_send();
    try testing.expectEqual(.invalid, bad.outcome);
    try support.client_receive();
    try testing.expectEqual(.connected, std.meta.activeTag(support.events[0]));
    try testing.expectEqual(.finished, std.meta.activeTag(support.events[1]));
}

test "a cancel before the exchange is written drops it, and reports nothing" {
    try support.start_cleartext(.h11);
    var cancelled: HttpExchange = .{ .method = "GET", .path = "/cancelled", .body = &bodies[0] };
    var kept: HttpExchange = .{ .method = "GET", .path = "/kept", .body = &bodies[1] };
    const id = try connection.request(&cancelled);
    _ = try connection.request(&kept);
    connection.cancel(id);
    support.client_send();
    const sent = support.to_peer[0..support.to_peer_len];
    try testing.expect(std.mem.indexOf(u8, sent, "/cancelled") == null);
    try testing.expect(std.mem.indexOf(u8, sent, "GET /kept") != null);
    try support.peer_h11_read();
    try support.peer_h11_answer(ok, &empty_fields, "");
    try support.client_receive();
    try testing.expectEqual(1, support.count(.finished));
    try testing.expectEqual(&kept, support.find(.finished).?.finished.exchange);
}

test "RFC 9112 §9.3.1: the transport's close ends a written exchange closed and a waiting one refused" {
    try support.start_cleartext(.h11);
    var post: HttpExchange = .{ .method = "POST", .path = "/", .content = "query", .body = &bodies[0] };
    var waiting: HttpExchange = .{ .method = "GET", .path = "/", .body = &bodies[1] };
    _ = try connection.request(&post);
    _ = try connection.request(&waiting);
    // Decision 88: the GET waits for the POST's response, which never comes.
    support.client_send();
    connection.transport_closed();
    try support.client_receive();
    try testing.expectEqual(.closed, post.outcome);
    try testing.expectEqual(.refused, waiting.outcome);
    try testing.expect(support.find(.closed) != null);
    try testing.expect(connection.should_close());
    // A second close changes nothing.
    connection.transport_closed();
    try testing.expect(connection.should_close());
}

test "RFC 9110 §8.6: h2 names the content's length, and a GET's none" {
    try support.start_cleartext(.h2);
    support.peer_events_len = 0;
    var post: HttpExchange = .{ .method = "POST", .path = "/", .content = "query", .body = &bodies[0] };
    var get: HttpExchange = .{ .method = "GET", .path = "/", .body = &bodies[1] };
    _ = try connection.request(&post);
    _ = try connection.request(&get);
    try support.pump_h2();
    var lengths: [bodies_count]?u64 = @splat(null);
    var seen: usize = 0;
    for (support.peer_events[0..support.peer_events_len]) |peer_event| {
        if (peer_event != .request) continue;
        lengths[seen] = peer_event.request.request.content_length;
        seen += 1;
    }
    try testing.expectEqual(bodies_count, seen);
    try testing.expectEqual(5, lengths[0].?);
    try testing.expectEqual(null, lengths[1]);
    _ = h2;
    _ = event;
}
