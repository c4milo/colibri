//! The tests of the client's h11 half (`connection_h11.zig`) over cleartext: exchanges go out in
//! order to h11's server side in the same process, and each response comes back as the outcome of
//! the oldest exchange awaiting one (RFC 9112 §9.2).
const std = @import("std");
const support = @import("connection_test_support.zig");
const event = @import("../event.zig");

const testing = std.testing;
const connection = &support.connection;
const HttpExchange = support.HttpExchange;
const Field = support.Field;

const ok: u16 = 200;
/// RFC 9110 §15.2.4: 103 Early Hints, an interim response.
const early_hints: u16 = 103;
const hello_fields = [_]Field{.{ .name = "Content-Length", .value = "5" }};
const empty_fields = [_]Field{.{ .name = "Content-Length", .value = "0" }};

/// Where the tests' exchanges put their responses, outside any stack frame. Test-only.
var bodies: [bodies_count][body_len]u8 = undefined;
var values: [values_len]u8 = undefined;
const bodies_count: usize = 3;
const body_len: usize = 1024;
const values_len: usize = 64;
var upload: [support.buffer_len]u8 = undefined;

fn get(body: []u8) HttpExchange {
    return .{ .method = "GET", .path = "/dns-query", .body = body };
}

fn start() !void {
    try support.start_cleartext(.h11);
    support.peer_requests = 0;
}

/// Whether the octets the client sent and the peer has not read hold `text`. Test-only.
fn sent(text: []const u8) bool {
    return std.mem.indexOf(u8, support.to_peer[0..support.to_peer_len], text) != null;
}

test "RFC 9114 §3.1.2: a cleartext response's Alt-Svc names nothing, since h3 serves no http origin" {
    try start();
    var exchange = get(&bodies[0]);
    _ = try connection.request(&exchange);
    support.client_send();
    try support.peer_h11_read();
    const fields = [_]Field{ .{ .name = "Content-Length", .value = "5" }, .{ .name = "Alt-Svc", .value = "h3=\":443\"" } };
    try support.peer_h11_answer(ok, &fields, "hello");
    try support.client_receive();
    try testing.expectEqual(.response, exchange.outcome);
    try testing.expectEqual(null, connection.take_alt_svc());
}

test "RFC 9112 §3.2: a GET goes out with Host first, and its response fills the exchange" {
    try start();
    var wanted = [_]event.Wanted{.{ .name = "content-length" }};
    var exchange = get(&bodies[0]);
    exchange.wanted = &wanted;
    exchange.values = &values;
    try testing.expectEqual(1, try connection.request(&exchange));
    support.client_send();
    // RFC 9110 §7.2: a user agent sends Host first; RFC 9110 §8.6: a GET with no content sends
    // no Content-Length.
    try testing.expect(sent("GET /dns-query HTTP/1.1\r\nHost: localhost\r\n\r\n"));
    try support.peer_h11_read();
    try testing.expectEqual(1, support.peer_requests);
    try support.peer_h11_answer(ok, &hello_fields, "hello");
    try support.client_receive();
    try testing.expectEqual(event.Protocol.h11, support.find(.connected).?.connected);
    try testing.expectEqual(1, support.find(.finished).?.finished.id);
    try testing.expectEqual(ok, exchange.status);
    try testing.expectEqualStrings("hello", exchange.content_received());
    try testing.expectEqualStrings("5", wanted[0].value.?);
}

test "decision 88: a POST's content goes out whole, and the GET after it waits for its response" {
    try start();
    var post: HttpExchange = .{ .method = "POST", .path = "/upload", .content = "query", .body = &bodies[0] };
    var after = get(&bodies[1]);
    _ = try connection.request(&post);
    _ = try connection.request(&after);
    support.client_send();
    try testing.expect(sent("Content-Length: 5\r\n\r\nquery"));
    // RFC 9112 §9.3.2: no request is pipelined after one that is not idempotent.
    try testing.expect(!sent("GET"));
    try support.peer_h11_read();
    try support.peer_h11_answer(ok, &empty_fields, "");
    try support.client_receive();
    try testing.expectEqual(.response, post.outcome);
    support.client_send();
    try testing.expect(sent("GET /dns-query"));
    try support.peer_h11_read();
    try support.peer_h11_answer(ok, &hello_fields, "hello");
    try support.client_receive();
    try testing.expectEqual(.response, after.outcome);
    try testing.expectEqual(2, support.peer_requests);
}

test "RFC 9110 §8.6: a POST without content sends Content-Length 0" {
    try start();
    var post: HttpExchange = .{ .method = "POST", .path = "/", .body = &bodies[0] };
    _ = try connection.request(&post);
    support.client_send();
    try testing.expect(sent("Content-Length: 0\r\n\r\n"));
}

test "RFC 9110 §15.2: interim responses are counted, and the final one gives the status" {
    try start();
    var exchange = get(&bodies[0]);
    _ = try connection.request(&exchange);
    support.client_send();
    try support.peer_h11_read();
    support.to_client_len += try support.peer_h11.write_response(support.to_client[support.to_client_len..], early_hints, "", &.{});
    try support.peer_h11_answer(ok, &empty_fields, "");
    try support.client_receive();
    try testing.expectEqual(1, exchange.interims);
    try testing.expectEqual(ok, exchange.status);
}

test "RFC 9112 §9.2: content past the caller's memory is dropped, and the next response still arrives" {
    try start();
    var small = get(bodies[0][0..2]);
    var next = get(&bodies[1]);
    _ = try connection.request(&small);
    _ = try connection.request(&next);
    support.client_send();
    try support.peer_h11_read();
    try support.peer_h11_answer(ok, &hello_fields, "hello");
    try support.peer_h11_read();
    try support.peer_h11_answer(ok, &hello_fields, "world");
    try support.client_receive();
    try testing.expectEqual(.too_large, small.outcome);
    try testing.expectEqual(.response, next.outcome);
    try testing.expectEqualStrings("world", next.content_received());
    try testing.expectEqual(null, support.find(.closed));
}

test "RFC 9112 §9.2: a cancelled exchange's response is read and dropped, and reports nothing" {
    try start();
    var cancelled = get(&bodies[0]);
    var next = get(&bodies[1]);
    const id = try connection.request(&cancelled);
    _ = try connection.request(&next);
    support.client_send();
    connection.cancel(id);
    try support.peer_h11_read();
    try support.peer_h11_answer(ok, &hello_fields, "hello");
    try support.peer_h11_read();
    try support.peer_h11_answer(ok, &hello_fields, "world");
    try support.client_receive();
    try testing.expectEqual(1, support.count(.finished));
    try testing.expectEqual(.pending, cancelled.outcome);
    try testing.expectEqualStrings("world", next.content_received());
}

test "RFC 9112 §9.6: a response that closes refuses the exchange waiting, and the connection ends" {
    try start();
    var post: HttpExchange = .{ .method = "POST", .path = "/", .content = "query", .body = &bodies[0] };
    var waiting = get(&bodies[1]);
    _ = try connection.request(&post);
    _ = try connection.request(&waiting);
    support.client_send();
    try support.peer_h11_read();
    try support.peer_h11_answer(ok, &.{ .{ .name = "Content-Length", .value = "0" }, .{ .name = "Connection", .value = "close" } }, "");
    try support.client_receive();
    try testing.expectEqual(.response, post.outcome);
    // RFC 9112 §9.6: the server never saw the request that waited, so it may go elsewhere.
    try testing.expectEqual(.refused, waiting.outcome);
    try testing.expect(support.find(.draining) != null and support.find(.closed) != null);
    try testing.expect(connection.should_close());
    var third = get(&bodies[2]);
    try testing.expectError(error.ConnectionClosed, connection.request(&third));
}

test "RFC 9112 §6.3: a body that runs until the close ends with it, and one cut short does not" {
    try start();
    var exchange = get(&bodies[0]);
    _ = try connection.request(&exchange);
    support.client_send();
    // RFC 9112 §6.3 rule 8: a response with neither Content-Length nor chunked ends at the close.
    const response = "HTTP/1.1 200 OK\r\n\r\nhello";
    @memcpy(support.to_client[0..response.len], response);
    support.to_client_len = response.len;
    try support.client_receive();
    connection.transport_closed();
    try support.client_receive();
    try testing.expectEqual(.response, exchange.outcome);
    try testing.expectEqualStrings("hello", exchange.content_received());
    try start();
    _ = try connection.request(&exchange);
    support.client_send();
    // RFC 9112 §8: a response the close cuts short is incomplete.
    const cut = "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhel";
    @memcpy(support.to_client[0..cut.len], cut);
    support.to_client_len = cut.len;
    try support.client_receive();
    connection.transport_closed();
    try support.client_receive();
    try testing.expectEqual(.closed, exchange.outcome);
}

test "RFC 9112 §8: a malformed response ends its exchange malformed, and the connection" {
    try start();
    var exchange = get(&bodies[0]);
    var next = get(&bodies[1]);
    _ = try connection.request(&exchange);
    _ = try connection.request(&next);
    support.client_send();
    // RFC 9110 §15: 999 is no status code.
    const response = "HTTP/1.1 999 X\r\n\r\n";
    @memcpy(support.to_client[0..response.len], response);
    support.to_client_len = response.len;
    try support.client_receive();
    try testing.expectEqual(.malformed, exchange.outcome);
    try testing.expectEqual(.closed, next.outcome);
    try testing.expect(support.find(.closed) != null);
}

test "RFC 9112 §6.2: a cancel while the content is going out ends the connection" {
    try start();
    @memset(&upload, 'x');
    var post: HttpExchange = .{ .method = "POST", .path = "/", .content = &upload, .body = &bodies[0] };
    const id = try connection.request(&post);
    support.client_send();
    // The output holds less than the content, so some of it is still to go.
    try testing.expect(support.to_peer_len < upload.len);
    connection.cancel(id);
    try support.client_receive();
    try testing.expectEqual(0, support.count(.finished));
    try testing.expect(support.find(.closed) != null);
}
