//! The tests of the client's h11 half (`connection_h11.zig`) over cleartext: exchanges go out in
//! order to h11's server side in the same process, and each response comes back as the outcome of
//! the oldest exchange awaiting one (RFC 9112 §9.2).
const std = @import("std");
const support = @import("connection_test_support.zig");
const event = @import("../event.zig");

const testing = std.testing;
const connection = &support.connection;
const Exchange = support.Exchange;
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

fn get(body: []u8) Exchange {
    return .{ .request = .{ .method = "GET", .path = "/dns-query" }, .response = .{ .body = body } };
}

fn start() !void {
    try support.start_cleartext(.h11);
    support.peer_requests = 0;
}

/// Whether the octets the client sent and the peer has not read hold `text`. Test-only.
fn sent(text: []const u8) bool {
    return std.mem.indexOf(u8, support.to_peer[0..support.to_peer_len], text) != null;
}

/// Passes the client `octets` in one call, as a caller that read them from its socket.
fn give(octets: []const u8) event.Received {
    @memcpy(support.to_client[0..octets.len], octets);
    return connection.receive(support.to_client[0..octets.len], support.now_ns);
}

/// A call with no octets, as the channel makes to read what the connection owes, reads nothing.
fn expect_nothing() !void {
    const polled = give("");
    try testing.expectEqual(0, polled.consumed);
    try testing.expectEqual(null, polled.event);
}

test "design §8 step 21c.3: a call with no octets waits for half a head or chunk-size line" {
    try start();
    var exchange = get(&bodies[0]);
    _ = try connection.request(&exchange.request, &exchange.response);
    support.client_send();
    // The connection reports `connected` before it reads an octet.
    try support.client_receive();
    // h11 reads half a head again from its first octet, once the caller passes it with the rest.
    const head = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
    const half = give(head[0.."HTTP/1.1 2".len]);
    try testing.expectEqual(0, half.consumed);
    try testing.expectEqual(null, half.event);
    try expect_nothing();
    const whole = give(head);
    try testing.expectEqual(head.len, whole.consumed);
    try testing.expectEqual(null, whole.event);
    // A chunk-size line is read the same way (RFC 9112 §7.1).
    const size_line = give("5");
    try testing.expectEqual(0, size_line.consumed);
    try expect_nothing();
    const body = give("5\r\nhello\r\n0\r\n\r\n");
    try testing.expectEqual(1, body.event.?.finished.id);
    try testing.expectEqual(.response, exchange.response.outcome);
    try testing.expectEqualStrings("hello", exchange.response.content_received());
}

test "RFC 9114 §3.1.2: a cleartext response's Alt-Svc names nothing, since h3 serves no http origin" {
    try start();
    var exchange = get(&bodies[0]);
    _ = try connection.request(&exchange.request, &exchange.response);
    support.client_send();
    try support.peer_h11_read();
    const fields = [_]Field{ .{ .name = "Content-Length", .value = "5" }, .{ .name = "Alt-Svc", .value = "h3=\":443\"" } };
    try support.peer_h11_answer(ok, &fields, "hello");
    try support.client_receive();
    try testing.expectEqual(.response, exchange.response.outcome);
    try testing.expectEqual(null, connection.take_alt_svc());
}

test "RFC 9112 §3.2: a GET goes out with Host first, and its response fills the exchange" {
    try start();
    var wanted = [_]event.Wanted{.{ .name = "content-length" }};
    var exchange = get(&bodies[0]);
    exchange.response.wanted = &wanted;
    exchange.response.values = &values;
    try testing.expectEqual(1, try connection.request(&exchange.request, &exchange.response));
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
    try testing.expectEqual(ok, exchange.response.status);
    try testing.expectEqualStrings("hello", exchange.response.content_received());
    try testing.expectEqualStrings("5", wanted[0].value.?);
}

test "decision 88: a POST's content goes out whole, and the GET after it waits for its response" {
    try start();
    var post: Exchange = .{ .request = .{ .method = "POST", .path = "/upload", .content = "query" }, .response = .{ .body = &bodies[0] } };
    var after = get(&bodies[1]);
    _ = try connection.request(&post.request, &post.response);
    _ = try connection.request(&after.request, &after.response);
    support.client_send();
    try testing.expect(sent("Content-Length: 5\r\n\r\nquery"));
    // RFC 9112 §9.3.2: no request is pipelined after one that is not idempotent.
    try testing.expect(!sent("GET"));
    try support.peer_h11_read();
    try support.peer_h11_answer(ok, &empty_fields, "");
    try support.client_receive();
    try testing.expectEqual(.response, post.response.outcome);
    support.client_send();
    try testing.expect(sent("GET /dns-query"));
    try support.peer_h11_read();
    try support.peer_h11_answer(ok, &hello_fields, "hello");
    try support.client_receive();
    try testing.expectEqual(.response, after.response.outcome);
    try testing.expectEqual(2, support.peer_requests);
}

test "RFC 9110 §8.6: a POST without content sends Content-Length 0" {
    try start();
    var post: Exchange = .{ .request = .{ .method = "POST", .path = "/" }, .response = .{ .body = &bodies[0] } };
    _ = try connection.request(&post.request, &post.response);
    support.client_send();
    try testing.expect(sent("Content-Length: 0\r\n\r\n"));
}

test "RFC 9110 §15.2: interim responses are counted, and the final one gives the status" {
    try start();
    var exchange = get(&bodies[0]);
    _ = try connection.request(&exchange.request, &exchange.response);
    support.client_send();
    try support.peer_h11_read();
    support.to_client_len += try support.peer_h11.write_response(support.to_client[support.to_client_len..], early_hints, "", &.{});
    try support.peer_h11_answer(ok, &empty_fields, "");
    try support.client_receive();
    try testing.expectEqual(1, exchange.response.interims);
    try testing.expectEqual(ok, exchange.response.status);
}

test "RFC 9112 §9.2: content past the caller's memory is dropped, and the next response still arrives" {
    try start();
    var small = get(bodies[0][0..2]);
    var next = get(&bodies[1]);
    _ = try connection.request(&small.request, &small.response);
    _ = try connection.request(&next.request, &next.response);
    support.client_send();
    try support.peer_h11_read();
    try support.peer_h11_answer(ok, &hello_fields, "hello");
    try support.peer_h11_read();
    try support.peer_h11_answer(ok, &hello_fields, "world");
    try support.client_receive();
    try testing.expectEqual(.too_large, small.response.outcome);
    try testing.expectEqual(.response, next.response.outcome);
    try testing.expectEqualStrings("world", next.response.content_received());
    try testing.expectEqual(null, support.find(.closed));
}

test "RFC 9112 §9.2: a cancelled exchange's response is read and dropped, and reports nothing" {
    try start();
    var cancelled = get(&bodies[0]);
    var next = get(&bodies[1]);
    const id = try connection.request(&cancelled.request, &cancelled.response);
    _ = try connection.request(&next.request, &next.response);
    support.client_send();
    connection.cancel(id);
    try support.peer_h11_read();
    try support.peer_h11_answer(ok, &hello_fields, "hello");
    try support.peer_h11_read();
    try support.peer_h11_answer(ok, &hello_fields, "world");
    try support.client_receive();
    try testing.expectEqual(1, support.count(.finished));
    try testing.expectEqual(.pending, cancelled.response.outcome);
    try testing.expectEqualStrings("world", next.response.content_received());
}

test "RFC 9112 §9.6: a response that closes refuses the exchange waiting, and the connection ends" {
    try start();
    var post: Exchange = .{ .request = .{ .method = "POST", .path = "/", .content = "query" }, .response = .{ .body = &bodies[0] } };
    var waiting = get(&bodies[1]);
    _ = try connection.request(&post.request, &post.response);
    _ = try connection.request(&waiting.request, &waiting.response);
    support.client_send();
    try support.peer_h11_read();
    try support.peer_h11_answer(ok, &.{ .{ .name = "Content-Length", .value = "0" }, .{ .name = "Connection", .value = "close" } }, "");
    try support.client_receive();
    try testing.expectEqual(.response, post.response.outcome);
    // RFC 9112 §9.6: the server never saw the request that waited, so it may go elsewhere.
    try testing.expectEqual(.refused, waiting.response.outcome);
    try testing.expect(support.find(.draining) != null and support.find(.closed) != null);
    try testing.expect(connection.should_close());
    var third = get(&bodies[2]);
    try testing.expectError(error.ConnectionClosed, connection.request(&third.request, &third.response));
}

test "RFC 9112 §6.3: a body that runs until the close ends with it, and one cut short does not" {
    try start();
    var exchange = get(&bodies[0]);
    _ = try connection.request(&exchange.request, &exchange.response);
    support.client_send();
    // RFC 9112 §6.3 rule 8: a response with neither Content-Length nor chunked ends at the close.
    const response = "HTTP/1.1 200 OK\r\n\r\nhello";
    @memcpy(support.to_client[0..response.len], response);
    support.to_client_len = response.len;
    try support.client_receive();
    connection.transport_closed();
    try support.client_receive();
    try testing.expectEqual(.response, exchange.response.outcome);
    try testing.expectEqualStrings("hello", exchange.response.content_received());
    try start();
    _ = try connection.request(&exchange.request, &exchange.response);
    support.client_send();
    // RFC 9112 §8: a response the close cuts short is incomplete.
    const cut = "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhel";
    @memcpy(support.to_client[0..cut.len], cut);
    support.to_client_len = cut.len;
    try support.client_receive();
    connection.transport_closed();
    try support.client_receive();
    try testing.expectEqual(.closed, exchange.response.outcome);
}

test "RFC 9112 §8: a malformed response ends its exchange malformed, and the connection" {
    try start();
    var exchange = get(&bodies[0]);
    var next = get(&bodies[1]);
    _ = try connection.request(&exchange.request, &exchange.response);
    _ = try connection.request(&next.request, &next.response);
    support.client_send();
    // RFC 9110 §15: 999 is no status code.
    const response = "HTTP/1.1 999 X\r\n\r\n";
    @memcpy(support.to_client[0..response.len], response);
    support.to_client_len = response.len;
    try support.client_receive();
    try testing.expectEqual(.malformed, exchange.response.outcome);
    try testing.expectEqual(.closed, next.response.outcome);
    try testing.expect(support.find(.closed) != null);
}

/// RFC 9110 §15.5.13: 412 Precondition Failed, which a server may send before it reads the
/// content. The connection stays open, since it names no close option (RFC 9112 §9.6).
const precondition_failed: u16 = 412;
const early_response = "HTTP/1.1 412 Precondition Failed\r\nContent-Length: 0\r\n\r\n";
const ok_response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";

/// The peer writes `octets` itself, and the client reads them. Test-only.
fn peer_writes(octets: []const u8) !void {
    @memcpy(support.to_client[support.to_client_len..][0..octets.len], octets);
    support.to_client_len += octets.len;
    try support.client_receive();
}

/// A PUT of `upload`, which the output of one `send` does not hold. Test-only.
fn put_upload(body: []u8) Exchange {
    @memset(&upload, 'x');
    return .{ .request = .{ .method = "PUT", .path = "/object", .content = &upload }, .response = .{ .body = body } };
}

/// Sends until every octet of `put`'s content is written. The peer drops what it gets. Test-only.
fn send_content(put: *const Exchange) !void {
    // Bounded: each pass writes some of the content, until all of it is written.
    for (0..upload.len) |_| {
        support.client_send();
        support.to_peer_len = 0;
        if (put.response.content_sent == upload.len) return;
    }
    return error.TestUnexpectedResult;
}

test "RFC 9112 §9.5: a response that ends before the content went out ends the connection" {
    try start();
    var put = put_upload(&bodies[0]);
    var waiting = get(&bodies[1]);
    _ = try connection.request(&put.request, &put.response);
    _ = try connection.request(&waiting.request, &waiting.response);
    support.client_send();
    try testing.expect(put.response.content_sent > 0 and put.response.content_sent < upload.len);
    try peer_writes(early_response);
    try testing.expectEqual(.response, put.response.outcome);
    try testing.expectEqual(precondition_failed, put.response.status);
    // The server never saw the request that waited, so it may go on another connection.
    try testing.expectEqual(.refused, waiting.response.outcome);
    try testing.expect(support.find(.closed) != null);
    try testing.expect(connection.should_close());
    // No more of the content is written, and the connection takes no new request.
    const content_sent = put.response.content_sent;
    const written = support.to_peer_len;
    support.client_send();
    try testing.expectEqual(written, support.to_peer_len);
    try testing.expectEqual(content_sent, put.response.content_sent);
    var third = get(&bodies[2]);
    try testing.expectError(error.ConnectionClosed, connection.request(&third.request, &third.response));
}

test "RFC 9112 §9.5: a response too large for its memory, which ends before the content, ends it too" {
    try start();
    var put = put_upload(bodies[0][0..2]);
    var waiting = get(&bodies[1]);
    _ = try connection.request(&put.request, &put.response);
    _ = try connection.request(&waiting.request, &waiting.response);
    support.client_send();
    // The content does not fit the two octets of `body`, so the response is read and dropped.
    try peer_writes("HTTP/1.1 412 Precondition Failed\r\nContent-Length: 5\r\n\r\nhel");
    // h11 has not ended the PUT's content, so the next head waits (RFC 9112 §9.3.2).
    support.client_send();
    try testing.expectEqual(.pending, waiting.response.outcome);
    try peer_writes("lo");
    try testing.expectEqual(.too_large, put.response.outcome);
    try testing.expect(put.response.content_sent < upload.len);
    try testing.expectEqual(.refused, waiting.response.outcome);
    try testing.expect(support.find(.closed) != null);
}

test "RFC 9112 §9.5: a response that ends after the content went out keeps the connection" {
    try start();
    var put = put_upload(&bodies[0]);
    var next = get(&bodies[1]);
    _ = try connection.request(&put.request, &put.response);
    try send_content(&put);
    try peer_writes(ok_response);
    try testing.expectEqual(.response, put.response.outcome);
    try testing.expectEqual(null, support.find(.closed));
    _ = try connection.request(&next.request, &next.response);
    support.client_send();
    try testing.expect(sent("GET /dns-query"));
    try peer_writes("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello");
    try testing.expectEqualStrings("hello", next.response.content_received());
}

test "RFC 9112 §9.3.2: a response to the exchange before the one whose content goes out keeps it" {
    try start();
    var first = get(&bodies[0]);
    var put = put_upload(&bodies[1]);
    _ = try connection.request(&first.request, &first.response);
    _ = try connection.request(&put.request, &put.response);
    // A GET is idempotent, so the PUT follows it before its response (decision 88).
    support.client_send();
    try testing.expect(put.response.content_sent > 0 and put.response.content_sent < upload.len);
    try peer_writes(ok_response);
    try testing.expectEqual(.response, first.response.outcome);
    try testing.expectEqual(null, support.find(.closed));
    try send_content(&put);
    try peer_writes(ok_response);
    try testing.expectEqual(.response, put.response.outcome);
    try testing.expectEqual(null, support.find(.closed));
}

test "RFC 9112 §6.2: a cancel while the content is going out ends the connection" {
    try start();
    @memset(&upload, 'x');
    var post: Exchange = .{ .request = .{ .method = "POST", .path = "/", .content = &upload }, .response = .{ .body = &bodies[0] } };
    const id = try connection.request(&post.request, &post.response);
    support.client_send();
    // The output holds less than the content, so some of it is still to go.
    try testing.expect(support.to_peer_len < upload.len);
    connection.cancel(id);
    try support.client_receive();
    try testing.expectEqual(0, support.count(.finished));
    try testing.expect(support.find(.closed) != null);
}
