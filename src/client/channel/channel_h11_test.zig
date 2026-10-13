//! The tests of the channel over TCP in cleartext h11 (`channel.zig`, `channel_events.zig`). The
//! channel reads what its connection owes with a call that passes no octets, and h11 needs the
//! octets it left unconsumed at the start of the next call's input (design §8 step 21c.3). The
//! peer is h11's server side in the same process, or a response the test writes itself.
const std = @import("std");
const support = @import("../connection/connection_test_support.zig");
const channel_module = @import("channel.zig");
const event = @import("../event.zig");

const testing = std.testing;
const Channel = channel_module.Channel;
const HttpExchange = event.HttpExchange;
const Event = channel_module.Event;

/// The channel the tests drive, its configuration and the events it reported, outside any stack
/// frame. Test-only.
var channel: Channel align(@alignOf(Channel)) = undefined;
var config: channel_module.Config align(@alignOf(channel_module.Config)) = undefined;
var events: [support.events_max]Event align(@alignOf(Event)) = undefined;
var events_len: usize = 0;
var bodies: [bodies_count][body_len]u8 = undefined;
const bodies_count: usize = 2;
const body_len: usize = 1024;

const ok: u16 = 200;
/// RFC 9110 §15.3.5: 204 No Content, a response that has no content.
const no_content: u16 = 204;
/// RFC 9110 §4.2.1: the port of an "http" origin whose URI names none.
const http_port: u16 = 80;
/// An IPv4 host, its four octets alike. Test-only.
const ipv4_len: usize = 4;
const host_octet: u8 = 0x7f;
const loopback: [ipv4_len]u8 = @splat(host_octet);
const addresses = [_]channel_module.Address{channel_module.Address.of(&loopback, 0)};

/// The start of a response head, which ends inside its status code.
const half_head = "HTTP/1.1 2";
const chunked_head = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
/// RFC 9112 §7.1: one chunk of five octets, then the last chunk and an empty trailer section.
const chunked_body = "5\r\nhello\r\n0\r\n\r\n";
/// The first octet of `chunked_body`: a chunk-size line without its CRLF.
const half_size_line = chunked_body[0..1];

/// A channel with no QUIC configured, whose TCP connection speaks h11 in cleartext, with one
/// exchange written to the peer's buffer.
fn start(exchange: *HttpExchange) !void {
    config = .{ .authority = support.authority, .versions = support.only(.h11) };
    try channel.init(&config, .{ .addresses = &addresses, .port = http_port }, null);
    support.peer_h11.init(.server, .{});
    support.peer_requests = 0;
    support.to_peer_len = 0;
    support.to_client_len = 0;
    events_len = 0;
    _ = try channel.request(exchange);
    // The channel asks for TCP, and its connection takes the exchange once it is started.
    try collect();
    try testing.expectEqual(event.Protocol.h11, find(.connected).?.connected);
    send();
}

/// Writes what the channel's connection owes into the peer's buffer.
fn send() void {
    support.to_peer_len += channel.send_stream(support.to_peer[support.to_peer_len..], support.now_ns);
}

/// Passes the channel what the peer sent, in calls until one takes nothing and reports nothing,
/// with `.none` once no octet is left. Starts the connection an `open` event asks for, and keeps
/// the events.
fn collect() !void {
    // Bounded: each pass consumes an octet or reports an event, and both are finite.
    for (0..support.buffer_len + support.events_max) |_| {
        const input: channel_module.Input = if (support.to_client_len > 0) .{ .stream = support.to_client[0..support.to_client_len] } else .none;
        const received = channel.receive(input, support.now_ns);
        std.mem.copyForwards(u8, &support.to_client, support.to_client[received.consumed..support.to_client_len]);
        support.to_client_len -= received.consumed;
        const reported = received.event orelse {
            if (received.consumed == 0) return;
            continue;
        };
        if (events_len == events.len) return error.TestUnexpectedResult;
        events[events_len] = reported;
        events_len += 1;
        if (reported == .open) try channel.start_tcp(support.stream.random(), 0, null);
    }
    return error.TestUnexpectedResult;
}

/// Passes the channel `octets` as what its socket holds, and returns how many it took.
fn give(octets: []const u8) !usize {
    @memcpy(support.to_client[0..octets.len], octets);
    support.to_client_len = octets.len;
    try collect();
    return octets.len - support.to_client_len;
}

/// The first event of `tag` the channel reported, or null.
fn find(tag: std.meta.Tag(Event)) ?Event {
    for (events[0..events_len]) |reported| {
        if (reported == tag) return reported;
    }
    return null;
}

fn count(tag: std.meta.Tag(Event)) usize {
    var counted: usize = 0;
    for (events[0..events_len]) |reported| counted += @intFromBool(reported == tag);
    return counted;
}

fn get(body: []u8) HttpExchange {
    return .{ .method = "GET", .path = "/", .body = body };
}

test "design §8 step 21c.3: a channel reads half an h11 head again once its caller passes it whole" {
    var exchange = get(&bodies[0]);
    try start(&exchange);
    const response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
    try testing.expectEqual(0, try give(response[0..half_head.len]));
    // The caller holds half a head, and reads the channel with no octets, as after a send.
    const polled = channel.receive(.none, support.now_ns);
    try testing.expectEqual(0, polled.consumed);
    try testing.expectEqual(null, polled.event);
    try testing.expectEqual(.pending, exchange.outcome);
    try testing.expectEqual(response.len, try give(response));
    try testing.expectEqual(&exchange, find(.finished).?.finished.exchange);
    try testing.expectEqual(.response, exchange.outcome);
    try testing.expectEqualStrings("hello", exchange.content_received());
}

test "design §8 step 21c.3: a channel reads half a chunk-size line again with the rest of it" {
    var exchange = get(&bodies[0]);
    try start(&exchange);
    // h11 takes the head, and leaves the chunk-size line until its CRLF arrives (RFC 9112 §7.1).
    try testing.expectEqual(chunked_head.len, try give(chunked_head ++ half_size_line));
    const polled = channel.receive(.none, support.now_ns);
    try testing.expectEqual(0, polled.consumed);
    try testing.expectEqual(null, polled.event);
    try testing.expectEqual(.pending, exchange.outcome);
    try testing.expectEqual(chunked_body.len, try give(chunked_body));
    try testing.expectEqual(.response, exchange.outcome);
    try testing.expectEqualStrings("hello", exchange.content_received());
}

test "design §8 step 21c.3: a channel carries two h11 exchanges, the last answered with no content" {
    var first = get(&bodies[0]);
    var last = get(&bodies[1]);
    try start(&first);
    const last_id = try channel.request(&last);
    send();
    try support.peer_h11_read();
    try support.peer_h11_answer(ok, &.{.{ .name = "Content-Length", .value = "5" }}, "hello");
    try support.peer_h11_read();
    try testing.expectEqual(2, support.peer_requests);
    // RFC 9110 §15.3.5: a 204 response ends with its head, so no octet follows it.
    try support.peer_h11_answer(no_content, &.{}, "");
    try collect();
    try testing.expectEqual(0, support.to_client_len);
    try testing.expectEqual(2, count(.finished));
    try testing.expectEqual(.response, first.outcome);
    try testing.expectEqual(ok, first.status);
    try testing.expectEqualStrings("hello", first.content_received());
    try testing.expectEqual(.response, last.outcome);
    try testing.expectEqual(no_content, last.status);
    try testing.expectEqual(0, last.content_received().len);
    try testing.expectEqual(last_id, events[events_len - 1].finished.id);
}

/// The index of the `n`th event of `tag` the channel reported, counted from 0, or null.
fn index_of(tag: std.meta.Tag(Event), n: usize) ?usize {
    var seen: usize = 0;
    for (events[0..events_len], 0..) |reported, index| {
        if (reported != tag) continue;
        if (seen == n) return index;
        seen += 1;
    }
    return null;
}

test "decision 100: a channel reports a closed connection's close before it asks for the next socket" {
    var first = get(&bodies[0]);
    var second = get(&bodies[1]);
    try start(&first);
    _ = try channel.request(&second);
    // RFC 9112 §9.6: a response that says "close" ends the connection after it, so the second
    // exchange waits for another connection, in the same call that reads the connection's end.
    const response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello";
    try testing.expectEqual(response.len, try give(response));
    try testing.expectEqual(.response, first.outcome);
    try testing.expectEqual(2, count(.open));
    const closed_at = index_of(.close, 0) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(Event{ .close = .tcp }, events[closed_at]);
    try testing.expect(closed_at < index_of(.open, 1).?);
    try testing.expectEqual(2, count(.connected));
}
