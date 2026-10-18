//! The tests of the channel over TCP in cleartext h11 (`channel.zig`, `channel_events.zig`). The
//! channel reads what its connection owes with a call that passes no octets, and h11 needs the
//! octets it left unconsumed at the start of the next call's input (design §8 step 21c.3). A
//! request goes out again after a close only while no octet of its response arrived (decision 124).
//! The peer is h11's server side in the same process, or a response the test writes itself.
const std = @import("std");
const support = @import("../connection/connection_test_support.zig");
const channel_module = @import("channel.zig");
const channel_support = @import("channel_test_support.zig");
const event = @import("../event.zig");

const testing = std.testing;
const Exchange = support.Exchange;
const Event = channel_module.Event;

/// The channel's configuration and the events it reported, outside any stack frame. Test-only.
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

/// Passes the channel what the peer sent, in calls until one takes nothing and reports nothing,
/// with `.none` once no octet is left. Starts the connection an `open` event asks for, and keeps
/// the events.
fn collect(channel: anytype) !void {
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

fn get(body: []u8) Exchange {
    return .{ .request = .{ .method = "GET", .path = "/" }, .response = .{ .body = body } };
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

/// The content of a PUT, which the output of one `send_stream` does not hold. Test-only.
var upload: [support.buffer_len]u8 = undefined;

/// What the h11 peer read: the request heads, the octets of content, and the ends of requests.
const PeerRead = struct { requests: usize = 0, content_len: usize = 0, ends: usize = 0 };

fn peer_read() !PeerRead {
    var read: PeerRead = .{};
    var consumed: usize = 0;
    // Bounded: each pass consumes an octet or reports an event, and both are finite.
    for (0..support.to_peer_len + support.events_max) |_| {
        const received = try support.peer_h11.receive(support.to_peer[consumed..support.to_peer_len], &.{});
        consumed += received.consumed;
        switch (received.event orelse break) {
            .request => read.requests += 1,
            .data => |octets| read.content_len += octets.len,
            .end => read.ends += 1,
            .interim, .response, .tunnel => return error.TestUnexpectedResult,
        }
    }
    support.to_peer_len = 0;
    return read;
}

const content_length_5: []const support.Field = &.{.{ .name = "Content-Length", .value = "5" }};

test {
    // Decision 124: each test below runs on the default channel and on one with no QUIC.
    inline for (channel_support.channels) |Channel| _ = Tests(Channel);
}

/// The tests over a channel of type `Channel`, and the helpers that name the channel itself.
fn Tests(comptime Channel: type) type {
    return struct {
        /// The channel the tests drive, outside any stack frame. Test-only.
        var channel: Channel align(@alignOf(Channel)) = undefined;

        /// A channel with no QUIC configured, whose TCP connection speaks h11 in cleartext, with
        /// one exchange written to the peer's buffer.
        fn start(exchange: *Exchange) !void {
            config = .{ .authority = support.authority, .versions = channel_support.versions_for(&channel, support.only(.h11)) };
            try channel.init(&config, .{ .addresses = &addresses, .port = http_port }, null);
            support.peer_h11.init(.server, .{});
            support.peer_requests = 0;
            support.to_peer_len = 0;
            support.to_client_len = 0;
            events_len = 0;
            _ = try channel.request(&exchange.request, &exchange.response);
            // The channel asks for TCP, and its connection takes the exchange once it is started.
            try collect(&channel);
            try testing.expectEqual(event.Protocol.h11, find(.connected).?.connected);
            send();
        }

        /// Writes what the channel's connection owes into the peer's buffer.
        fn send() void {
            support.to_peer_len += channel.send_stream(support.to_peer[support.to_peer_len..], support.now_ns);
        }

        /// Passes the channel `octets` as what its socket holds, and returns how many it took.
        fn give(octets: []const u8) !usize {
            @memcpy(support.to_client[0..octets.len], octets);
            support.to_client_len = octets.len;
            try collect(&channel);
            return octets.len - support.to_client_len;
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
            try testing.expectEqual(.pending, exchange.response.outcome);
            try testing.expectEqual(response.len, try give(response));
            try testing.expectEqual(&exchange.response, find(.finished).?.finished.response);
            try testing.expectEqual(&exchange.request, find(.finished).?.finished.request);
            try testing.expectEqual(.response, exchange.response.outcome);
            try testing.expectEqualStrings("hello", exchange.response.content_received());
        }

        test "design §8 step 21c.3: a channel reads half a chunk-size line again with the rest of it" {
            var exchange = get(&bodies[0]);
            try start(&exchange);
            // h11 takes the head, and leaves the chunk-size line until its CRLF arrives
            // (RFC 9112 §7.1).
            try testing.expectEqual(chunked_head.len, try give(chunked_head ++ half_size_line));
            const polled = channel.receive(.none, support.now_ns);
            try testing.expectEqual(0, polled.consumed);
            try testing.expectEqual(null, polled.event);
            try testing.expectEqual(.pending, exchange.response.outcome);
            try testing.expectEqual(chunked_body.len, try give(chunked_body));
            try testing.expectEqual(.response, exchange.response.outcome);
            try testing.expectEqualStrings("hello", exchange.response.content_received());
        }

        test "design §8 step 21c.3: a channel carries two h11 exchanges, the last answered with no content" {
            var first = get(&bodies[0]);
            var last = get(&bodies[1]);
            try start(&first);
            const last_id = try channel.request(&last.request, &last.response);
            send();
            try support.peer_h11_read();
            try support.peer_h11_answer(ok, &.{.{ .name = "Content-Length", .value = "5" }}, "hello");
            try support.peer_h11_read();
            try testing.expectEqual(2, support.peer_requests);
            // RFC 9110 §15.3.5: a 204 response ends with its head, so no octet follows it.
            try support.peer_h11_answer(no_content, &.{}, "");
            try collect(&channel);
            try testing.expectEqual(0, support.to_client_len);
            try testing.expectEqual(2, count(.finished));
            try testing.expectEqual(.response, first.response.outcome);
            try testing.expectEqual(ok, first.response.status);
            try testing.expectEqualStrings("hello", first.response.content_received());
            try testing.expectEqual(.response, last.response.outcome);
            try testing.expectEqual(no_content, last.response.status);
            try testing.expectEqual(0, last.response.content_received().len);
            try testing.expectEqual(last_id, events[events_len - 1].finished.id);
        }

        test "decision 100: a channel reports a closed connection's close before it asks for the next socket" {
            var first = get(&bodies[0]);
            var second = get(&bodies[1]);
            try start(&first);
            _ = try channel.request(&second.request, &second.response);
            // RFC 9112 §9.6: a response that says "close" ends the connection after it, so the
            // second exchange waits for another connection, in the same call that reads the
            // connection's end.
            const response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello";
            try testing.expectEqual(response.len, try give(response));
            try testing.expectEqual(.response, first.response.outcome);
            try testing.expectEqual(2, count(.open));
            const closed_at = index_of(.close, 0) orelse return error.TestUnexpectedResult;
            try testing.expectEqual(Event{ .close = .tcp }, events[closed_at]);
            try testing.expect(closed_at < index_of(.open, 1).?);
            try testing.expectEqual(2, count(.connected));
        }

        test "decision 124: an early h11 response ends its connection, and the next exchange opens another" {
            @memset(&upload, 'x');
            var put: Exchange = .{ .request = .{ .method = "PUT", .path = "/object", .content = &upload }, .response = .{ .body = &bodies[0] } };
            try start(&put);
            try testing.expect(put.response.content_sent < upload.len);
            // RFC 9110 §15.5.13: the server refuses the precondition before it reads the content,
            // and names no close option (RFC 9112 §9.6). RFC 9112 §9.5: the client ends the
            // connection.
            const early_response = "HTTP/1.1 412 Precondition Failed\r\nContent-Length: 0\r\n\r\n";
            try testing.expectEqual(early_response.len, try give(early_response));
            try testing.expectEqual(.response, put.response.outcome);
            const closed_at = index_of(.close, 0) orelse return error.TestUnexpectedResult;
            try testing.expectEqual(Event{ .close = .tcp }, events[closed_at]);
            // The peer serves the new connection from here on.
            support.peer_h11.init(.server, .{});
            support.to_peer_len = 0;
            var next = get(&bodies[1]);
            _ = try channel.request(&next.request, &next.response);
            try collect(&channel);
            try testing.expectEqual(2, count(.open));
            try testing.expectEqual(2, count(.connected));
            send();
            try support.peer_h11_read();
            try testing.expectEqual(1, support.peer_requests);
            try support.peer_h11_answer(ok, &.{.{ .name = "Content-Length", .value = "5" }}, "hello");
            try collect(&channel);
            try testing.expectEqual(.response, next.response.outcome);
            try testing.expectEqualStrings("hello", next.response.content_received());
        }

        test "decision 120: a shut-down channel drops the open of a connection no caller heard of" {
            var first = get(&bodies[0]);
            var second = get(&bodies[1]);
            try start(&first);
            const second_id = try channel.request(&second.request, &second.response);
            // RFC 9112 §9.6: the response closes the connection, so the second exchange waits for
            // another.
            const response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello";
            @memcpy(support.to_client[0..response.len], response);
            support.to_client_len = response.len;
            // The program reads until the channel says to close the socket, and no further.
            for (0..support.buffer_len + support.events_max) |_| {
                const input: channel_module.Input = if (support.to_client_len > 0) .{ .stream = support.to_client[0..support.to_client_len] } else .none;
                const received = channel.receive(input, support.now_ns);
                std.mem.copyForwards(u8, &support.to_client, support.to_client[received.consumed..support.to_client_len]);
                support.to_client_len -= received.consumed;
                const reported = received.event orelse continue;
                if (reported == .close) break;
            } else return error.TestUnexpectedResult;
            // The program gives the second exchange up and shuts the channel down, before the
            // `open` the channel owes for it.
            channel.cancel(second_id);
            channel.shutdown();
            events_len = 0;
            try collect(&channel);
            // The connection's `close` went out already, and the one the channel never opened has
            // none.
            try testing.expectEqual(0, count(.open) + count(.close));
            try testing.expectEqual(Event.closed, find(.closed).?);
        }

        /// The caller's transport closes: the program drops what it held of the socket, and the
        /// peer of the next connection starts with nothing read or written.
        fn close_transport() !void {
            channel.transport_closed(.tcp);
            support.peer_h11.init(.server, .{});
            support.peer_requests = 0;
            support.to_peer_len = 0;
            support.to_client_len = 0;
            try collect(&channel);
        }

        test "RFC 9112 §9.3.1: an h11 GET whose connection closed before any of its response goes out again" {
            var exchange = get(&bodies[0]);
            try start(&exchange);
            try testing.expectEqual(1, (try peer_read()).requests);
            try close_transport();
            try testing.expectEqual(null, find(.finished));
            try testing.expectEqual(2, count(.open));
            send();
            try testing.expectEqual(1, (try peer_read()).requests);
            try support.peer_h11_answer(ok, content_length_5, "hello");
            try collect(&channel);
            try testing.expectEqual(1, count(.finished));
            try testing.expectEqual(.response, exchange.response.outcome);
            try testing.expectEqualStrings("hello", exchange.response.content_received());
        }

        test "RFC 9110 §9.2.2: an h11 POST whose connection closed before any of its response ends closed" {
            var exchange: Exchange = .{ .request = .{ .method = "POST", .path = "/form", .content = "a=1" }, .response = .{ .body = &bodies[0] } };
            try start(&exchange);
            try close_transport();
            try testing.expectEqual(.closed, exchange.response.outcome);
            try testing.expectEqual(1, count(.open));
        }

        test "RFC 9110 §9.2.2: an h11 PUT sent again sends its whole content again" {
            const put_len: usize = 64;
            @memset(upload[0..put_len], 'u');
            var put: Exchange = .{ .request = .{ .method = "PUT", .path = "/object", .content = upload[0..put_len] }, .response = .{ .body = &bodies[0] } };
            try start(&put);
            try testing.expectEqual(PeerRead{ .requests = 1, .content_len = put_len, .ends = 1 }, try peer_read());
            try close_transport();
            send();
            try testing.expectEqual(PeerRead{ .requests = 1, .content_len = put_len, .ends = 1 }, try peer_read());
            try support.peer_h11_answer(no_content, &.{}, "");
            try collect(&channel);
            try testing.expectEqual(.response, put.response.outcome);
            try testing.expectEqual(put_len, put.response.content_sent);
        }

        test "RFC 9110 §9.2.2: an h11 GET whose second connection also closed before any of its response ends closed" {
            var exchange = get(&bodies[0]);
            try start(&exchange);
            try close_transport();
            send();
            try testing.expectEqual(1, (try peer_read()).requests);
            try close_transport();
            try testing.expectEqual(.closed, exchange.response.outcome);
            try testing.expectEqual(1, count(.finished));
            try testing.expectEqual(2, count(.open));
        }

        test "RFC 9110 §9.2.2: an h11 GET whose connection closed after one octet of its response ends closed" {
            var exchange = get(&bodies[0]);
            try start(&exchange);
            // h11 holds the octet until the rest of the head arrives, and the channel read it.
            try testing.expectEqual(0, try give(half_head[0..1]));
            try close_transport();
            try testing.expectEqual(.closed, exchange.response.outcome);
            try testing.expectEqual(1, count(.open));
        }

        test "RFC 9110 §9.2.2: an h11 GET whose connection closed after its whole head ends closed" {
            var exchange = get(&bodies[0]);
            try start(&exchange);
            // h11 takes the head, and the content it names never arrives.
            const head = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n";
            try testing.expectEqual(head.len, try give(head));
            try testing.expectEqual(ok, exchange.response.status);
            try close_transport();
            try testing.expectEqual(.closed, exchange.response.outcome);
            try testing.expectEqual(1, count(.open));
        }

        test "RFC 9112 §9.2: an octet after an h11 response is the next response's, though the channel read it once" {
            var first = get(&bodies[0]);
            var second = get(&bodies[1]);
            try start(&first);
            _ = try channel.request(&second.request, &second.response);
            send();
            // RFC 9112 §9.3.2: the client pipelines the second request behind the first.
            try testing.expectEqual(2, channel.tcp.slots.count(.sent));
            // One call reads the first response whole and leaves the first octet of the second, and
            // the transport closes before the program passes that octet again.
            const octets = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloH";
            @memcpy(support.to_client[0..octets.len], octets);
            const received = channel.receive(.{ .stream = support.to_client[0..octets.len] }, support.now_ns);
            try testing.expectEqual(octets.len - 1, received.consumed);
            try testing.expectEqual(&first.response, received.event.?.finished.response);
            try close_transport();
            try testing.expectEqual(.response, first.response.outcome);
            try testing.expectEqual(.closed, second.response.outcome);
            try testing.expectEqual(1, count(.open));
        }

        test "decision 124: an h11 request a close moved unwritten, whose next connection closed before any response, ends closed" {
            var first = get(&bodies[0]);
            var second = get(&bodies[1]);
            try start(&first);
            _ = try channel.request(&second.request, &second.response);
            // RFC 9112 §9.6: the response closes the connection before the second request was
            // written, so the second is refused and moves.
            const response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello";
            try testing.expectEqual(response.len, try give(response));
            try testing.expectEqual(2, count(.connected));
            support.peer_h11.init(.server, .{});
            support.to_peer_len = 0;
            send();
            try testing.expectEqual(1, (try peer_read()).requests);
            // The refusal spent the one move (`moves_max`), so the close sends nothing again.
            try close_transport();
            try testing.expectEqual(.closed, second.response.outcome);
            try testing.expectEqual(2, count(.open));
        }

        test "decision 124: a cancelled h11 exchange is never sent again" {
            var exchange = get(&bodies[0]);
            try start(&exchange);
            // A channel's first exchange gets id 1.
            channel.cancel(1);
            try close_transport();
            try testing.expectEqual(null, find(.finished));
            try testing.expectEqual(1, count(.open));
        }
    };
}
