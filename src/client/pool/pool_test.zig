//! The tests of the pool to one origin (`pool.zig`, `pool_events.zig`) over TCP: the
//! pool asks for the transport, carries each exchange on the connection it opened, sends an
//! idempotent request again after a close (decision 124), and ends once shut down, against h2's
//! server side in the same process.
const std = @import("std");
const h2 = @import("h2");
const support = @import("../connection/connection_test_support.zig");
const pool_module = @import("pool.zig");
const pool_support = @import("pool_test_support.zig");
const event = @import("../event.zig");
const constants = @import("../constants.zig");

const testing = std.testing;
const Exchange = support.Exchange;
const Event = pool_module.Event;

/// The pool's configuration and the events it reported, outside any stack frame. Test-only.
var config: pool_module.Config align(@alignOf(pool_module.Config)) = undefined;
var events: [support.events_max]Event align(@alignOf(Event)) = undefined;
var events_len: usize = 0;
var bodies: [bodies_count][body_len]u8 = undefined;
const bodies_count: usize = 2;
const body_len: usize = 1024;

const ok: u16 = 200;
const https_port: u16 = 443;
/// An IPv4 host, its four octets alike. Test-only.
const ipv4_len: usize = 4;
const host_octet: u8 = 0x7f;
const loopback: [ipv4_len]u8 = @splat(host_octet);
const other_octet: u8 = 0x7e;
const other_host: [ipv4_len]u8 = @splat(other_octet);
const addresses = [_]pool_module.Address{pool_module.Address.of(&loopback, 0)};
const two_addresses = [_]pool_module.Address{ pool_module.Address.of(&loopback, 0), pool_module.Address.of(&other_host, 0) };
/// Whether `collect` starts a TCP connection an `open` event asks for.
var starts: bool = true;
const unstarted_octet: u8 = 0x01;
/// Rounds of moving octets a test takes at most.
const rounds: usize = 8;

/// Reports every event the pool owes, taking what the peer sent, starts a transport an `open`
/// event asks for, and keeps the events.
fn collect(pool: anytype) !void {
    // Bounded: each pass consumes an octet or reports an event, and both are finite.
    for (0..support.buffer_len + support.events_max) |_| {
        const input: pool_module.Input = if (support.to_client_len > 0) .{ .stream = support.to_client[0..support.to_client_len] } else .none;
        const received = pool.receive(input, support.now_ns);
        std.mem.copyForwards(u8, &support.to_client, support.to_client[received.consumed..support.to_client_len]);
        support.to_client_len -= received.consumed;
        const reported = received.event orelse {
            if (received.consumed == 0) return;
            continue;
        };
        if (events_len == events.len) return error.TestUnexpectedResult;
        events[events_len] = reported;
        events_len += 1;
        if (reported == .open and starts) try pool.start_tcp(support.stream.random(), 0, null);
    }
    return error.TestUnexpectedResult;
}

/// Moves octets both ways for a few rounds.
fn pump(pool: anytype) !void {
    for (0..rounds) |_| {
        support.to_peer_len += pool.send_stream(support.to_peer[support.to_peer_len..], support.now_ns);
        try support.peer_h2_read();
        try collect(pool);
    }
}

/// The first event of `tag` the pool reported, or null.
fn find(tag: std.meta.Tag(Event)) ?Event {
    const index = index_of(tag) orelse return null;
    return events[index];
}

fn index_of(tag: std.meta.Tag(Event)) ?usize {
    for (events[0..events_len], 0..) |reported, index| {
        if (reported == tag) return index;
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

/// The h2 peer of the next connection the pool opens: it starts again, with nothing read or
/// written either way.
fn fresh_peer() void {
    support.peer_h2.init(.server);
    support.to_peer_len = 0;
    support.to_client_len = 0;
    support.peer_events_len = 0;
}

/// What the peer read of requests since `fresh_peer`: the heads, the octets of content, and
/// whether a DATA frame ended a stream.
const PeerRead = struct { requests: usize = 0, content_len: usize = 0, ended: bool = false };

fn peer_read() PeerRead {
    var read: PeerRead = .{};
    for (support.peer_events[0..support.peer_events_len]) |peer_event| switch (peer_event) {
        .request => read.requests += 1,
        .data => |data| {
            read.content_len += data.payload.len;
            read.ended = read.ended or data.end_stream;
        },
        else => {},
    };
    return read;
}

/// The content of a PUT the pool sends again. Test-only.
var upload: [upload_len]u8 = undefined;
const upload_len: usize = 4096;

test {
    // Decision 124: each test below runs on the default pool and on one with no QUIC.
    inline for (pool_support.pools) |Pool| _ = Tests(Pool);
}

/// The tests over a pool of type `Pool`, and the helpers that name the pool itself.
fn Tests(comptime Pool: type) type {
    return struct {
        /// The pool the tests drive, outside any stack frame. Test-only.
        var pool: Pool align(@alignOf(Pool)) = undefined;
        var pool_memory: [Pool.memory_bytes(.{})]u8 align(Pool.memory_alignment) = undefined;

        /// A pool with no QUIC configured, whose TCP connections speak h2 in cleartext.
        fn start_tcp_only() !void {
            try start_at(&addresses);
        }

        fn start_at(to: []const pool_module.Address) !void {
            config = .{ .authority = support.authority, .versions = pool_support.versions_for(&pool, support.only(.h2)) };
            // Every octet 1, so each flag of a connection the pool never started reads as set,
            // and a read of one shows.
            @memset(std.mem.asBytes(&pool), unstarted_octet);
            try pool.init(&pool_memory, &config, .{ .addresses = to, .port = https_port }, .{}, null);
            starts = true;
            support.peer_h2.init(.server);
            support.to_peer_len = 0;
            support.to_client_len = 0;
            support.peer_events_len = 0;
            events_len = 0;
        }

        test "decision 100: with no QUIC configured, the pool opens TCP and carries an exchange on it" {
            try start_tcp_only();
            var exchange: Exchange = .{ .request = .{ .method = "GET", .path = "/" }, .response = .{ .body = &bodies[0] } };
            const id = try pool.request(&exchange.request, &exchange.response);
            try collect(&pool);
            // RFC 9110 §4.2.2: with no HTTPS record, the connection goes to the origin's port.
            const opened = find(.open).?.open;
            try testing.expectEqual(pool_module.Transport.tcp, opened.transport);
            try testing.expectEqual(https_port, opened.to.port);
            try pump(&pool);
            try testing.expectEqual(event.Protocol.h2, find(.connected).?.connected);
            try support.peer_h2_answer(1, ok, &.{}, "hello");
            try collect(&pool);
            const finished = find(.finished).?.finished;
            try testing.expectEqual(id, finished.id);
            try testing.expectEqual(.response, exchange.response.outcome);
            try testing.expectEqualStrings("hello", exchange.response.content_received());
            // The pool is not closed until its caller shuts it down.
            try testing.expectEqual(null, find(.closed));
        }

        test "decision 100: a shut-down pool drains its connection, asks for its close, and reports closed" {
            try start_tcp_only();
            var exchange: Exchange = .{ .request = .{ .method = "GET", .path = "/" }, .response = .{ .body = &bodies[0] } };
            _ = try pool.request(&exchange.request, &exchange.response);
            try pump(&pool);
            pool.shutdown();
            try support.peer_h2_answer(1, ok, &.{}, "hello");
            try pump(&pool);
            try testing.expectEqual(.response, exchange.response.outcome);
            try testing.expectEqual(pool_module.Transport.tcp, find(.close).?.close);
            // The pool closes once, after its transports did.
            try testing.expectEqual(1, count(.closed));
            try testing.expect(index_of(.close).? < index_of(.closed).?);
            try testing.expectEqual(pool_module.Phase.closed, pool.phase(.tcp));
            // It ended after its last exchange, not on a failure.
            try testing.expect(!pool.tcp[0].failed);
        }

        test "RFC 9113 §6.8: a shut-down pool asks for its transport's close once the GOAWAY is written" {
            try start_tcp_only();
            var exchange = get(&bodies[0]);
            _ = try pool.request(&exchange.request, &exchange.response);
            try pump(&pool);
            pool.shutdown();
            try support.peer_h2_answer(1, ok, &.{}, "hello");
            // The pool reads the response and its connection's `closed` in these calls, before
            // any send: h2 holds its GOAWAY, and the connection's output is empty.
            try collect(&pool);
            try testing.expectEqual(.response, exchange.response.outcome);
            try testing.expectEqual(null, find(.close));
            support.peer_events_len = 0;
            support.to_peer_len += pool.send_stream(support.to_peer[support.to_peer_len..], support.now_ns);
            try support.peer_h2_read();
            try testing.expectEqual(.goaway, std.meta.activeTag(support.peer_events[0]));
            try collect(&pool);
            try testing.expectEqual(pool_module.Transport.tcp, find(.close).?.close);
            try testing.expectEqual(1, count(.closed));
        }

        test "RFC 9113 §8.7: a transport the caller closed moves the exchange it had not written to a new connection" {
            try start_at(&two_addresses);
            var exchange = get(&bodies[0]);
            _ = try pool.request(&exchange.request, &exchange.response);
            try collect(&pool);
            // The exchange waits in the connection, unwritten, when the caller's transport closes.
            pool.transport_closed(.tcp);
            try collect(&pool);
            try testing.expectEqual(null, find(.finished));
            try testing.expectEqual(2, count(.open));
            // The connection that closed had taken the exchange, so it was no failed attempt, and
            // the second one goes to the same address.
            for (events[0..events_len]) |reported| {
                if (reported == .open) try testing.expect(reported.open.to.same_host(&two_addresses[0]));
            }
            try pump(&pool);
            try support.peer_h2_answer(1, ok, &.{}, "hello");
            try collect(&pool);
            try testing.expectEqual(.response, exchange.response.outcome);
        }

        test "RFC 9110 §9.2.2: a transport the caller closed ends its written POST closed, and asks for no close" {
            try start_tcp_only();
            var exchange: Exchange = .{ .request = .{ .method = "POST", .path = "/", .content = "form" }, .response = .{ .body = &bodies[0] } };
            _ = try pool.request(&exchange.request, &exchange.response);
            try pump(&pool);
            pool.transport_closed(.tcp);
            try collect(&pool);
            try testing.expectEqual(.closed, exchange.response.outcome);
            try testing.expectEqual(&exchange.response, find(.finished).?.finished.response);
            try testing.expectEqual(&exchange.request, find(.finished).?.finished.request);
            try testing.expectEqual(null, find(.close));
            try testing.expectEqual(pool_module.Phase.closed, pool.phase(.tcp));
            // A POST is not idempotent, so the pool opens no connection to send it again.
            try testing.expectEqual(1, count(.open));
        }

        test "a pool holds exchanges_max exchanges at once, and refuses one more" {
            try start_tcp_only();
            var exchanges: [constants.exchanges_max + 1]Exchange = @splat(get(&bodies[0]));
            for (exchanges[0..constants.exchanges_max]) |*exchange| _ = try pool.request(&exchange.request, &exchange.response);
            try testing.expectError(error.Full, pool.request(&exchanges[constants.exchanges_max].request, &exchanges[constants.exchanges_max].response));
        }

        test "what a transport with no running connection read is dropped" {
            try start_tcp_only();
            var octets: [ipv4_len]u8 = @splat(host_octet);
            const datagram = pool.receive(.{ .datagram = .{ .octets = &octets } }, support.now_ns);
            try testing.expectEqual(octets.len, datagram.consumed);
            try testing.expectEqual(null, datagram.event);
            const stream = pool.receive(.{ .stream = &octets }, support.now_ns);
            try testing.expectEqual(octets.len, stream.consumed);
            try testing.expectEqual(null, stream.event);
        }

        test "a transport that failed before its handshake completed tries the next address next time" {
            try start_at(&two_addresses);
            starts = false;
            var exchange = get(&bodies[0]);
            _ = try pool.request(&exchange.request, &exchange.response);
            try collect(&pool);
            try testing.expect(find(.open).?.open.to.same_host(&two_addresses[0]));
            // The caller's connection failed, so no transport is left, and the exchange ends
            // refused.
            pool.transport_closed(.tcp);
            try collect(&pool);
            try testing.expectEqual(.refused, exchange.response.outcome);
            events_len = 0;
            _ = try pool.request(&exchange.request, &exchange.response);
            try collect(&pool);
            try testing.expect(find(.open).?.open.to.same_host(&two_addresses[1]));
        }

        /// Closes the caller's transport, and reports what the pool then owes to a fresh peer.
        fn close_transport() !void {
            pool.transport_closed(.tcp);
            fresh_peer();
            try collect(&pool);
        }

        test "RFC 9110 §9.2.2: a GET whose connection closed before any of its response goes out again, and is answered" {
            try start_tcp_only();
            var exchange = get(&bodies[0]);
            const id = try pool.request(&exchange.request, &exchange.response);
            try pump(&pool);
            try testing.expectEqual(1, peer_read().requests);
            try close_transport();
            // RFC 9112 §9.3.1: the pool opens another connection for the request, and reports
            // nothing.
            try testing.expectEqual(null, find(.finished));
            try testing.expectEqual(2, count(.open));
            try pump(&pool);
            try testing.expectEqual(1, peer_read().requests);
            try support.peer_h2_answer(1, ok, &.{}, "hello");
            try collect(&pool);
            try testing.expectEqual(id, find(.finished).?.finished.id);
            try testing.expectEqual(1, count(.finished));
            try testing.expectEqual(.response, exchange.response.outcome);
            try testing.expectEqualStrings("hello", exchange.response.content_received());
        }

        test "RFC 9110 §9.2.2: a PUT sent again sends its whole content again" {
            try start_tcp_only();
            @memset(&upload, 'u');
            var put: Exchange = .{ .request = .{ .method = "PUT", .path = "/object", .content = &upload }, .response = .{ .body = &bodies[0] } };
            _ = try pool.request(&put.request, &put.response);
            try pump(&pool);
            try testing.expectEqual(upload_len, peer_read().content_len);
            try close_transport();
            try pump(&pool);
            try testing.expectEqual(PeerRead{ .requests = 1, .content_len = upload_len, .ended = true }, peer_read());
            try support.peer_h2_answer(1, ok, &.{}, "");
            try collect(&pool);
            try testing.expectEqual(.response, put.response.outcome);
            try testing.expectEqual(upload_len, put.response.content_sent);
        }

        test "RFC 9110 §9.2.2: a GET whose second connection also closed before any of its response ends closed" {
            try start_tcp_only();
            var exchange = get(&bodies[0]);
            _ = try pool.request(&exchange.request, &exchange.response);
            try pump(&pool);
            try close_transport();
            try pump(&pool);
            try testing.expectEqual(1, peer_read().requests);
            // RFC 9110 §9.2.2: "A client SHOULD NOT automatically retry a failed automatic retry."
            try close_transport();
            try testing.expectEqual(.closed, exchange.response.outcome);
            try testing.expectEqual(1, count(.finished));
            try testing.expectEqual(2, count(.open));
        }

        test "RFC 9110 §9.2.2: a GET whose connection closed after a HEADERS frame of its response ends closed" {
            try start_tcp_only();
            var exchange = get(&bodies[0]);
            _ = try pool.request(&exchange.request, &exchange.response);
            try pump(&pool);
            // The head arrives with no END_STREAM, and the content never does.
            support.to_client_len += try support.peer_h2.write_response(support.to_client[support.to_client_len..], 1, ok, &.{}, false);
            try collect(&pool);
            try close_transport();
            try testing.expectEqual(.closed, exchange.response.outcome);
            try testing.expectEqual(ok, exchange.response.status);
            try testing.expectEqual(1, count(.open));
        }

        /// The h2 peer writes the header of a HEADERS frame on stream 1 that ends its field block,
        /// then `payload`, which is the frame's payload or the first octets of it.
        fn peer_headers(payload_len: u32, payload: []const u8) !void {
            var frame = h2.core.Writer.init(support.to_client[support.to_client_len..]);
            try h2.frame.write_header(&frame, .{ .length = payload_len, .type = h2.constants.frame_type_headers, .flags = h2.constants.flag_end_headers, .stream_id = 1 });
            try frame.write_bytes(payload);
            support.to_client_len += frame.written().len;
        }

        test "decision 124: a GET whose HEADERS frame fails to decode ends closed, not sent again" {
            try start_tcp_only();
            var exchange = get(&bodies[0]);
            _ = try pool.request(&exchange.request, &exchange.response);
            try pump(&pool);
            // RFC 7541 §6.1: "The index value of 0 is not used", so the field block is a
            // COMPRESSION_ERROR (RFC 9113 §4.3), and the connection fails.
            const index_zero = [_]u8{0x80};
            try peer_headers(index_zero.len, &index_zero);
            try collect(&pool);
            try testing.expectEqual(.closed, exchange.response.outcome);
            try testing.expectEqual(1, count(.open));
        }

        test "decision 124: a GET whose connection closed inside a HEADERS frame ends closed, not sent again" {
            try start_tcp_only();
            var exchange = get(&bodies[0]);
            _ = try pool.request(&exchange.request, &exchange.response);
            try pump(&pool);
            // The frame's header arrives, and its payload never does.
            const field_block_len: u32 = 16;
            try peer_headers(field_block_len, "");
            try collect(&pool);
            try close_transport();
            try testing.expectEqual(.closed, exchange.response.outcome);
            try testing.expectEqual(1, count(.open));
        }

        test "RFC 9110 §9.2.2: a request whose method RFC 9110 does not define is not sent again" {
            try start_tcp_only();
            var exchange: Exchange = .{ .request = .{ .method = "PATCH", .path = "/object", .content = "diff" }, .response = .{ .body = &bodies[0] } };
            _ = try pool.request(&exchange.request, &exchange.response);
            try pump(&pool);
            try close_transport();
            try testing.expectEqual(.closed, exchange.response.outcome);
            try testing.expectEqual(1, count(.open));
        }

        /// The h2 peer says GOAWAY before it reads a request, so the GOAWAY names no stream (RFC
        /// 9113 §6.8). The pool reads it, and the connection's `close` and the next `open`
        /// follow.
        fn goaway_first() !void {
            support.peer_h2.shutdown(h2.constants.error_no_error);
            support.peer_h2_owe();
            try collect(&pool);
            // The draining connection writes what it owes, its GOAWAY last, and no request.
            _ = pool.send_stream(&support.to_peer, support.now_ns);
            try collect(&pool);
            fresh_peer();
        }

        test "decision 124: a request a GOAWAY moved, whose next connection closed before any response, ends closed" {
            try start_tcp_only();
            var exchange = get(&bodies[0]);
            _ = try pool.request(&exchange.request, &exchange.response);
            try collect(&pool);
            try goaway_first();
            try testing.expectEqual(2, count(.open));
            try pump(&pool);
            try testing.expectEqual(1, peer_read().requests);
            // The refusal spent the one move (`moves_max`), so the close sends nothing again.
            try close_transport();
            try testing.expectEqual(.closed, exchange.response.outcome);
            try testing.expectEqual(2, count(.open));
        }

        test "decision 124: a GET sent again that its next connection refuses ends closed, since a server may have processed it" {
            try start_tcp_only();
            var exchange = get(&bodies[0]);
            _ = try pool.request(&exchange.request, &exchange.response);
            try pump(&pool);
            try close_transport();
            try goaway_first();
            try testing.expectEqual(.closed, exchange.response.outcome);
            try testing.expectEqual(1, count(.finished));
            try testing.expectEqual(2, count(.open));
        }

        test "decision 124: a cancelled exchange is never sent again" {
            try start_tcp_only();
            var exchange = get(&bodies[0]);
            const id = try pool.request(&exchange.request, &exchange.response);
            try pump(&pool);
            pool.cancel(id);
            try close_transport();
            try testing.expectEqual(null, find(.finished));
            try testing.expectEqual(1, count(.open));
        }
    };
}
