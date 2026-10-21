//! The tests of a pool's connection handles and its `send` event (decision 125), over TCP in
//! cleartext h11 (`pool_handle.zig`, `pool_events.zig`). The peer is h11's server side in the
//! same process, or a response the test writes itself.
const std = @import("std");
const support = @import("../connection/connection_test_support.zig");
const pool_module = @import("pool.zig");
const pool_support = @import("pool_test_support.zig");

const testing = std.testing;
const Exchange = support.Exchange;
const Event = pool_module.Event;
const Pool = pool_module.Pool;
const ConnectionHandle = pool_module.ConnectionHandle;

/// The pool the tests drive, its memory, its configuration and the events it reported, outside
/// any stack frame. Test-only.
var pool: Pool align(@alignOf(Pool)) = undefined;
var pool_memory: [Pool.memory_bytes(.{})]u8 align(Pool.memory_alignment) = undefined;
var config: pool_module.Config align(@alignOf(pool_module.Config)) = undefined;
var events: [support.events_max]Event align(@alignOf(Event)) = undefined;
var events_len: usize = 0;
var bodies: [bodies_count][body_len]u8 = undefined;
const bodies_count: usize = 2;
const body_len: usize = 64;

const ok: u16 = 200;
/// RFC 9110 §4.2.1: the port of an "http" origin whose URI names none.
const http_port: u16 = 80;
/// An IPv4 host, its four octets alike. Test-only.
const ipv4_len: usize = 4;
const host_octet: u8 = 0x7f;
const loopback: [ipv4_len]u8 = @splat(host_octet);
const addresses = [_]pool_module.Address{pool_module.Address.of(&loopback, 0)};
const content_length_5: []const support.Header = &.{.{ .name = "Content-Length", .value = "5" }};

/// A pool whose TCP connection speaks h11 in cleartext, with `exchange` taken and its connection
/// started. Returns the handle the `open` named.
fn start(exchange: *Exchange) !ConnectionHandle {
    config = .{ .authority = support.authority, .protocols = .{ .h2 = false, .h3 = false } };
    try pool.init(&pool_memory, &config, .{ .addresses = &addresses, .port = http_port }, .{}, null);
    support.peer_h11.init(.server, .{});
    support.peer_requests = 0;
    support.to_peer_len = 0;
    support.to_client_len = 0;
    events_len = 0;
    _ = try pool.request(&exchange.request, &exchange.response);
    try collect();
    return find(.open, 0).?.open.connection;
}

/// Passes the pool what the peer sent, in calls until one takes nothing and reports nothing, with
/// `.none` once no octet is left. Starts the connection an `open` asks for, and keeps the events.
fn collect() !void {
    // Bounded: each pass consumes an octet or reports an event, and both are finite.
    for (0..support.buffer_len + support.events_max) |_| {
        const connection = pool_support.connection_of(&pool, .tcp);
        const octets = support.to_client[0..support.to_client_len];
        const input: pool_module.Input = if (octets.len > 0) .{ .stream = .{ .connection = connection, .bytes = octets } } else .none;
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
        if (reported == .open) try pool.start_tcp(reported.open.connection, support.stream.random(), 0, null);
    }
    return error.TestUnexpectedResult;
}

/// Writes what the connection `connection` owes into the peer's buffer, and returns how much.
fn send(connection: ConnectionHandle) usize {
    const written = pool.send_stream(connection, support.to_peer[support.to_peer_len..], support.now_ns);
    support.to_peer_len += written;
    return written;
}

/// The `n`th event of `tag` the pool reported, counted from 0, or null.
fn find(tag: std.meta.Tag(Event), n: usize) ?Event {
    var seen: usize = 0;
    for (events[0..events_len]) |reported| {
        if (reported != tag) continue;
        if (seen == n) return reported;
        seen += 1;
    }
    return null;
}

fn count(tag: std.meta.Tag(Event)) usize {
    var counted: usize = 0;
    for (events[0..events_len]) |reported| counted += @intFromBool(reported == tag);
    return counted;
}

fn get() Exchange {
    return .{ .request = .{ .method = "GET", .path = "/" }, .response = .{ .body = &bodies[0] } };
}

test "decision 125: a pool says send once for each debt, and not again for a debt the peer holds back" {
    var first: Exchange = .{ .request = .{ .method = "POST", .path = "/" }, .response = .{ .body = &bodies[0] } };
    const connection = try start(&first);
    // The connection owes the first request, once its socket connected.
    try testing.expectEqual(connection, find(.send, 0).?.send);
    try testing.expectEqual(1, count(.send));
    try testing.expect(send(connection) > 0);
    // Nothing more is owed, so a call with no octets reports nothing.
    try testing.expectEqual(null, pool.receive(.none, support.now_ns).event);
    // RFC 9112 §9.3.2: h11 holds a request back until a POST before it is answered (decision 88).
    var second: Exchange = .{ .request = .{ .method = "GET", .path = "/" }, .response = .{ .body = &bodies[1] } };
    _ = try pool.request(&second.request, &second.response);
    try collect();
    try testing.expectEqual(connection, find(.send, 1).?.send);
    try testing.expectEqual(0, send(connection));
    // The connection writes nothing, so the pool says no `send` until it reads octets.
    try collect();
    try testing.expectEqual(2, count(.send));
    try support.peer_h11_read();
    try support.peer_h11_answer(ok, content_length_5, "hello");
    try collect();
    try testing.expectEqual(.response, first.response.outcome);
    // The answer let the second request go, and the pool says `send` for it.
    try testing.expectEqual(3, count(.send));
    try testing.expect(send(connection) > 0);
    try support.peer_h11_read();
    try testing.expectEqual(2, support.peer_requests);
}

test "decision 125: a handle names nothing once its connection's close went out" {
    var first = get();
    var second: Exchange = .{ .request = .{ .method = "GET", .path = "/" }, .response = .{ .body = &bodies[1] } };
    const old = try start(&first);
    _ = send(old);
    _ = try pool.request(&second.request, &second.response);
    // RFC 9112 §9.6: a response that says "close" ends the connection after it, so the second
    // exchange goes to the slot's next connection.
    const response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello";
    @memcpy(support.to_client[0..response.len], response);
    support.to_client_len = response.len;
    try collect();
    try testing.expectEqual(old, find(.close, 0).?.close);
    const next = find(.open, 1).?.open.connection;
    try testing.expectEqual(old.slot, next.slot);
    try testing.expectEqual(old.generation +% 1, next.generation);
    // Each call with the old handle changes nothing, and its octets are dropped.
    try testing.expectEqual(0, pool.send_stream(old, &support.to_peer, support.now_ns));
    var stale = "HTTP/1.1 200 OK\r\n".*;
    const dropped = pool.receive(.{ .stream = .{ .connection = old, .bytes = &stale } }, support.now_ns);
    try testing.expectEqual(stale.len, dropped.consumed);
    try testing.expectEqual(null, pool.take_ticket(old));
    pool.transport_closed(old);
    try testing.expectEqual(pool_module.Phase.open, pool.phase(pool_support.slot_of(pool, .tcp)));
    // The next connection carries the second exchange.
    try testing.expectEqual(next, find(.send, count(.send) - 1).?.send);
}
