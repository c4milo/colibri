//! The tests of a pool over h2 in cleartext (decision 125): a connection that an upload blocked
//! on h2's flow control (RFC 9113 §6.9) gets its next `send` from a call of the program that gives
//! it a debt it can write, and exchanges past one connection's slots wait for a slot. The peer is
//! h2's server side in the same process, and it reads nothing, so it opens no window.
const std = @import("std");
const support = @import("../connection/connection_test_support.zig");
const pool_module = @import("pool.zig");
const pool_support = @import("pool_test_support.zig");
const constants = @import("../constants.zig");

const testing = std.testing;
const Exchange = support.Exchange;
const Event = pool_module.Event;
const ConnectionPool = pool_module.ConnectionPool;
const ConnectionHandle = pool_module.ConnectionHandle;

/// The pool the tests drive, its memory, its configuration and the events it reported, outside
/// any stack frame. Test-only.
var pool: ConnectionPool align(@alignOf(ConnectionPool)) = undefined;
var pool_memory: [ConnectionPool.memory_bytes(.{})]u8 align(ConnectionPool.memory_alignment) = undefined;
var config: pool_module.Config align(@alignOf(pool_module.Config)) = undefined;
var events: [support.events_max]Event align(@alignOf(Event)) = undefined;
var events_len: usize = 0;
var bodies: [bodies_count][body_len]u8 = undefined;
const bodies_count: usize = 2;
const body_len: usize = 64;
/// An upload longer than the initial window of 65,535 octets (RFC 9113 §6.9.2). Test-only.
var upload: [upload_len]u8 = undefined;
const upload_len: usize = 70_000;
/// The upload's exchange id. Test-only.
var post_id: pool_module.RequestId align(@alignOf(pool_module.RequestId)) = 0;
/// Calls of `send_stream` that an upload takes at most until the window is spent.
const sends_max: usize = 16;

const https_port: u16 = 443;
/// An IPv4 host, its four octets alike. Test-only.
const ipv4_len: usize = 4;
const host_octet: u8 = 0x7f;
const loopback: [ipv4_len]u8 = @splat(host_octet);
const addresses = [_]pool_module.Address{pool_module.Address.of(&loopback, 0)};

/// Reports every event the pool owes, starts the connection an `open` asks for, and keeps the
/// events. The peer sends nothing, so each call passes no octets.
fn collect() !void {
    // Bounded: each pass reports an event, and they are finite.
    for (0..support.events_max) |_| {
        const reported = pool.receive(.none, support.now_ns).event orelse return;
        if (events_len == events.len) return error.TestUnexpectedResult;
        events[events_len] = reported;
        events_len += 1;
        if (reported == .open) try pool.start_tcp(reported.open.connection, support.stream.random(), 0, null);
    }
    return error.TestUnexpectedResult;
}

fn count(tag: std.meta.Tag(Event)) usize {
    var counted: usize = 0;
    for (events[0..events_len]) |reported| counted += @intFromBool(reported == tag);
    return counted;
}

/// Writes what `connection` owes into the peer's buffer, and returns how much.
fn send(connection: ConnectionHandle) usize {
    const written = pool.send_stream(connection, support.to_peer[support.to_peer_len..], support.now_ns);
    support.to_peer_len += written;
    return written;
}

/// Sends what the upload's connection owes until a call writes nothing: the window is spent.
fn spend_window(connection: ConnectionHandle) !void {
    for (0..sends_max) |_| {
        try collect();
        if (send(connection) == 0) return;
    }
    return error.TestUnexpectedResult;
}

/// A pool whose TCP connection speaks h2 in cleartext with prior knowledge, which uploads
/// `upload` until the window is spent. Returns the connection's handle.
fn start_blocked(post: *Exchange) !ConnectionHandle {
    config = .{ .authority = support.authority, .protocols = .{ .h11 = false, .h3 = false } };
    try pool.init(&pool_memory, &config, .{ .addresses = &addresses, .port = https_port }, null);
    support.to_peer_len = 0;
    support.to_client_len = 0;
    events_len = 0;
    @memset(&upload, 'x');
    post.* = .{ .request = .{ .method = "POST", .path = "/", .body = &upload }, .response = .{ .body = &bodies[0] } };
    post_id = try pool.request(&post.request, &post.response);
    try collect();
    const connection = pool_support.connection_of(&pool, .tcp);
    try spend_window(connection);
    try testing.expect(post.response.body_sent < upload.len);
    // The connection is blocked: a call with no octets reports no `send`.
    const sends = count(.send);
    try collect();
    try testing.expectEqual(sends, count(.send));
    return connection;
}

test "decision 125: a request gives a blocked h2 connection its next send" {
    var post: Exchange = undefined;
    const connection = try start_blocked(&post);
    const sends = count(.send);
    // RFC 9113 §6.9: flow control holds DATA alone, so a new request's HEADERS may go.
    var get: Exchange = .{ .request = .{ .method = "GET", .path = "/" }, .response = .{ .body = &bodies[1] } };
    _ = try pool.request(&get.request, &get.response);
    try collect();
    try testing.expectEqual(sends + 1, count(.send));
    try testing.expect(send(connection) > 0);
}

test "decision 125: a cancel gives a blocked h2 connection its next send, for its RST_STREAM" {
    var post: Exchange = undefined;
    const connection = try start_blocked(&post);
    const sends = count(.send);
    // RFC 9113 §8.1: a client that abandons a request resets its stream.
    pool.cancel(post_id);
    try collect();
    try testing.expectEqual(sends + 1, count(.send));
    try testing.expect(send(connection) > 0);
}

/// More requests than the slots of one connection hold, their memory and their bodies.
/// Test-only.
const many_count: u16 = constants.requests_max + many_waiting;
const many_waiting: u16 = 4;
var many_memory: [ConnectionPool.memory_bytes(.{ .requests = many_count })]u8 align(ConnectionPool.memory_alignment) = undefined;
var many_bodies: [many_count][body_len]u8 = undefined;
var many: [many_count]Exchange align(@alignOf(Exchange)) = undefined;

/// The exchanges that wait for a connection. Test-only.
fn waiting() usize {
    var counted: usize = 0;
    for (pool.entries) |entry| counted += @intFromBool(entry.stage == .waiting);
    return counted;
}

test "decision 125: exchanges past an h2 connection's slots wait for a slot, and no other connection opens" {
    config = .{ .authority = support.authority, .protocols = .{ .h11 = false, .h3 = false }, .requests = many_count };
    try pool.init(&many_memory, &config, .{ .addresses = &addresses, .port = https_port }, null);
    support.to_peer_len = 0;
    events_len = 0;
    var first: pool_module.RequestId = 0;
    for (&many, &many_bodies, 0..) |*exchange, *body, index| {
        exchange.* = .{ .request = .{ .method = "GET", .path = "/" }, .response = .{ .body = body } };
        const id = try pool.request(&exchange.request, &exchange.response);
        if (index == 0) first = id;
    }
    try collect();
    // RFC 9113 §9.1: one h2 connection, whose slots take `requests_max` requests.
    try testing.expectEqual(1, count(.open));
    try testing.expectEqual(many_count - constants.requests_max, waiting());
    // A cancel frees a slot, which the oldest waiting exchange takes.
    pool.cancel(first);
    try collect();
    try testing.expectEqual(many_count - constants.requests_max - 1, waiting());
    try testing.expectEqual(1, count(.open));
}
