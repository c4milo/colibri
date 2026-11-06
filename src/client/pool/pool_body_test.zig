//! The tests of a streamed request body at the pool (`pool_calls.zig`, `pool_body.zig`, decision
//! 153, design §8 step 39e), over TCP in cleartext h11: what `write_body` refuses, a piece handed
//! before a connection takes the exchange, the `body_taken` event, and the resend rule. The pool
//! sends a streamed request again only before its first `body_taken`.
const std = @import("std");
const h2 = @import("h2");
const support = @import("../connection/connection_test_support.zig");
const constants = @import("../constants.zig");
const pool_module = @import("pool.zig");
const pool_support = @import("pool_test_support.zig");

const testing = std.testing;
const Exchange = support.Exchange;
const Event = pool_module.Event;
const Pool = pool_module.ConnectionPool;

/// The pool the tests drive, its configuration and the events it reported, outside any stack
/// frame. Test-only.
var pool: Pool align(@alignOf(Pool)) = undefined;
var pool_memory: [Pool.memory_bytes(.{})]u8 align(Pool.memory_alignment) = undefined;
var config: pool_module.Config align(@alignOf(pool_module.Config)) = undefined;
var events: [support.events_max]Event align(@alignOf(Event)) = undefined;
var events_len: usize = 0;
var body: [body_len]u8 = undefined;
const body_len: usize = 1024;

/// RFC 9110 §4.2.1: the port of an "http" origin whose URI names none.
const http_port: u16 = 80;
/// An IPv4 host, its four octets alike. Test-only.
const ipv4_len: usize = 4;
const host_octet: u8 = 0x7f;
const loopback: [ipv4_len]u8 = @splat(host_octet);
const addresses = [_]pool_module.Address{pool_module.Address.of(&loopback, 0)};
const first_piece = "hello";
const last_piece = "world";

/// A pool with no QUIC configured, whose TCP connection speaks h11 in cleartext, and nothing
/// requested.
fn start() !void {
    try start_speaking(.h11);
}

/// As `start`, with a connection that speaks `protocol`.
fn start_speaking(protocol: pool_module.Protocol) !void {
    config = .{ .authority = support.authority, .protocols = pool_support.versions_for(&pool, support.only(protocol)) };
    try pool.init(&pool_memory, &config, .{ .addresses = &addresses, .port = http_port }, null);
    fresh_peer();
    events_len = 0;
}

/// The peer of the next connection the pool opens, with nothing read or written either way.
fn fresh_peer() void {
    support.peer_h11.init(.server, .{});
    support.peer_h2.init(.server);
    support.to_peer_len = 0;
    support.to_client_len = 0;
}

/// A streamed PUT, which RFC 9110 §9.2.2 makes idempotent, so the pool may send it again.
fn streamed_put() Exchange {
    return .{ .request = .{ .method = "PUT", .path = "/object", .streamed = .{ .request = true } }, .response = .{ .body = &body } };
}

/// Passes the pool what the peer sent, in calls until one takes nothing and reports nothing,
/// starts the connection an `open` event asks for, and keeps the events.
fn collect() !void {
    // Bounded: each pass consumes an octet or reports an event, and both are finite.
    for (0..support.buffer_len + support.events_max) |_| {
        const input: pool_module.Input = if (support.to_client_len > 0) .{ .stream = .{ .connection = pool_support.connection_of(&pool, .tcp), .bytes = support.to_client[0..support.to_client_len] } } else .none;
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
        if (reported == .open) try pool.start_tcp(pool_support.connection_of(&pool, .tcp), support.stream.random(), 0, null);
    }
    return error.TestUnexpectedResult;
}

/// Writes what the pool's connection owes into the peer's buffer, and reports what that changed.
fn send() !void {
    support.to_peer_len += pool.send_stream(pool_support.connection_of(&pool, .tcp), support.to_peer[support.to_peer_len..], support.now_ns);
    try collect();
}

fn count(tag: std.meta.Tag(Event)) usize {
    var counted: usize = 0;
    for (events[0..events_len]) |reported| counted += @intFromBool(reported == tag);
    return counted;
}

/// The body the h11 peer read, and how many requests it read. Test-only.
var read_body: [body_len]u8 = undefined;
var read_len: usize = 0;
var read_requests: usize = 0;

fn peer_read() !void {
    read_len = 0;
    read_requests = 0;
    var consumed: usize = 0;
    // Bounded: each pass consumes an octet or reports an event, and both are finite.
    for (0..support.to_peer_len + support.events_max) |_| {
        const received = try support.peer_h11.receive(support.to_peer[consumed..support.to_peer_len], &.{});
        consumed += received.consumed;
        switch (received.event orelse break) {
            .request => read_requests += 1,
            .data => |data| {
                @memcpy(read_body[read_len..][0..data.len], data);
                read_len += data.len;
            },
            .end => {},
            .interim, .response, .tunnel => return error.TestUnexpectedResult,
        }
    }
}

test "decision 153: write_body refuses an unknown id, a second piece while one is held, and a piece after the end" {
    try start();
    var put = streamed_put();
    const id = try pool.request(&put.request, &put.response);
    try testing.expectError(error.UnknownRequest, pool.write_body(id + 1, first_piece, false));
    try pool.write_body(id, first_piece, false);
    try testing.expectError(error.PieceHeld, pool.write_body(id, last_piece, true));
    // The piece handed while the exchange waited goes out once the connection takes it.
    try collect();
    try send();
    try testing.expectEqual(1, count(.body_taken));
    try testing.expectEqual(id, events[events_len - 1].body_taken);
    try pool.write_body(id, last_piece, true);
    try testing.expectError(error.PieceHeld, pool.write_body(id, last_piece, true));
    try send();
    try testing.expectEqual(2, count(.body_taken));
    try testing.expectError(error.BodyEnded, pool.write_body(id, last_piece, true));
    try peer_read();
    try testing.expectEqualStrings(first_piece ++ last_piece, read_body[0..read_len]);
    // The exchange ends, and its id is unknown from then on.
    support.to_client_len = (try support.peer_h11.write_response(&support.to_client, 200, "", &.{.{ .name = "Content-Length", .value = "0" }}));
    try collect();
    try testing.expectEqual(.response, put.response.result);
    try testing.expectError(error.UnknownRequest, pool.write_body(id, last_piece, true));
}

test "decision 153 ruling 3: a streamed request whose connection closed before its first take goes out again, piece and all" {
    try start();
    var put = streamed_put();
    const id = try pool.request(&put.request, &put.response);
    try pool.write_body(id, first_piece, true);
    try collect();
    // The connection closes before it wrote the request.
    pool.transport_closed(pool_support.connection_of(&pool, .tcp));
    fresh_peer();
    try collect();
    try testing.expectEqual(2, count(.open));
    try testing.expectEqual(0, count(.finished));
    try send();
    try testing.expectEqual(1, count(.body_taken));
    try peer_read();
    try testing.expectEqual(1, read_requests);
    try testing.expectEqualStrings(first_piece, read_body[0..read_len]);
}

test "decision 153 ruling 3: a streamed request whose connection closed after a take is never sent again" {
    try start();
    var put = streamed_put();
    const id = try pool.request(&put.request, &put.response);
    try pool.write_body(id, first_piece, false);
    try collect();
    try send();
    try testing.expectEqual(1, count(.body_taken));
    // RFC 9110 §9.2.2 would let the pool send a PUT again, since none of its response arrived,
    // but the program may have reused the piece's memory.
    pool.transport_closed(pool_support.connection_of(&pool, .tcp));
    fresh_peer();
    try collect();
    try testing.expectEqual(.closed, put.response.result);
    try testing.expectEqual(1, count(.finished));
    try testing.expectEqual(1, count(.open));
}

test "decision 153: cancel gives the held piece back with the exchange" {
    try start();
    var put = streamed_put();
    const id = try pool.request(&put.request, &put.response);
    try pool.write_body(id, first_piece, false);
    pool.cancel(id, support.now_ns);
    try testing.expectError(error.UnknownRequest, pool.write_body(id, last_piece, true));
    try collect();
    try testing.expectEqual(0, count(.body_taken));
    try testing.expectEqual(0, count(.finished));
}

test "decision 153 ruling 3: a streamed request refused after a take ends closed, and is never sent again" {
    try start_speaking(.h2);
    var put = streamed_put();
    const id = try pool.request(&put.request, &put.response);
    try collect();
    // RFC 9113 §3.4: the preface and the SETTINGS go both ways before the request does.
    for (0..rounds) |_| {
        try send();
        try support.peer_h2_read();
        try collect();
    }
    try pool.write_body(id, first_piece, false);
    try send();
    try support.peer_h2_read();
    try testing.expectEqual(1, count(.body_taken));
    // RFC 9113 §8.7: REFUSED_STREAM says the server processed none of the request, yet the program
    // may have reused the piece's memory.
    try support.peer_h2.reset_stream(1, h2.constants.protocol.error_refused_stream);
    support.peer_h2_owe();
    try collect();
    try testing.expectEqual(.closed, put.response.result);
    try testing.expectEqual(1, count(.finished));
    try testing.expectEqual(1, count(.open));
}

/// Rounds of moving octets both ways that start an h2 connection.
const rounds: usize = 4;

/// Where each piece of a streamed response lands. Test-only.
var piece: [piece_len]u8 = undefined;
const piece_len: usize = 4;
const alphabet = "abcdefghijklmnopqrstuvwxyz";

/// A streamed GET, whose response comes in pieces of four octets.
fn streamed_get() Exchange {
    return .{ .request = .{ .method = "GET", .path = "/stream", .streamed = .{ .response = true } }, .response = .{ .body = &piece } };
}

test "decision 153 ruling 7: the pool reports a streamed response's head, then each piece, and finishes after the last release" {
    try start();
    var get = streamed_get();
    const id = try pool.request(&get.request, &get.response);
    try collect();
    try send();
    try peer_read();
    try support.peer_h11_answer(200, &.{.{ .name = "Content-Length", .value = "26" }}, alphabet);
    var received: [alphabet.len]u8 = undefined;
    var received_len: usize = 0;
    for (0..alphabet.len) |_| {
        const before = events_len;
        try collect();
        const last = events[events_len - 1];
        if (last == .finished) break;
        try testing.expect(events_len > before);
        try testing.expectEqual(id, last.body.id);
        @memcpy(received[received_len..][0..last.body.len], piece[0..last.body.len]);
        received_len += last.body.len;
        // Decision 153 ruling 7: the pool reads no more of the response while the piece is held.
        const held = pool.receive(.{ .stream = .{ .connection = pool_support.connection_of(&pool, .tcp), .bytes = support.to_client[0..support.to_client_len] } }, support.now_ns);
        try testing.expectEqual(0, held.consumed);
        try testing.expectEqual(null, held.event);
        pool.release_body(id);
    }
    // The head came first, and once.
    try testing.expectEqual(1, count(.headers));
    for (events[0..events_len]) |reported| {
        if (reported == .body) return error.TestUnexpectedResult;
        if (reported == .headers) {
            try testing.expectEqual(id, reported.headers);
            break;
        }
    }
    try testing.expectEqualStrings(alphabet, received[0..received_len]);
    try testing.expectEqual(1, count(.finished));
    try testing.expectEqual(.response, get.response.result);
    // An id the pool no longer holds changes nothing.
    pool.release_body(id);
}

test "decision 153 ruling 7: a streamed response refused after its head ends closed, and is never sent again" {
    try start_speaking(.h2);
    var get = streamed_get();
    _ = try pool.request(&get.request, &get.response);
    try collect();
    for (0..rounds) |_| {
        try send();
        try support.peer_h2_read();
        try collect();
    }
    support.to_client_len += try support.peer_h2.write_response(support.to_client[support.to_client_len..], 1, 200, &.{}, false);
    try collect();
    try testing.expectEqual(1, count(.headers));
    // RFC 9113 §6.8: the server takes no new stream, so the connection takes no new exchange.
    // RFC 9113 §8.7 then lets a client send a refused request again on another connection, but
    // the program has its head.
    support.peer_h2.shutdown(h2.constants.protocol.error_no_error);
    support.peer_h2_owe();
    try support.peer_h2.reset_stream(1, h2.constants.protocol.error_refused_stream);
    support.peer_h2_owe();
    try collect();
    try testing.expectEqual(.closed, get.response.result);
    // The exchange never moved, so the head the program had is still in its response.
    try testing.expectEqual(200, get.response.status);
    try testing.expectEqual(1, count(.finished));
    try testing.expectEqual(1, count(.open));
}

test "decision 153 ruling 7: write_body on an exchange the pool ended returns BodyStopped" {
    try start();
    var first = streamed_put();
    var second = streamed_put();
    const first_id = try pool.request(&first.request, &first.response);
    const second_id = try pool.request(&second.request, &second.response);
    // The connect fails, so no connection is left to take either exchange. The pool ends both,
    // and reports the end of one a call.
    for (0..support.events_max) |_| {
        const reported = pool.receive(.none, support.now_ns).event orelse return error.TestUnexpectedResult;
        if (reported == .open) pool.transport_closed(reported.open.connection);
        if (reported == .finished) break;
    }
    try testing.expectError(error.UnknownRequest, pool.write_body(first_id, first_piece, false));
    // RFC 9113 §8.7: no server processed the exchange, and no more of it goes out.
    try testing.expectError(error.BodyStopped, pool.write_body(second_id, first_piece, false));
    try testing.expectEqual(.refused, second.response.result);
}

/// The least output a `send_stream` that writes nothing finds the connection blocked with
/// (decision 125). Test-only.
var blocked_output: [constants.limits.stream_output_len_min]u8 = undefined;

/// Requires the pool's connection to owe nothing: a `send_stream` writes nothing, and no `send`
/// follows until a call of the program gives it a debt.
fn expect_blocked() !void {
    try testing.expectEqual(0, pool.send_stream(pool_support.connection_of(&pool, .tcp), &blocked_output, support.now_ns));
    events_len = 0;
    try collect();
    try testing.expectEqual(0, count(.send));
}

test "decision 125: write_body gives a connection that found nothing to send its next send" {
    try start();
    var put = streamed_put();
    const id = try pool.request(&put.request, &put.response);
    try pool.write_body(id, first_piece, false);
    try collect();
    try send();
    try testing.expectEqual(1, count(.body_taken));
    try expect_blocked();
    try pool.write_body(id, last_piece, true);
    try collect();
    try testing.expectEqual(1, count(.send));
}

/// Where each piece lands in the test of a release's send: one full DATA frame (RFC 9113 §4.2).
var frame_piece: [frame_piece_len]u8 = undefined;
const frame_piece_len: usize = 16_384;
const frame_content: [frame_piece_len]u8 = @splat('x');

/// Writes one full DATA frame on stream 1 from the h2 peer, which leaves the stream open.
fn peer_frame() !void {
    const sent = try support.peer_h2.write_data(support.to_client[support.to_client_len..], 1, &frame_content, false);
    try testing.expectEqual(frame_piece_len, sent.consumed);
    support.to_client_len += sent.written;
}

test "decision 125: release_body gives a connection that found nothing to send its WINDOW_UPDATE's send" {
    try start_speaking(.h2);
    var get: Exchange = .{ .request = .{ .method = "GET", .path = "/stream", .streamed = .{ .response = true } }, .response = .{ .body = &frame_piece } };
    const id = try pool.request(&get.request, &get.response);
    try collect();
    for (0..rounds) |_| {
        try send();
        try support.peer_h2_read();
        try collect();
    }
    support.to_client_len += try support.peer_h2.write_response(support.to_client[support.to_client_len..], 1, 200, &.{}, false);
    try peer_frame();
    try peer_frame();
    try collect();
    try testing.expectEqual(1, count(.body));
    pool.release_body(id);
    try collect();
    try testing.expectEqual(2, count(.body));
    // The connection's WINDOW_UPDATE went out at receipt, and the stream's waits for the release.
    try send();
    try expect_blocked();
    // RFC 9113 §6.9.1: the two pieces pass the threshold, so the release owes a WINDOW_UPDATE.
    pool.release_body(id);
    try collect();
    try testing.expectEqual(1, count(.send));
}
