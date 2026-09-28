//! More tests of the client over QUIC (`quic_connection.zig`): what a cancel, a response past the
//! caller's memory, a shutdown, a ticket, another protocol and the end of the connection leave
//! each exchange. Split out of `quic_connection_test.zig` for length.
const std = @import("std");
const quic = @import("quic");
const h3 = @import("h3");
const support = @import("quic_test_support.zig");
const event = @import("../event.zig");

const testing = std.testing;
const connection = &support.connection;
const HttpExchange = support.HttpExchange;

/// Where the tests' exchanges put their responses, outside any stack frame. Test-only.
var bodies: [bodies_count][body_len]u8 = undefined;
const bodies_count: usize = 2;
const body_len: usize = 1024;
/// Rounds that run past the closing period, three times the Probe Timeout (RFC 9000 §10.2).
const closing_rounds: usize = 128;

fn get(body: []u8) HttpExchange {
    return .{ .method = "GET", .path = "/dns-query", .body = body };
}

test "RFC 9114 §4.1.1: content past the caller's memory ends the exchange, and the server stops" {
    try support.start(&support.alpn_h3, &support.alpn_h3, false);
    // The response never ends, so only the client's STOP_SENDING stops it.
    support.answer_open = true;
    var exchange = get(bodies[0][0..2]);
    _ = try connection.request(&exchange);
    try support.pump(support.rounds_default);
    try testing.expectEqual(.too_large, exchange.outcome);
    // RFC 9000 §3.5: the server resets the response it was sending, which closes its stream, and
    // the exchange is reported once the client's stream closed too.
    try testing.expect(support.server.streams.lookup(.{ .value = 0 }) != .live);
    try testing.expectEqual(&exchange, support.find(.finished).?.finished.exchange);
}

test "RFC 9114 §4.1.1: a cancelled exchange's stream is reset, and no event reports it" {
    try support.start(&support.alpn_h3, &support.alpn_h3, false);
    support.server_answers = false;
    var exchange = get(&bodies[0]);
    const id = try connection.request(&exchange);
    try support.pump(support.rounds_default);
    connection.cancel(id);
    try support.pump(support.rounds_default);
    // RFC 9000 §3.5: the client's STOP_SENDING has the server reset the response it never sent,
    // which closes its stream.
    try testing.expect(support.server.streams.lookup(.{ .value = 0 }) != .live);
    try testing.expectEqual(null, support.find(.finished));
    try testing.expectEqual(.pending, exchange.outcome);
}

/// Content past the server's stream window, so its stream still sends after the response ends
/// (RFC 9000 §4.1). Test-only.
var upload: [upload_len]u8 = undefined;
const upload_len: usize = 600_000;

test "RFC 9114 §4.1.1: a cancel after the response resets the stream still sending the content" {
    try support.start(&support.alpn_h3, &support.alpn_h3, false);
    support.answer_early = true;
    @memset(&upload, 'z');
    var post: HttpExchange = .{ .method = "POST", .path = "/upload", .content = &upload, .body = &bodies[0] };
    const id = try connection.request(&post);
    // Bounded: the server answers once the request's head arrives.
    for (0..support.rounds_default) |_| {
        if (post.outcome != .pending) break;
        try support.pump(1);
    }
    try testing.expectEqual(.response, post.outcome);
    try testing.expect(support.answers[0].received < upload_len);
    connection.cancel(id);
    try support.pump(support.rounds_default);
    // RFC 9000 §3.1: the RESET_STREAM ends the request's part, so no side's stream reads the
    // caller's content again, and the server's stream closes.
    try testing.expect(support.server.streams.lookup(.{ .value = 0 }) != .live);
    try testing.expect(connection.transport.streams.lookup(.{ .value = 0 }) != .live);
    try testing.expectEqual(null, support.find(.finished));
}

test "RFC 9114 §5.2: a shut-down connection closes with H3_NO_ERROR after its last exchange" {
    try support.start(&support.alpn_h3, &support.alpn_h3, false);
    var exchange = get(&bodies[0]);
    _ = try connection.request(&exchange);
    connection.shutdown();
    var closing_seen = false;
    for (0..closing_rounds) |_| {
        try support.pump(1);
        if (support.find(.closed) == null) continue;
        // RFC 9000 §10.2: the caller closes the flow only once the closing period has run.
        const period_over = connection.transport.termination.state == .closed;
        try testing.expectEqual(period_over, connection.should_close());
        if (!period_over) closing_seen = true;
    }
    try testing.expect(closing_seen);
    try testing.expectEqual(.response, exchange.outcome);
    try testing.expect(support.find(.draining) != null and support.find(.closed) != null);
    // RFC 9000 §10.2: the server read the client's CONNECTION_CLOSE.
    try testing.expect(support.server.termination.state != .active);
    try testing.expect(connection.should_close());
    // It ended after its last exchange, not on a failure, and closing its transport keeps it so.
    connection.transport_closed();
    try testing.expect(!connection.failed);
}

test "RFC 9846 §4.6.1: a ticket the server issues is reported, and take_ticket hands it over once" {
    try support.start(&support.alpn_h3, &support.alpn_h3, true);
    try support.pump(support.rounds_default);
    try testing.expect(support.find(.ticket) != null);
    var ticket = connection.take_ticket().?;
    defer ticket.wipe();
    try testing.expect(ticket.identity_len > 0);
    try testing.expectEqual(null, connection.take_ticket());
}

test "RFC 9114 §3.1: a handshake that selects another protocol ends the connection before any exchange" {
    const offered = [_][]const u8{ "hq-interop", "h3" };
    try support.start(&offered, &support.alpn_other, false);
    var exchange = get(&bodies[0]);
    _ = try connection.request(&exchange);
    try support.pump(support.rounds_default);
    try testing.expectEqual(null, support.find(.connected));
    try testing.expectEqual(.refused, exchange.outcome);
    try testing.expect(support.find(.closed) != null);
    try testing.expectEqual(0, support.answers_len);
}

test "RFC 9204 §4.5.4: a marked path and field line go out as literals with the N bit, and nothing else changes" {
    try support.start(&support.alpn_h3, &support.alpn_h3, false);
    support.server_answers = false;
    const path = "/dns-query?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE";
    const fields = [_]event.Field{ .{ .name = "authorization", .value = "secret" }, .{ .name = "accept", .value = "application/dns-message" } };
    const marks = [_]bool{ true, false };
    var marked: HttpExchange = .{ .method = "GET", .path = path, .fields = &fields, .never_indexed = .{ .path = true, .fields = &marks }, .body = &bodies[0] };
    var plain: HttpExchange = .{ .method = "GET", .path = path, .fields = &fields, .body = &bodies[1] };
    _ = try connection.request(&marked);
    _ = try connection.request(&plain);
    try support.pump(support.rounds_default);
    const marked_frames = connection.streams[0].prefix[0..connection.streams[0].prefix_len];
    const plain_frames = connection.streams[1].prefix[0..connection.streams[1].prefix_len];
    try testing.expectEqual(plain_frames.len, marked_frames.len);
    var differing: usize = 0;
    for (marked_frames, plain_frames) |with, without| {
        if (with == without) continue;
        differing += 1;
        // RFC 9204 §4.5.4: the pattern 01, then N, then T; the N bit is 0x20.
        try testing.expectEqual(n_bit, with ^ without);
        try testing.expect(with & n_bit != 0);
    }
    // The path's line and the marked field line; the unmarked one is the same in both.
    try testing.expectEqual(2, differing);
}

/// RFC 9204 §4.5.4: the N bit of a literal field line with a name reference. Test-only.
const n_bit: u8 = 0x20;

test "RFC 9000 §10.2: the server's CONNECTION_CLOSE ends the exchange awaiting its response" {
    try support.start(&support.alpn_h3, &support.alpn_h3, false);
    support.server_answers = false;
    var exchange = get(&bodies[0]);
    _ = try connection.request(&exchange);
    try support.pump(support.rounds_default);
    quic.connection_close.owe(&support.server, .{ .layer = .application, .error_code = h3.constants.error_internal, .frame_type = null, .reason = "" });
    try support.pump(support.rounds_default);
    try testing.expectEqual(.closed, exchange.outcome);
    try testing.expect(support.find(.closed) != null);
}

test "the transport's close ends a written exchange closed and a waiting one refused, once" {
    try support.start(&support.alpn_h3, &support.alpn_h3, false);
    support.server_answers = false;
    var written = get(&bodies[0]);
    _ = try connection.request(&written);
    try support.pump(support.rounds_default);
    var waiting = get(&bodies[1]);
    _ = try connection.request(&waiting);
    connection.transport_closed();
    try support.collect();
    try testing.expectEqual(.closed, written.outcome);
    try testing.expectEqual(.refused, waiting.outcome);
    try testing.expect(support.find(.closed) != null);
    try testing.expect(connection.should_close());
    connection.transport_closed();
    try testing.expectError(error.ConnectionClosed, connection.request(&waiting));
}

test "RFC 9000 §10.2: an active connection that fails owes its CONNECTION_CLOSE, with INTERNAL_ERROR" {
    try support.start(&support.alpn_h3, &support.alpn_h3, false);
    try support.pump(support.rounds_default);
    try testing.expect(!quic.connection_close.owes(&connection.transport));
    // A failure no h3 or QUIC rule closed, as the loss timer's refusals are.
    connection.fail();
    try testing.expect(connection.failed);
    try testing.expect(quic.connection_close.owes(&connection.transport));
    try support.pump(support.rounds_default);
    try testing.expect(support.server.termination.state != .active);
}
