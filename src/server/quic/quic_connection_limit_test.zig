//! The tests of the server's limit on the request streams a QUIC client opens and then cancels
//! (`quic_connection_h3.zig`, decision 110 as amended). Split out of `quic_connection_test.zig`
//! because a hand-written source file stays at or under 500 lines (CLAUDE.md).
const std = @import("std");
const h3 = @import("h3");
const support = @import("quic_test_support.zig");
const constants = @import("../constants.zig");

const testing = std.testing;
const connection = &support.connection;

const ok: u16 = 200;
/// Requests the client opens and cancels before its datagrams move: one for each fetch the test
/// client holds.
const batch_len: usize = 4;
/// Rounds that carry a request to the server, and its answer or its cancel back.
const rounds_few: usize = 2;

/// The client opens `count` requests and cancels each before its datagrams leave, with a
/// RESET_STREAM and a STOP_SENDING (RFC 9114 §4.1.1), then the datagrams move. Test-only.
fn cancel_batch(count: usize) !void {
    support.fetches_len = 0;
    for (0..count) |_| support.cancel_fetch(try support.request("GET", "/", ""));
    try support.pump(1);
}

test "RFC 9114 §10.5: a client that cancels more requests in one period than the limit closes the connection with H3_EXCESSIVE_LOAD" {
    try support.start();
    try support.connect();
    for (0..constants.quic_peer_reset_rate_max / batch_len) |_| try cancel_batch(batch_len);
    // The limit's worth of cancelled requests is not past it.
    try testing.expectEqual(constants.quic_peer_reset_rate_max, connection.peer_resets);
    try testing.expect(!support.server_failed);
    try testing.expectEqual(null, connection.close_reason());
    try cancel_batch(1);
    try testing.expect(support.server_failed);
    try testing.expectEqual(.peer_resets, connection.close_reason().?.limit);
    const close = connection.transport.pending_close.?;
    try testing.expectEqual(.application, close.layer);
    try testing.expectEqual(h3.constants.error_excessive_load, close.error_code);
}

test "RFC 9114 §4.1.1: a STOP_SENDING, a RESET_STREAM, or both cancel a request, and each request counts once" {
    try support.start();
    try support.connect();
    // The client stops the response to a request the server is answering.
    const stopped = try support.request("GET", "/", "");
    try support.pump(rounds_few);
    try connection.respond(stopped.id, .{ .status = ok, .end = false });
    try support.stop_fetch(stopped);
    try support.pump(rounds_few);
    try testing.expectEqual(stopped.id, support.nth(.cancelled, 0).?.id);
    try testing.expectEqual(1, connection.peer_resets);
    // It cancels a request whose head the server read, with both frames.
    const both = try support.request_open("POST", "/", "x");
    try support.pump(rounds_few);
    support.cancel_fetch(both);
    try support.pump(rounds_few);
    try testing.expectEqual(both.id, support.nth(.cancelled, 1).?.id);
    try testing.expectEqual(2, connection.peer_resets);
    // It resets its side of a request alone.
    const reset = try support.request_open("POST", "/", "x");
    try support.pump(rounds_few);
    try support.reset_fetch(reset);
    try support.pump(rounds_few);
    try testing.expectEqual(3, connection.peer_resets);
    try testing.expect(!support.server_failed);
}

test "decision 110: the count of cancelled requests starts again each period" {
    try support.start();
    try support.connect();
    try cancel_batch(batch_len);
    try testing.expectEqual(batch_len, connection.peer_resets);
    // The server reads a cancel one round before the period ends, which counts in it, and the
    // next at the instant it ends, which starts the next period.
    const period_end_ns = connection.peer_reset_period_start_ns + constants.quic_peer_reset_rate_period_ns;
    support.now_ns = period_end_ns - support.round_ns - support.round_ns;
    try cancel_batch(1);
    try testing.expectEqual(period_end_ns - support.round_ns, support.now_ns);
    try testing.expectEqual(batch_len + 1, connection.peer_resets);
    try cancel_batch(1);
    try testing.expectEqual(period_end_ns, support.now_ns);
    try testing.expectEqual(1, connection.peer_resets);
    try testing.expect(!support.server_failed);
}

test "decision 110: a request the server cancels is not counted against the client" {
    try support.start();
    try support.connect();
    const fetch = try support.request_open("POST", "/", "x");
    try support.pump(rounds_few);
    connection.cancel(fetch.id);
    // RFC 9000 §3.5: the client answers the server's STOP_SENDING with a RESET_STREAM, which is
    // no cancel of its own.
    try support.pump(support.rounds_default);
    try testing.expect(fetch.reset != null);
    try testing.expectEqual(0, connection.peer_resets);
}
