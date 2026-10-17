//! The tests of the server's limit on the request streams a QUIC client opens and then cancels
//! (`quic_connection_h3.zig`, decision 110 as amended). Split out of `quic_connection_test.zig`
//! because a hand-written source file stays at or under 500 lines (CLAUDE.md).
const std = @import("std");
const h3 = @import("h3");
const quic = @import("quic");
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
    for (0..constants.peer_resets_max / batch_len) |_| try cancel_batch(batch_len);
    // The limit's worth of cancelled requests is not past it.
    try testing.expectEqual(constants.peer_resets_max, connection.peer_resets);
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

test "decision 110 as amended: the limit is the configuration's, which the endpoint takes from Limits.peer_resets_max" {
    try support.start();
    support.config.peer_resets_max = batch_len;
    try support.connect();
    try cancel_batch(batch_len);
    try testing.expect(!support.server_failed);
    try cancel_batch(1);
    try testing.expect(support.server_failed);
    try testing.expectEqual(.peer_resets, connection.close_reason().?.limit);
}

/// A request head that declares more content than the stream carries: h3 refuses it once the
/// stream ends (RFC 9114 §4.1.2), after the caller heard of it. Test-only.
const declared = [_]support.Field{.{ .name = "content-length", .value = "5" }};

/// The client sends `count` requests h3 refuses, then the datagrams move. Test-only.
fn broken_batch(count: usize) !void {
    support.fetches_len = 0;
    for (0..count) |_| _ = try support.request_with_fields("POST", "/", &declared);
    try support.pump(1);
}

test "decision 110 as amended: h3 counts each request it refuses, and past the limit closes the connection with H3_EXCESSIVE_LOAD" {
    try support.start();
    support.config.resets_sent_max = batch_len;
    try support.connect();
    try broken_batch(batch_len);
    try testing.expectEqual(batch_len, connection.resets_sent);
    try testing.expect(!support.server_failed);
    try testing.expectEqual(null, connection.close_reason());
    // The caller heard of each request, then of its refusal.
    try testing.expect(support.nth(.cancelled, 0).?.reason.? == .refused);
    try broken_batch(1);
    try testing.expect(support.server_failed);
    try testing.expectEqual(.resets_sent, connection.close_reason().?.limit);
    const close = connection.transport.pending_close.?;
    try testing.expectEqual(.application, close.layer);
    try testing.expectEqual(h3.constants.error_excessive_load, close.error_code);
}

test "decision 110 as amended: the count of refused requests starts again each period, apart from the client's cancels" {
    try support.start();
    try support.connect();
    try broken_batch(batch_len);
    try cancel_batch(1);
    try testing.expectEqual(batch_len, connection.resets_sent);
    try testing.expectEqual(1, connection.peer_resets);
    const period_end_ns = connection.resets_sent_period_start_ns + constants.quic_resets_sent_period_ns;
    support.now_ns = period_end_ns - support.round_ns;
    try broken_batch(1);
    try testing.expectEqual(period_end_ns, support.now_ns);
    try testing.expectEqual(1, connection.resets_sent);
    try testing.expect(!support.server_failed);
}

test "decision 110 as amended: a request refused before the caller heard of it counts too" {
    try support.start();
    try support.connect();
    // RFC 9114 §4.1: a request stream that ends before a whole head is refused with
    // H3_REQUEST_INCOMPLETE, and its head never reaches the caller.
    const fetch = try support.stage_request("GET", "/", &.{}, "", &.{});
    try quic.connection_stream_send.supply(&support.client, .{ .value = fetch.id }, 0, true);
    try support.pump(rounds_few);
    try testing.expectEqual(1, connection.resets_sent);
    try testing.expectEqual(null, support.nth(.cancelled, 0));
    try testing.expectEqual(null, support.nth(.request, 0));
}

test "decision 110 as amended: by default h3 closes the connection past Limits' default of refused requests" {
    try support.start();
    try support.connect();
    for (0..constants.resets_sent_max / batch_len) |_| try broken_batch(batch_len);
    try testing.expectEqual(constants.resets_sent_max, connection.resets_sent);
    try testing.expect(!support.server_failed);
    try broken_batch(1);
    try testing.expectEqual(.resets_sent, connection.close_reason().?.limit);
}
