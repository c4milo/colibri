//! The tests of the server's body deadlines over QUIC (`quic_body.zig`, decision 110 as amended):
//! a request body under the minimum rate or past its cap, with no response, with one begun and
//! with one ended, and the bodies of a connection together.
const std = @import("std");
const assert = std.debug.assert;
const quic = @import("quic");
const h3 = @import("h3");
const support = @import("quic_test_support.zig");
const tcp_support = @import("../connection/connection_test_support.zig");
const constants = @import("../constants.zig");
const quic_deadline = @import("quic_deadline.zig");
const internal = @import("quic_connection_internal.zig");
const Deadline = @import("../deadline.zig").Deadline;

const testing = std.testing;
const connection = &support.connection;

const ok: u16 = 200;
/// RFC 9110 §15.5.9: 408 (Request Timeout).
const request_timeout: u16 = 408;
/// Rounds that carry a request to the server, and its answer back.
const rounds_few: usize = 2;
/// What a window owes at the default rate, and content for four windows.
const quota: usize = 10_240;
const windows: usize = 4;
const content: [windows * quota]u8 = @splat('c');
/// From the start of a body's wait to the end of its first window.
const first_window_ns: u64 = constants.rate_grace_ns + constants.rate_window_ns;
/// A cap that passes inside a body's second window.
const cap_seconds: u64 = 25;
const cap_ns: u64 = cap_seconds * constants.nanoseconds_per_second;
/// How long after the first body a test opens a second one.
const stagger_seconds: u64 = 15;
const stagger_ns: u64 = stagger_seconds * constants.nanoseconds_per_second;

fn connected() !void {
    try support.start();
    try support.connect();
}

/// A POST whose head and DATA frame header reach the server, and none of its content.
fn post_holding() !*support.Fetch {
    const fetch = try support.stage_request("POST", "/", &.{}, &content, &.{});
    try send_content(fetch, 0);
    try support.pump(rounds_few);
    return fetch;
}

/// The client sends `fetch`'s content up to its first `len` octets.
fn send_content(fetch: *const support.Fetch, len: usize) !void {
    try quic.connection_stream_send.supply(&support.client, .{ .value = fetch.id }, fetch.prefix_len + len, false);
}

/// The instant the wait for `fetch`'s body started at.
fn since_ns(fetch: *const support.Fetch) u64 {
    const record = connection.requests.of(fetch.id).?;
    const body = connection.bodies.entries[connection.requests.index_of(record)];
    assert(body.waiting);
    return body.since_ns;
}

/// Has the server see `now_ns`, and the test's clock with it, and keeps what it reports.
fn server_at(now_ns: u64) void {
    internal.on_instant(connection, now_ns);
    support.now_ns = now_ns;
    support.collect();
}

/// The deadline the `n`th `cancelled` event names, or null when there is no such event.
fn cancelled_for(n: usize) ?Deadline {
    const entry = support.nth(.cancelled, n) orelse return null;
    return entry.reason.?.deadline;
}

fn is_no_error(code: u64) bool {
    return code == h3.constants.error_no_error or h3.constants.is_reserved(code);
}

test "RFC 9110 §15.5.9: a body under the minimum rate gets a 408 when its first window ends, and the connection goes on" {
    try connected();
    const slow = try post_holding();
    const at_ns = since_ns(slow) + first_window_ns;
    try testing.expectEqual(at_ns, quic_deadline.soonest(connection).?);
    server_at(at_ns - 1);
    try testing.expectEqual(null, cancelled_for(0));
    internal.on_instant(connection, at_ns);
    // RFC 9114 §4.1: after the response, the server asks the client to stop with H3_NO_ERROR.
    const stream = connection.transport.streams.lookup(.{ .value = slow.id }).live;
    try testing.expect(stream.stop_sending.owed and is_no_error(stream.stop_error_code));
    server_at(at_ns);
    try testing.expectEqual(Deadline.body_rate, cancelled_for(0).?);
    try testing.expectEqual(0, connection.bodies.waiting);
    try support.pump(support.rounds_default);
    try testing.expectEqual(request_timeout, slow.status);
    try testing.expect(slow.ended and slow.reset == null);
    // One request ended, and no more is reported of it; the next is answered as before.
    try testing.expectEqual(null, support.nth(.done, 0));
    try testing.expectEqual(0, connection.peer_resets);
    try testing.expect(!support.server_failed and connection.clock.timed_out == null);
    const next = try support.request("GET", "/", "");
    try support.pump(rounds_few);
    try connection.respond(next.id, .{ .status = ok, .end = true });
    try support.pump(support.rounds_default);
    try testing.expectEqual(ok, next.status);
}

test "decision 110: a body that brings its quota each window is not cut, and one octet short is cut at the window's end" {
    try connected();
    const fetch = try post_holding();
    const first_end_ns = since_ns(fetch) + first_window_ns;
    try send_content(fetch, quota);
    try support.pump(rounds_few);
    server_at(first_end_ns);
    try send_content(fetch, 2 * quota);
    try support.pump(rounds_few);
    server_at(first_end_ns + constants.rate_window_ns);
    try testing.expectEqual(null, cancelled_for(0));
    // The third window brings one octet less than it owes.
    try send_content(fetch, 3 * quota - 1);
    try support.pump(rounds_few);
    const third_end_ns = first_end_ns + 2 * constants.rate_window_ns;
    try testing.expectEqual(third_end_ns, quic_deadline.soonest(connection).?);
    server_at(third_end_ns - 1);
    try testing.expectEqual(null, cancelled_for(0));
    server_at(third_end_ns);
    try testing.expectEqual(Deadline.body_rate, cancelled_for(0).?);
}

test "decision 110: a body that keeps the rate still ends at its cap" {
    try support.start();
    support.config.deadlines.body_ns = cap_ns;
    try support.connect();
    const fetch = try post_holding();
    const since = since_ns(fetch);
    try send_content(fetch, quota);
    try support.pump(rounds_few);
    server_at(since + first_window_ns);
    try testing.expectEqual(since + cap_ns, quic_deadline.soonest(connection).?);
    server_at(since + cap_ns - 1);
    try testing.expectEqual(null, cancelled_for(0));
    server_at(since + cap_ns);
    try testing.expectEqual(Deadline.body, cancelled_for(0).?);
}

test "decision 110: a body that ended, and one with no limits, run no deadline" {
    try connected();
    _ = try support.request("POST", "/", "x");
    try support.pump(rounds_few);
    try testing.expect(support.nth(.body, 1).?.end);
    try testing.expectEqual(0, connection.bodies.waiting);
    try testing.expectEqual(null, quic_deadline.soonest(connection));

    try support.start();
    support.config.deadlines.body_rate_min = null;
    support.config.deadlines.body_ns = null;
    try support.connect();
    const fetch = try post_holding();
    try testing.expectEqual(null, quic_deadline.soonest(connection));
    server_at(since_ns(fetch) + first_window_ns);
    try testing.expectEqual(null, cancelled_for(0));
    try testing.expectEqual(1, connection.bodies.waiting);
}

test "RFC 9114 §4.1.1: a body that falls short after its response began is reset with H3_REQUEST_CANCELLED" {
    try connected();
    const fetch = try post_holding();
    const at_ns = since_ns(fetch) + first_window_ns;
    try connection.respond(fetch.id, .{ .status = ok, .end = false });
    try support.pump(rounds_few);
    server_at(at_ns);
    try testing.expectEqual(Deadline.body_rate, cancelled_for(0).?);
    try support.pump(support.rounds_default);
    try testing.expectEqual(h3.constants.error_request_cancelled, fetch.reset.?);
    try testing.expectEqual(ok, fetch.status);
    try testing.expectEqual(null, support.nth(.done, 0));
}

test "RFC 9114 §4.1: a body that falls short after its response was acknowledged is stopped, and nothing is reported" {
    try connected();
    const fetch = try post_holding();
    const at_ns = since_ns(fetch) + first_window_ns;
    try connection.respond(fetch.id, .{ .status = ok, .end = true });
    try support.pump(support.rounds_default);
    try testing.expectEqual(fetch.id, support.nth(.done, 0).?.id);
    // The request's stream is still open, and its record held.
    try testing.expect(connection.requests.of(fetch.id).?.over);
    try testing.expectEqual(1, connection.bodies.waiting);
    server_at(at_ns - 1);
    try testing.expectEqual(1, connection.bodies.waiting);
    internal.on_instant(connection, at_ns);
    const stream = connection.transport.streams.lookup(.{ .value = fetch.id }).live;
    try testing.expect(stream.stop_sending.owed and is_no_error(stream.stop_error_code));
    try testing.expectEqual(0, connection.bodies.waiting);
    try support.pump(support.rounds_default);
    // RFC 9000 §3.5: the stream closes once the client answers the STOP_SENDING, which is no
    // cancel of its own.
    try testing.expectEqual(null, cancelled_for(0));
    try testing.expect(fetch.status == ok and fetch.ended and fetch.reset == null);
    try testing.expect(connection.requests.idle());
    try testing.expectEqual(0, connection.peer_resets);
}

test "RFC 9114 §4.1: a body that falls short after its response ended is stopped, and the response arrives whole" {
    try connected();
    const fetch = try post_holding();
    const at_ns = since_ns(fetch) + first_window_ns;
    server_at(at_ns - 1);
    // The response's octets have not left when the deadline passes.
    try connection.respond(fetch.id, .{ .status = ok, .end = true });
    server_at(at_ns);
    try testing.expectEqual(0, connection.bodies.waiting);
    try support.pump(support.rounds_default);
    try testing.expectEqual(null, cancelled_for(0));
    try testing.expectEqual(fetch.id, support.nth(.done, 0).?.id);
    try testing.expect(fetch.status == ok and fetch.ended and fetch.reset == null);
    try testing.expect(connection.requests.idle());
}

test "RFC 9114 §10.5: bodies that together fall under the rate close the connection with H3_EXCESSIVE_LOAD" {
    try connected();
    const first = try post_holding();
    const since = since_ns(first);
    server_at(since + stagger_ns);
    const second = try post_holding();
    // The first request ends, so the second body's own window ends after the bodies' window.
    support.cancel_fetch(first);
    try support.pump(rounds_few);
    try testing.expectEqual(1, connection.bodies.waiting);
    try testing.expect(since_ns(second) > since);
    try testing.expectEqual(since + first_window_ns, quic_deadline.soonest(connection).?);
    server_at(since + first_window_ns - 1);
    try testing.expect(connection.clock.timed_out == null and !support.server_failed);
    server_at(since + first_window_ns);
    try testing.expectEqual(Deadline.body_rate, connection.clock.timed_out.?);
    const close = connection.transport.pending_close.?;
    try testing.expect(close.layer == .application and close.error_code == h3.constants.error_excessive_load);
    try testing.expect(support.server_failed);
}

test "decision 110: bodies that together bring the quota keep the connection, and the slow one ends alone" {
    try connected();
    const slow = try post_holding();
    const since = since_ns(slow);
    server_at(since + stagger_ns);
    const fast = try post_holding();
    try send_content(fast, quota);
    try support.pump(rounds_few);
    server_at(since + first_window_ns);
    try testing.expectEqual(Deadline.body_rate, cancelled_for(0).?);
    try testing.expectEqual(slow.id, support.nth(.cancelled, 0).?.id);
    try testing.expect(connection.clock.timed_out == null and !support.server_failed);
    try testing.expectEqual(1, connection.bodies.waiting);
}

test "decision 110: a body's own window wakes the caller when the bodies together hold their quota" {
    try connected();
    const fast = try post_holding();
    const since = since_ns(fast);
    try send_content(fast, quota);
    try support.pump(rounds_few);
    server_at(since + stagger_ns);
    const slow = try post_holding();
    const slow_end_ns = since_ns(slow) + first_window_ns;
    server_at(since + first_window_ns);
    // The second window of the first body, and of the bodies together, holds its quota too.
    try send_content(fast, 2 * quota);
    try support.pump(rounds_few);
    try testing.expectEqual(slow_end_ns, quic_deadline.soonest(connection).?);
    server_at(slow_end_ns);
    try testing.expectEqual(slow.id, support.nth(.cancelled, 0).?.id);
    try testing.expect(connection.clock.timed_out == null);
}

test "decision 110: a request the client resets, or the caller cancels, runs no body deadline" {
    try connected();
    const reset = try post_holding();
    const since = since_ns(reset);
    support.cancel_fetch(reset);
    try support.pump(rounds_few);
    const dropped = try post_holding();
    connection.cancel(dropped.id);
    try testing.expectEqual(0, connection.bodies.waiting);
    server_at(since + first_window_ns + stagger_ns);
    try testing.expectEqual(null, support.nth(.cancelled, 1));
    try testing.expect(connection.clock.timed_out == null and !support.server_failed);
}

test "decision 110: a body ended by trailers, by its client's end after the response, or by a refusal runs no deadline" {
    try connected();
    // RFC 9110 §6.5: the trailer section ends the content, before the stream's end arrives.
    const checksum = [_]support.Field{.{ .name = "checksum", .value = "1" }};
    const trailed = try support.stage_request("POST", "/", &.{}, "", &checksum);
    try send_content(trailed, 0);
    try support.pump(rounds_few);
    try testing.expectEqual(trailed.id, support.nth(.trailers, 0).?.id);
    try testing.expectEqual(0, connection.bodies.waiting);
    // RFC 9114 §4.1.2: content short of its content-length is malformed, and h3 refuses it.
    const declared = [_]support.Field{.{ .name = "content-length", .value = "5" }};
    _ = try support.request_with_fields("POST", "/", &declared);
    try support.pump(rounds_few);
    try testing.expect(support.nth(.cancelled, 0).?.reason.? == .refused);
    try testing.expectEqual(0, connection.bodies.waiting);
    // A request answered whole whose client then ends it: the caller hears of it no more.
    const fetch = try post_holding();
    try connection.respond(fetch.id, .{ .status = ok, .end = true });
    try support.pump(support.rounds_default);
    try testing.expectEqual(1, connection.bodies.waiting);
    try quic.connection_stream_send.supply(&support.client, .{ .value = fetch.id }, fetch.prefix_len, true);
    try support.pump(rounds_few);
    try testing.expectEqual(0, connection.bodies.waiting);
}

test "decision 101: a coded response whose request a body deadline ends gives its encoder back" {
    try support.start_coding();
    try support.connect();
    const accepts_gzip = [_]support.Field{.{ .name = "accept-encoding", .value = "gzip" }};
    const fetch = try support.stage_request("POST", "/", &accepts_gzip, &content, &.{});
    try send_content(fetch, 0);
    try support.pump(rounds_few);
    const free = tcp_support.pool.free_count();
    try connection.respond(fetch.id, .{ .status = ok, .end = false, .codable = true });
    try testing.expectEqual(free - 1, tcp_support.pool.free_count());
    server_at(since_ns(fetch) + first_window_ns);
    try testing.expectEqual(Deadline.body_rate, cancelled_for(0).?);
    try testing.expectEqual(free, tcp_support.pool.free_count());
}

test "decision 110 as amended: a body rate an honest peer can fall short of is refused at start" {
    try support.start();
    // Twice 819 octets a second over a window of 10 s is under a unit of 16,384 octets.
    support.config.deadlines.body_rate_min = unit_bound_rate - 1;
    try testing.expectError(error.DeadlineInvalid, support.connect());
    try support.start();
    support.config.deadlines.body_rate_min = unit_bound_rate;
    try support.connect();
}

/// The least rate `Deadlines.validate_units` takes at the default window.
const unit_bound_rate: u32 = 820;
