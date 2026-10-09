//! The tests of the deadlines that wait while the server holds credit its client needs
//! (`quic_deadline.zig`, `quic_body.zig`, decision 110 as amended): a head, the idle connection
//! and a body, each judged as though the time the credit was held never passed.
//!
//! A test holds the credit by leaving the server's congestion window no room, so nothing that
//! elicits an acknowledgment goes out (RFC 9002 §7). ACK frames still do (RFC 9002 §2), so the
//! client goes on sending what its windows allow.
const std = @import("std");
const quic = @import("quic");
const support = @import("quic_test_support.zig");
const constants = @import("../constants.zig");
const quic_deadline = @import("quic_deadline.zig");
const internal = @import("quic_connection_internal.zig");
const Deadline = @import("../deadline.zig").Deadline;

const testing = std.testing;
const connection = &support.connection;

const ok: u16 = 200;
/// Rounds that carry a request to the server, and its answer back.
const rounds_few: usize = 2;
/// A receive pool, and so every window the server grants, of 32,768 octets. Test-only.
const pool_len: usize = 32_768;
const Pool = quic.stream.stream_incoming.Pool(pool_len);
threadlocal var pool: Pool align(@alignOf(Pool)) = undefined;
/// Content past half the window, so reading it earns credit (`flow_credit_fraction`), and twice
/// what a window of the body rate owes.
const content_len: usize = 20_480;
const content: [content_len]u8 = @splat('c');
/// An idle limit shorter than QUIC's own idle timeout, so the two are told apart.
const idle_short_seconds: u64 = 5;
const idle_short_ns: u64 = idle_short_seconds * constants.nanoseconds_per_second;
/// From the start of a body's wait to the end of its first window.
const first_window_ns: u64 = constants.rate_grace_ns + constants.rate_window_ns;

/// A connected pair whose server grants windows of `pool_len` octets and goes idle after
/// `idle_ns`.
fn connected(idle_ns: u64) !void {
    try support.start_with_pool(pool.storage());
    support.config.deadlines.idle_ns = idle_ns;
    try support.connect();
}

/// A POST whose head and DATA frame header reach the server, and none of its content.
fn post_holding() !*support.Fetch {
    const fetch = try support.stage_request("POST", "/", &.{}, &content, &.{});
    try quic.connection_stream_send.supply(&support.client, .{ .value = fetch.id }, fetch.prefix_len, false);
    try support.pump(rounds_few);
    return fetch;
}

/// The client sends all of `fetch`'s content, and ends the stream when `fin` is set.
fn send_content(fetch: *const support.Fetch, fin: bool) !void {
    try quic.connection_stream_send.supply(&support.client, .{ .value = fetch.id }, fetch.prefix_len + content.len, fin);
}

/// Leaves the server's congestion window no room, once every packet it sent is acknowledged, and
/// returns the window it had.
fn fill_window() !u64 {
    try support.pump(support.rounds_default);
    const recovery = &connection.transport.recovery;
    try testing.expectEqual(0, recovery.in_flight_len());
    const window = recovery.congestion.window;
    recovery.congestion.window = 0;
    return window;
}

/// Gives the server's congestion window back, and returns the instant the credit went out at,
/// which the send itself notes. The client then acknowledges the credit, so no loss owes it again
/// while a test moves time on.
fn empty_window(window: u64) !u64 {
    connection.transport.recovery.congestion.window = window;
    support.now_ns += support.round_ns;
    try support.server_to_client();
    try testing.expectEqual(null, connection.clock.credit_held_since_ns);
    const released_ns = support.now_ns;
    try support.pump(rounds_few);
    return released_ns;
}

/// Has the server see `now_ns`, and the test's clock with it, and keeps what it reports.
fn server_at(now_ns: u64) void {
    internal.on_instant(connection, now_ns);
    support.now_ns = now_ns;
    support.collect();
}

/// The server sees `at_ns - 1`, at which the idle deadline has not passed, and then `at_ns`.
fn expect_idle_at(at_ns: u64) !void {
    try testing.expectEqual(at_ns, quic_deadline.soonest(connection).?);
    server_at(at_ns - 1);
    try testing.expectEqual(null, connection.clock.timed_out);
    server_at(at_ns);
    try testing.expectEqual(Deadline.idle, connection.clock.timed_out.?);
}

test "decision 110 as amended: a head waits while the server holds credit, and its deadline moves by the time it was held" {
    try connected(constants.idle_timeout_ns);
    // No body deadline runs, so none comes before the head's.
    try connection.set_deadlines(.{ .body_rate_min = null, .body_ns = null });
    const open = try post_holding();
    const late = try support.request_short_of_head("GET", "/");
    try support.pump(rounds_few);
    const since_ns = connection.h3.oldest_head_wait().?.since_ns;
    const window = try fill_window();
    try send_content(open, false);
    try support.pump(rounds_few);
    const held_ns = connection.clock.credit_held_since_ns.?;
    try testing.expectEqual(null, quic_deadline.soonest(connection));
    server_at(since_ns + constants.head_timeout_ns);
    try testing.expectEqual(late.id, connection.h3.oldest_head_wait().?.stream_id);
    const released_ns = try empty_window(window);
    const at_ns = since_ns + (released_ns - held_ns) + constants.head_timeout_ns;
    try testing.expectEqual(at_ns, quic_deadline.soonest(connection).?);
    server_at(at_ns - 1);
    try testing.expectEqual(late.id, connection.h3.oldest_head_wait().?.stream_id);
    server_at(at_ns);
    try testing.expectEqual(null, connection.h3.oldest_head_wait());
    try testing.expect(connection.requests.of(late.id).?.over);
}

test "decision 110 as amended: the idle deadline moves by the time the server held credit" {
    try connected(idle_short_ns);
    const fetch = try post_holding();
    // The response is done, so the connection is idle while the request's content is to come.
    try connection.respond(fetch.id, .{ .status = ok, .end = true });
    try support.pump(support.rounds_default);
    const idle_since_ns = connection.clock.idle_since_ns.?;
    const window = try fill_window();
    try send_content(fetch, true);
    try support.pump(rounds_few);
    const held_ns = connection.clock.credit_held_since_ns.?;
    try testing.expectEqual(null, quic_deadline.soonest(connection));
    server_at(idle_since_ns + idle_short_ns);
    try testing.expectEqual(null, connection.clock.timed_out);
    const released_ns = try empty_window(window);
    try expect_idle_at(idle_since_ns + (released_ns - held_ns) + idle_short_ns);
}

test "decision 110 as amended: a connection that goes idle while the server holds credit starts its idle deadline once the credit is out" {
    try connected(idle_short_ns);
    const fetch = try post_holding();
    const window = try fill_window();
    try send_content(fetch, false);
    try support.pump(rounds_few);
    try testing.expect(connection.clock.credit_held_since_ns != null);
    // The caller cancels the one request, so the connection goes idle.
    connection.cancel(fetch.id);
    try support.pump(1);
    const idle_since_ns = connection.clock.idle_since_ns.?;
    try testing.expectEqual(null, quic_deadline.soonest(connection));
    server_at(idle_since_ns + idle_short_ns);
    try testing.expectEqual(null, connection.clock.timed_out);
    const released_ns = try empty_window(window);
    try testing.expectEqual(released_ns, connection.clock.idle_since_ns.?);
    try expect_idle_at(released_ns + idle_short_ns);
}

test "decision 110 as amended: a body's rate waits while the server holds credit, and starts again with a grace period" {
    try connected(constants.idle_timeout_ns);
    const fetch = try post_holding();
    const record = connection.requests.of(fetch.id).?;
    const since_ns = connection.bodies.entries[connection.requests.index_of(record)].since_ns;
    const window = try fill_window();
    try send_content(fetch, false);
    try support.pump(rounds_few);
    try testing.expect(connection.clock.credit_held_since_ns != null);
    // The meters wait, and the cap goes on.
    try testing.expectEqual(since_ns + constants.body_timeout_ns, quic_deadline.soonest(connection).?);
    server_at(since_ns + first_window_ns);
    const released_ns = try empty_window(window);
    const at_ns = released_ns + first_window_ns;
    try testing.expectEqual(at_ns, quic_deadline.soonest(connection).?);
    // A meter that had gone on would have cut the body, or the connection, a window after the
    // first.
    server_at(at_ns - 1);
    try testing.expectEqual(null, support.nth(.cancelled, 0));
    try testing.expectEqual(null, connection.clock.timed_out);
    server_at(at_ns);
    try testing.expectEqual(Deadline.body_rate, support.nth(.cancelled, 0).?.reason.?.deadline);
}
