//! The tests of the server's deadlines over QUIC (`quic_deadline.zig`, decision 110 as amended):
//! a connection that brings no request, one that goes idle, and a request whose head is late,
//! each at its instant and not a nanosecond before.
const std = @import("std");
const h3 = @import("h3");
const support = @import("quic_test_support.zig");
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
/// An idle limit shorter than QUIC's own idle timeout, so the two are told apart.
const idle_short_seconds: u64 = 5;
const idle_short_ns: u64 = idle_short_seconds * constants.nanoseconds_per_second;
/// Wakes a caller's loop makes before a test gives up.
const wakes_max: usize = 64;

/// A server and a client whose handshake completed, the server with `idle_ns` as its idle limit.
fn connected(idle_ns: ?u64) !void {
    try support.start();
    support.config.deadlines.idle_ns = idle_ns;
    try support.connect();
}

/// Whether `code` is H3_NO_ERROR, or the reserved code h3 sends in its place now and then (RFC
/// 9114 §8.1). Test-only.
fn is_no_error(code: u64) bool {
    return code == h3.constants.error_no_error or h3.constants.is_reserved(code);
}

/// Whether the connection owes an application close with H3_NO_ERROR. Test-only.
fn closing_with_no_error() bool {
    const close = connection.transport.pending_close orelse return false;
    return close.layer == .application and is_no_error(close.error_code);
}

/// Has the server see `now_ns`, and the test's clock with it. Test-only.
fn server_at(now_ns: u64) void {
    internal.on_instant(connection, now_ns);
    support.now_ns = now_ns;
}

/// A whole GET the server answers, its response acknowledged, so the connection is idle.
fn one_exchange() !void {
    const fetch = try support.request("GET", "/", "");
    try support.pump(rounds_few);
    try connection.respond(fetch.id, .{ .status = ok, .end = true });
    try support.pump(support.rounds_default);
    try testing.expect(fetch.ended);
}

test "decision 110: a connection that brings no whole request head by its first-request deadline ends with H3_NO_ERROR" {
    try connected(constants.idle_timeout_ns);
    // A head that is not whole is no request.
    _ = try support.request_short_of_head("GET", "/");
    try support.pump(rounds_few);
    const at_ns = connection.clock.opened_ns + constants.first_request_timeout_ns;
    try testing.expectEqual(at_ns, quic_deadline.soonest(connection).?);
    server_at(at_ns - 1);
    try testing.expectEqual(null, connection.close_reason());
    server_at(at_ns);
    try testing.expectEqual(Deadline.first_request, connection.close_reason().?.deadline);
    // RFC 9114 §5.2: a GOAWAY goes first, and the close follows its acknowledgment.
    try testing.expect(connection.h3.goaway_sent != null and connection.transport.pending_close == null);
    try support.pump(rounds_few);
    try testing.expect(closing_with_no_error());
    // A deadline is no failure, and the connection reads nothing more.
    try support.pump(rounds_few);
    try testing.expect(!support.server_failed);
    try testing.expect(support.client.termination.state != .active);
}

test "RFC 9000 §10.2.3: a client that never completes its handshake is closed at the first-request deadline" {
    try support.start();
    // One round carries the client's first Initial, and the server's answer finds no reply.
    try support.pump(1);
    try testing.expect(support.server_started and !connection.transport.handshake_complete);
    const at_ns = connection.clock.opened_ns + constants.first_request_timeout_ns;
    server_at(at_ns - 1);
    try testing.expectEqual(null, connection.clock.timed_out);
    server_at(at_ns);
    try testing.expectEqual(Deadline.first_request, connection.clock.timed_out.?);
    // The close leaves in a packet the client holds the keys of, and ends its connection.
    try support.pump(rounds_few);
    try testing.expect(!support.server_failed);
    try testing.expectEqual(.closed_by_peer, support.client.termination.reason.?);
}

test "decision 110: a caller that wakes at deadline_ns meets the first-request deadline at its instant" {
    try connected(constants.idle_timeout_ns);
    const at_ns = connection.clock.opened_ns + constants.first_request_timeout_ns;
    var woke_ns: u64 = 0;
    for (0..wakes_max) |_| {
        woke_ns = internal.deadline_ns(connection) orelse break;
        internal.on_instant(connection, woke_ns);
        if (connection.clock.timed_out != null) break;
    }
    try testing.expectEqual(at_ns, woke_ns);
    try testing.expectEqual(Deadline.first_request, connection.clock.timed_out.?);
}

test "decision 110: a deadline that passed fires at the next receive, with no call to on_instant" {
    try connected(constants.idle_timeout_ns);
    const at_ns = connection.clock.opened_ns + constants.first_request_timeout_ns;
    support.now_ns = at_ns;
    try testing.expectEqual(null, (try connection.receive(at_ns)).event);
    try testing.expectEqual(Deadline.first_request, connection.clock.timed_out.?);
}

test "decision 110: a program changes one connection's limits, null turns one off, and what a start refuses is refused" {
    try connected(constants.idle_timeout_ns);
    try testing.expectError(error.DeadlineInvalid, connection.set_deadlines(.{ .idle_ns = 0 }));
    // Twice 819 octets a second over a window of 10 s is under a unit of 16,384 octets.
    try testing.expectError(error.DeadlineInvalid, connection.set_deadlines(.{ .body_rate_min = unit_bound_rate - 1 }));
    try testing.expectEqual(constants.first_request_timeout_ns, connection.deadlines.first_request_ns.?);
    try connection.set_deadlines(.{ .first_request_ns = null });
    try testing.expectEqual(null, quic_deadline.soonest(connection));
    // A shorter limit counts from the start the deadline already has.
    try connection.set_deadlines(.{ .first_request_ns = idle_short_ns });
    try testing.expectEqual(connection.clock.opened_ns + idle_short_ns, quic_deadline.soonest(connection).?);
}

/// The least body rate `Deadlines.validate_units` takes at the default window.
const unit_bound_rate: u32 = 820;

test "decision 110: a deadline set to null does not run" {
    try support.start();
    support.config.deadlines.first_request_ns = null;
    try support.connect();
    try testing.expectEqual(null, quic_deadline.soonest(connection));
    server_at(connection.clock.opened_ns + constants.first_request_timeout_ns);
    try testing.expectEqual(null, connection.clock.timed_out);
}

test "decision 110: an idle connection closes at its idle deadline, counted from when its last request ended" {
    try connected(idle_short_ns);
    const fetch = try support.request("GET", "/", "");
    try support.pump(rounds_few);
    // A request is open, so the connection is not idle, and its first request came.
    try testing.expectEqual(null, connection.clock.idle_since_ns);
    try testing.expectEqual(null, quic_deadline.soonest(connection));
    const responded_ns = support.now_ns;
    try connection.respond(fetch.id, .{ .status = ok, .end = true });
    try support.pump(support.rounds_default);
    const idle_since_ns = connection.clock.idle_since_ns.?;
    try testing.expect(idle_since_ns > responded_ns);
    const at_ns = idle_since_ns + idle_short_ns;
    try testing.expectEqual(at_ns, quic_deadline.soonest(connection).?);
    server_at(at_ns - 1);
    try testing.expectEqual(null, connection.clock.timed_out);
    server_at(at_ns);
    try testing.expectEqual(Deadline.idle, connection.clock.timed_out.?);
    try support.pump(rounds_few);
    try testing.expect(closing_with_no_error());
}

test "decision 110: a request stream whose head is not whole does not stop the idle deadline" {
    try connected(idle_short_ns);
    try one_exchange();
    const idle_since_ns = connection.clock.idle_since_ns.?;
    const late = try support.request_short_of_head("GET", "/");
    try support.pump(rounds_few);
    try testing.expectEqual(late.id, connection.h3.oldest_head_wait().?.stream_id);
    try testing.expectEqual(idle_since_ns, connection.clock.idle_since_ns.?);
    server_at(idle_since_ns + idle_short_ns);
    try testing.expectEqual(Deadline.idle, connection.clock.timed_out.?);
}

test "RFC 9110 §15.5.9: a request whose head is late gets a 408, the server stops reading it, and the connection goes on" {
    try connected(constants.idle_timeout_ns);
    // An open request keeps the connection from being idle while the late head waits.
    const open = try support.request_open("POST", "/", "x");
    try support.pump(rounds_few);
    const late = try support.request_short_of_head("GET", "/");
    try support.pump(rounds_few);
    const wait = connection.h3.oldest_head_wait().?;
    try testing.expectEqual(late.id, wait.stream_id);
    const at_ns = wait.since_ns + constants.head_timeout_ns;
    try testing.expectEqual(at_ns, quic_deadline.soonest(connection).?);
    server_at(at_ns - 1);
    // The stream still waits for its head, and has no response.
    try testing.expectEqual(late.id, connection.h3.oldest_head_wait().?.stream_id);
    try testing.expectEqual(null, connection.requests.of(late.id));
    server_at(at_ns);
    try testing.expectEqual(null, connection.h3.oldest_head_wait());
    try testing.expect(connection.requests.of(late.id).?.over);
    // RFC 9114 §4.1: the server asks the client to stop sending with H3_NO_ERROR.
    const stream = connection.transport.streams.lookup(.{ .value = late.id }).live;
    try testing.expect(stream.stop_sending.owed and is_no_error(stream.stop_error_code));
    try support.pump(support.rounds_default);
    try testing.expectEqual(request_timeout, late.status);
    try testing.expect(late.ended and late.reset == null);
    // RFC 9114 §4.1: the client was asked to stop sending, which is no cancel of its own, and the
    // caller never hears of the request.
    try testing.expectEqual(0, connection.peer_resets);
    try testing.expectEqual(null, support.nth(.request, 1));
    try testing.expectEqual(null, support.nth(.done, 0));
    try testing.expectEqual(null, connection.requests.of(late.id));
    // The other request is answered as before.
    try testing.expectEqual(null, connection.clock.timed_out);
    try connection.respond(open.id, .{ .status = ok, .end = true });
    try support.pump(support.rounds_default);
    try testing.expectEqual(ok, open.status);
}

test "RFC 9114 §4.1.1: a late head with no record free for a response is rejected" {
    try connected(constants.idle_timeout_ns);
    const open = try support.request_open("POST", "/", "x");
    try support.pump(rounds_few);
    const late = try support.request_short_of_head("GET", "/");
    try support.pump(rounds_few);
    const wait = connection.h3.oldest_head_wait().?;
    // Every record is taken, as if each held a response.
    for (&connection.requests.records) |*record| {
        if (record.in_use) continue;
        record.* = .{ .in_use = true, .stream_id = open.id, .ended = true, .answered = false, .finished = false, .over = true, .continue_owed = false, .response = undefined, .asked = .{}, .coded = null };
        record.response.init();
    }
    server_at(wait.since_ns + constants.head_timeout_ns);
    try support.pump(support.rounds_default);
    try testing.expectEqual(h3.constants.error_request_rejected, late.reset.?);
    try testing.expectEqual(0, late.status);
}
