//! The tests of how a server QUIC connection ends itself (decision 110 as amended): a GOAWAY
//! first, the close once the client acknowledged it, and the drain deadline that bounds both a
//! client that acknowledges nothing and the requests a shutdown leaves open.
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
/// An idle limit and a drain limit shorter than QUIC's own idle timeout, so each is told from it.
const short_seconds: u64 = 5;
const short_ns: u64 = short_seconds * constants.nanoseconds_per_second;

/// A server whose idle and drain limits are `short_ns`, and a client, connected.
fn connected() !void {
    try support.start();
    support.config.deadlines.idle_ns = short_ns;
    support.config.deadlines.drain_ns = short_ns;
    try support.connect();
}

/// Has the server see `now_ns`, and the test's clock with it, and keeps what it reports.
fn server_at(now_ns: u64) void {
    internal.on_instant(connection, now_ns);
    support.now_ns = now_ns;
    support.collect();
}

/// A whole GET the server answers, its response acknowledged, so the connection is idle.
fn one_exchange() !void {
    const fetch = try support.request("GET", "/", "");
    try support.pump(rounds_few);
    try connection.respond(fetch.id, .{ .status = ok, .end = true });
    try support.pump(support.rounds_default);
    try testing.expect(fetch.ended);
}

/// Whether the connection owes or sent an application close with H3_NO_ERROR, or the reserved
/// code h3 sends in its place now and then (RFC 9114 §8.1).
fn closing_with_no_error() bool {
    const close = connection.transport.pending_close orelse return false;
    if (close.layer != .application) return false;
    return close.error_code == h3.constants.error_no_error or h3.constants.is_reserved(close.error_code);
}

test "RFC 9114 §5.2: a connection its idle deadline ends sends a GOAWAY, takes no new request, and closes once the client acknowledged it" {
    try connected();
    try one_exchange();
    server_at(connection.clock.idle_since_ns.? + short_ns);
    try testing.expectEqual(Deadline.idle, connection.close_reason().?.deadline);
    try testing.expect(connection.h3.goaway_sent != null and connection.transport.pending_close == null);
    // One round carries the GOAWAY to the client, whose acknowledgment has not come back.
    try support.pump(1);
    try testing.expect(support.client_h3.goaway_received != null);
    try testing.expectEqual(null, connection.transport.pending_close);
    try testing.expectError(error.GoawayReceived, support.request("GET", "/", ""));
    try support.pump(rounds_few);
    try testing.expect(closing_with_no_error() and !support.server_failed);
    try testing.expectEqual(.closed_by_peer, support.client.termination.reason.?);
}

test "decision 110: a client that acknowledges no GOAWAY is closed at the drain deadline, for the deadline that began it" {
    try connected();
    try one_exchange();
    const idle_end_ns = connection.clock.idle_since_ns.? + short_ns;
    support.client_mute = true;
    server_at(idle_end_ns);
    try support.pump(rounds_few);
    try testing.expectEqual(null, connection.transport.pending_close);
    try testing.expectEqual(idle_end_ns + short_ns, quic_deadline.soonest(connection).?);
    server_at(idle_end_ns + short_ns - 1);
    try testing.expectEqual(null, connection.transport.pending_close);
    server_at(idle_end_ns + short_ns);
    try testing.expect(closing_with_no_error());
    try testing.expectEqual(Deadline.idle, connection.close_reason().?.deadline);
}

test "decision 110: requests a shutdown leaves open end with the connection when the drain passes" {
    try connected();
    _ = try support.request("GET", "/", "");
    try support.pump(rounds_few);
    connection.shutdown(support.now_ns);
    // The client acknowledges the GOAWAY, and its request is still open.
    try support.pump(support.rounds_default);
    try testing.expectEqual(null, connection.transport.pending_close);
    try testing.expectEqual(null, connection.close_reason());
    // The drain runs from the first call that saw the shutdown.
    const drain_end_ns = connection.clock.drain_since_ns.? + short_ns;
    try testing.expectEqual(drain_end_ns, quic_deadline.soonest(connection).?);
    server_at(drain_end_ns - 1);
    try testing.expectEqual(null, connection.close_reason());
    server_at(drain_end_ns);
    try testing.expectEqual(Deadline.drain, connection.close_reason().?.deadline);
    try testing.expect(closing_with_no_error() and connection.requests.idle());
}

test "decision 110: a shutdown whose requests finish in time closes with no deadline, and a drain of null runs none" {
    try connected();
    const fetch = try support.request("GET", "/", "");
    try support.pump(rounds_few);
    connection.shutdown(support.now_ns);
    try connection.respond(fetch.id, .{ .status = ok, .end = true });
    try support.pump(support.rounds_default);
    try testing.expect(closing_with_no_error());
    try testing.expectEqual(null, connection.close_reason());

    try support.start();
    support.config.deadlines.drain_ns = null;
    try support.connect();
    _ = try support.request("GET", "/", "");
    try support.pump(rounds_few);
    connection.shutdown(support.now_ns);
    try support.pump(rounds_few);
    try testing.expect(connection.clock.drain_since_ns != null);
    try testing.expectEqual(null, quic_deadline.soonest(connection));
}

test "RFC 9114 §5.2: a shutdown with no request open sends its GOAWAY before it closes" {
    try connected();
    connection.shutdown(support.now_ns);
    try testing.expect(connection.h3.goaway_sent != null and connection.transport.pending_close == null);
    try support.pump(1);
    try testing.expect(support.client_h3.goaway_received != null);
    try support.pump(rounds_few);
    try testing.expect(closing_with_no_error());
    try testing.expectEqual(null, connection.close_reason());
}

test "decision 110: a connection that is shutting down runs no first-request and no idle deadline" {
    try connected();
    connection.shutdown(support.now_ns);
    support.client_mute = true;
    try support.pump(rounds_few);
    const drain_end_ns = connection.clock.drain_since_ns.? + short_ns;
    try testing.expect(drain_end_ns < connection.clock.opened_ns + constants.first_request_timeout_ns);
    try testing.expectEqual(drain_end_ns, quic_deadline.soonest(connection).?);
    server_at(drain_end_ns);
    try testing.expectEqual(Deadline.drain, connection.close_reason().?.deadline);
}

test "RFC 9114 §4.1.1: a connection its idle deadline ends rejects each request whose head is not whole" {
    try connected();
    try one_exchange();
    const late = try support.request_short_of_head("GET", "/");
    const later = try support.request_short_of_head("GET", "/");
    try support.pump(rounds_few);
    try testing.expectEqual(late.id, connection.h3.oldest_head_wait().?.stream_id);
    // Each head's own deadline is further off than the idle deadline, so neither gets a 408.
    server_at(connection.clock.idle_since_ns.? + short_ns);
    try testing.expectEqual(Deadline.idle, connection.close_reason().?.deadline);
    try testing.expectEqual(null, connection.h3.oldest_head_wait());
    try support.pump(support.rounds_default);
    try testing.expectEqual(h3.constants.error_request_rejected, late.reset.?);
    try testing.expectEqual(h3.constants.error_request_rejected, later.reset.?);
    try testing.expectEqual(0, late.status + later.status);
    try testing.expect(closing_with_no_error() and !support.server_failed);
    // The client resets its side because the server asked it to, which is no cancel of its own.
    try testing.expectEqual(0, connection.peer_resets);
}

test "RFC 9114 §4.1.1: a shutdown rejects the request whose head is not whole, and answers the one it holds" {
    try connected();
    const held = try support.request("GET", "/", "");
    try support.pump(rounds_few);
    const late = try support.request_short_of_head("GET", "/");
    try support.pump(rounds_few);
    connection.shutdown(support.now_ns);
    try support.pump(rounds_few);
    try testing.expectEqual(h3.constants.error_request_rejected, late.reset.?);
    try testing.expectEqual(null, connection.transport.pending_close);
    try connection.respond(held.id, .{ .status = ok, .end = true });
    try support.pump(support.rounds_default);
    try testing.expectEqual(ok, held.status);
    try testing.expect(held.ended and held.reset == null and closing_with_no_error());
}

test "decision 110: a head that is late at the instant the idle deadline passes gets its 408, and no reset" {
    try connected();
    try one_exchange();
    const idle_since_ns = connection.clock.idle_since_ns.?;
    const late = try support.request_short_of_head("GET", "/");
    try support.pump(rounds_few);
    const wait = connection.h3.oldest_head_wait().?;
    // Both deadlines pass at one instant: the head's, and the idle deadline that began before it.
    const at_ns = wait.since_ns + short_ns;
    try connection.set_deadlines(.{ .head_ns = short_ns, .idle_ns = at_ns - idle_since_ns, .drain_ns = short_ns });
    server_at(at_ns - 1);
    try testing.expectEqual(null, connection.close_reason());
    server_at(at_ns);
    try testing.expectEqual(Deadline.idle, connection.close_reason().?.deadline);
    try support.pump(support.rounds_default);
    try testing.expectEqual(request_timeout, late.status);
    try testing.expect(late.ended and late.reset == null);
    try testing.expect(closing_with_no_error() and !support.server_failed);
}
