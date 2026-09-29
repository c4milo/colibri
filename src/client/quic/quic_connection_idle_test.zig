//! The tests of the client's idle rules over QUIC (`quic_connection.zig`, design §8 step 17g): a
//! connection near its idle timeout takes no new exchange and closes when it holds none, and sends
//! a PING when a response is outstanding (RFC 9114 §5.1, RFC 9000 §10.1.2).
const std = @import("std");
const quic = @import("quic");
const support = @import("quic_test_support.zig");
const tcp_support = @import("../connection/connection_test_support.zig");
const constants = @import("../constants.zig");

const testing = std.testing;
const connection = &support.connection;
const HttpExchange = support.HttpExchange;

/// Where the tests' exchanges put their responses, outside any stack frame. Test-only.
var bodies: [bodies_count][body_len]u8 = undefined;
const bodies_count: usize = 2;
const body_len: usize = 1024;
/// Rounds that run past the closing period, three times the Probe Timeout (RFC 9000 §10.2).
const closing_rounds: usize = 128;
/// An idle timeout short enough that half of it is less than `quic_idle_margin_ns_min`, in
/// milliseconds, and the margin it leaves. Test-only.
const short_idle_timeout_ms: u64 = 1_500;
const short_margin_ns: u64 = short_idle_timeout_ms * quic.constants.nanoseconds_per_millisecond / constants.quic_idle_margin_timeout_divisor;

fn get(body: []u8) HttpExchange {
    return .{ .method = "GET", .path = "/dns-query", .body = body };
}

/// A connection that carried one exchange to its response, and holds none. Test-only.
fn answered_once() !void {
    var exchange = get(&bodies[0]);
    _ = try connection.request(&exchange);
    try support.pump(support.rounds_default);
    try testing.expectEqual(.response, exchange.outcome);
}

/// Moves time to `at_ns` and fires the client's deadlines there. Test-only.
fn fire_at(at_ns: u64) void {
    support.now_ns = at_ns;
    connection.on_instant(at_ns);
}

test "RFC 9114 §5.1: an idle connection near its idle timeout takes no new exchange, and closes" {
    try support.start(&support.alpn_h3, &support.alpn_h3, false);
    try answered_once();
    // Both sides advertise 30 s, and one PTO is far below 1 s, so the margin is 1 s.
    const idle_deadline = quic.connection_idle.deadline_ns(&connection.transport).?;
    const acts_at = idle_deadline - constants.quic_idle_margin_ns_min;
    try testing.expect(connection.deadline_ns().? <= acts_at);
    fire_at(acts_at - 1);
    try testing.expect(!connection.draining);
    fire_at(acts_at);
    try testing.expect(connection.retired and connection.draining);
    var later = get(&bodies[1]);
    try testing.expectError(error.Draining, connection.request(&later));
    // It closes with H3_NO_ERROR once its closing period has run, and the server read the close.
    try support.pump(closing_rounds);
    try testing.expect(support.find(.draining) != null and support.find(.closed) != null);
    try testing.expect(support.server.termination.state != .active);
    try testing.expect(connection.should_close());
    connection.transport_closed();
    try testing.expect(!connection.failed);
}

test "RFC 9000 §10.1.2: a connection awaiting a response sends a PING near its idle deadline" {
    try support.start(&support.alpn_h3, &support.alpn_h3, false);
    support.server_answers = false;
    var exchange = get(&bodies[0]);
    _ = try connection.request(&exchange);
    try support.pump(support.rounds_default);
    const first_deadline = quic.connection_idle.deadline_ns(&connection.transport).?;
    const acts_at = first_deadline - constants.quic_idle_margin_ns_min;
    fire_at(acts_at);
    try testing.expect(quic.connection_idle.keep_alive_owed(&connection.transport));
    try testing.expect(!connection.retired and !connection.draining);
    // One deadline is acted on once: the connection asks for no second PING before the first
    // goes out.
    try testing.expect(connection.deadline_ns().? > acts_at);
    // The PING goes out, the server acknowledges it, and the idle deadline moves past the first.
    try support.pump(support.rounds_default);
    try testing.expect(!quic.connection_idle.keep_alive_owed(&connection.transport));
    try testing.expect(quic.connection_idle.deadline_ns(&connection.transport).? > first_deadline);
    // The response comes, and the exchange ends with it.
    support.server_answers = true;
    try support.answer_due();
    try support.pump(support.rounds_default);
    try testing.expectEqual(.response, exchange.outcome);
    try testing.expect(!connection.retired);
}

test "RFC 9114 §5.1: a margin never runs past half the idle timeout" {
    try support.prepare(&support.alpn_h3, &support.alpn_h3, false);
    support.config.idle_timeout_ms = short_idle_timeout_ms;
    try connection.init(&support.config, support.client_pool.storage(), support.client_start, tcp_support.stream.random(), tcp_support.now_seconds, support.now_ns, null);
    try answered_once();
    const acts_at = quic.connection_idle.deadline_ns(&connection.transport).? - short_margin_ns;
    fire_at(acts_at - 1);
    try testing.expect(!connection.retired);
    fire_at(acts_at);
    try testing.expect(connection.retired);
}

test "RFC 9114 §5.1: a connection already draining is not retired, and closes after its last exchange" {
    try support.start(&support.alpn_h3, &support.alpn_h3, false);
    try answered_once();
    connection.shutdown();
    const acts_at = quic.connection_idle.deadline_ns(&connection.transport).? - constants.quic_idle_margin_ns_min;
    fire_at(acts_at);
    try testing.expect(connection.draining and !connection.retired);
}

test "RFC 9114 §5.1: a connection whose handshake has not completed is not retired" {
    try support.start(&support.alpn_h3, &support.alpn_h3, false);
    // The server never hears the client, so the handshake never completes.
    var datagram: [quic.constants.datagram_len_max]u8 = undefined;
    _ = connection.send(&datagram, support.now_ns);
    const acts_at = quic.connection_idle.deadline_ns(&connection.transport).? - constants.quic_idle_margin_ns_min;
    fire_at(acts_at);
    try testing.expect(!connection.retired and !connection.draining);
}

test "RFC 9114 §5.1: a connection that failed is not retired, though its close has not gone out" {
    try support.start(&support.alpn_h3, &support.alpn_h3, false);
    try answered_once();
    connection.fail();
    // The CONNECTION_CLOSE waits for the next send, so the idle timer still runs.
    const acts_at = quic.connection_idle.deadline_ns(&connection.transport).? - constants.quic_idle_margin_ns_min;
    fire_at(acts_at);
    try testing.expect(!connection.retired and !connection.draining);
}
