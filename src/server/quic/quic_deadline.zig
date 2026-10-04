//! The deadlines of one server connection over QUIC (decision 110 as amended, design §8 step
//! 20c): the instant each started at, the soonest one the caller wakes for beside QUIC's own
//! timers, and what the connection does when one passes.
//!
//! QUIC's idle timeout counts silence alone (RFC 9000 §10.1), which a PING ends, and RFC 9000
//! §21.6 has a deployment bound how long a peer holds a connection. These deadlines count
//! requests. A connection brings a first whole request head, each request stream brings its head,
//! and a connection with no request open brings the next one.
//!
//! Only a request whose head arrived whole is open. A stream that still waits for its head does
//! not stop the idle deadline, so a client cannot hold a connection with partial heads. The
//! streams of h3 are independent, so a head that is late ends its request alone, with a 408.
//!
//! `quic_body.zig` keeps the deadlines of the request bodies, and `quic_sends.zig` those of the
//! responses the peer has yet to take. Both are reported and fired from here.
const std = @import("std");
const assert = std.debug.assert;
const quic = @import("quic");
const h3 = @import("h3");
const deadline = @import("../deadline.zig");
const quic_connection = @import("quic_connection.zig");
const quic_connection_h3 = @import("quic_connection_h3.zig");
const internal = @import("quic_connection_internal.zig");
const quic_body = @import("quic_body.zig");
const quic_sends = @import("quic_sends.zig");

const QuicConnection = quic_connection.QuicConnection;
const Deadline = deadline.Deadline;

/// Where a connection stands for its deadlines.
pub const Clock = struct {
    /// The instant the connection started at, with its client's first datagram.
    opened_ns: u64,
    /// A whole request head arrived, so the first-request deadline no longer runs.
    first_request_read: bool,
    /// The instant the connection went idle, with no request open, or null while it is not idle.
    idle_since_ns: ?u64,
    /// The instant the first call saw the connection shutting down, from which the drain runs.
    drain_since_ns: ?u64,
    /// The deadline that closed the connection, once one has.
    timed_out: ?Deadline,

    pub fn init(now_ns: u64) Clock {
        return .{ .opened_ns = now_ns, .first_request_read = false, .idle_since_ns = null, .drain_since_ns = null, .timed_out = null };
    }
};

/// A whole request head arrived.
pub fn on_request(connection: *QuicConnection) void {
    connection.clock.first_request_read = true;
}

/// Notes at `now_ns` whether the connection is idle: it runs, its first request came, and no
/// request is open.
pub fn observe(connection: *QuicConnection, now_ns: u64) void {
    const clock = &connection.clock;
    // Decision 110: the drain runs from the first call that sees the shutdown.
    if (waits_to_close(connection) and clock.drain_since_ns == null) clock.drain_since_ns = now_ns;
    // Decision 110: the idle deadline runs between requests, after the first one.
    const idle = takes_requests(connection) and clock.first_request_read and !connection.requests.any_open();
    if (!idle) {
        clock.idle_since_ns = null;
    } else if (clock.idle_since_ns == null) {
        clock.idle_since_ns = now_ns;
    }
    quic_sends.observe(connection, now_ns);
}

/// The soonest instant a deadline passes, or null when none runs.
pub fn soonest(connection: *QuicConnection) ?u64 {
    if (!running(connection)) return null;
    const clock = &connection.clock;
    const limits = &connection.deadlines;
    var at: ?u64 = null;
    if (takes_requests(connection)) {
        if (!clock.first_request_read) at = earlier(at, clock.opened_ns, limits.first_request_ns);
        if (clock.idle_since_ns) |since| at = earlier(at, since, limits.idle_ns);
    }
    if (clock.drain_since_ns) |since| at = earlier(at, since, limits.drain_ns);
    if (head_wait(connection)) |wait| at = earlier(at, wait.since_ns, limits.head_ns);
    return quic_sends.soonest(connection, quic_body.soonest(connection, at));
}

/// Closes the connection when its first-request or idle deadline has passed at `now_ns`, answers
/// each request whose head or body is late, and closes a connection whose bodies together fell
/// short.
pub fn fire(connection: *QuicConnection, now_ns: u64) void {
    if (!running(connection)) return;
    const clock = &connection.clock;
    const limits = &connection.deadlines;
    if (clock.drain_since_ns) |since| {
        if (is_past(since, limits.drain_ns, now_ns)) return close(connection);
    }
    if (late_for_requests(connection, now_ns)) |passed| shut_down(connection, passed, now_ns);
    if (!running(connection)) return;
    fire_heads(connection, now_ns);
    if (!running(connection)) return;
    if (quic_body.fire(connection, now_ns)) |passed| return overload(connection, passed);
    if (!running(connection)) return;
    if (quic_sends.fire(connection, now_ns)) |passed| overload(connection, passed);
}

/// Answers each request whose head is late at `now_ns`.
fn fire_heads(connection: *QuicConnection, now_ns: u64) void {
    // Bounded: each pass stops reading one stream, and h3 holds `request_streams_max` of them.
    for (0..h3.constants.request_streams_max) |_| {
        const wait = head_wait(connection) orelse return;
        if (!is_past(wait.since_ns, connection.deadlines.head_ns, now_ns)) return;
        refuse_head(connection, wait.stream_id);
        // A response that failed the connection stopped it.
        if (!running(connection)) return;
    }
}

/// Closes a connection whose peer `passed` judged across its streams. RFC 9114 §10.5: an endpoint
/// "MAY treat activity that is suspicious as a connection error of type H3_EXCESSIVE_LOAD".
fn overload(connection: *QuicConnection, passed: Deadline) void {
    assert(running(connection));
    connection.clock.timed_out = passed;
    const failed = connection.h3.fail(&connection.transport, h3.constants.error_excessive_load);
    assert(failed == error.ConnectionFailed);
    internal.fail(connection);
}

/// Whether the deadlines run: the connection reads requests, and QUIC has not begun to close it.
fn running(connection: *const QuicConnection) bool {
    if (connection.stopped or connection.closed) return false;
    return connection.transport.termination.state == .active;
}

/// Whether the connection still takes new requests: it runs, and is not shutting down.
fn takes_requests(connection: *const QuicConnection) bool {
    return running(connection) and !connection.shutting_down;
}

/// Whether the connection runs only until its requests are done and its GOAWAY acknowledged.
fn waits_to_close(connection: *const QuicConnection) bool {
    return running(connection) and connection.shutting_down;
}

/// The first-request or idle deadline, when it has passed at `now_ns` on a connection that
/// still takes requests, or null.
fn late_for_requests(connection: *const QuicConnection, now_ns: u64) ?Deadline {
    if (!takes_requests(connection)) return null;
    const clock = &connection.clock;
    const limits = &connection.deadlines;
    if (!clock.first_request_read and is_past(clock.opened_ns, limits.first_request_ns, now_ns)) return .first_request;
    const since = clock.idle_since_ns orelse return null;
    return if (is_past(since, limits.idle_ns, now_ns)) .idle else null;
}

/// Ends a connection that brought no request in time. RFC 9114 §5.1: "Servers SHOULD NOT
/// actively keep connections open". §5.2: a server "SHOULD send a GOAWAY frame when the closing
/// of a connection is known in advance", so the client learns which requests the server did not
/// take. The close follows once the client acknowledged the GOAWAY, or at the drain deadline
/// (decision 110 as amended). Before h3 runs there is no stream to send one on, and the
/// connection closes at once (RFC 9000 §10.2.3).
fn shut_down(connection: *QuicConnection, passed: Deadline, now_ns: u64) void {
    assert(passed == .first_request or passed == .idle);
    connection.clock.timed_out = passed;
    connection.shutting_down = true;
    quic_connection_h3.shut_down(connection, now_ns);
}

/// The request stream that has waited longest for its head, once h3 runs.
fn head_wait(connection: *QuicConnection) ?h3.connection.HeadWait {
    if (!connection.started) return null;
    return connection.h3.oldest_head_wait();
}

fn earlier(current: ?u64, since: u64, limit: ?u64) ?u64 {
    const span = limit orelse return current;
    // `Deadlines.validate` bounds every limit, and the caller's instants stay far below the end of
    // a `u64` (design §4.2).
    assert(since <= std.math.maxInt(u64) - span);
    const at = since + span;
    return @min(current orelse at, at);
}

fn is_past(since: u64, limit: ?u64, now_ns: u64) bool {
    const span = limit orelse return false;
    // Decision 110: a deadline passes at its instant, not a nanosecond later.
    return now_ns >= since + span;
}

/// Closes a connection whose drain passed, with the requests it still holds. RFC 9114 §8.1 has
/// H3_NO_ERROR say a connection closes with no error to signal. A drain that a deadline began
/// keeps that deadline as the connection's reason.
fn close(connection: *QuicConnection) void {
    assert(waits_to_close(connection));
    if (connection.clock.timed_out == null) connection.clock.timed_out = .drain;
    quic.connection_close.owe(&connection.transport, .{
        .layer = .application,
        .error_code = connection.h3.no_error_code(),
        // RFC 9000 §19.19: only a transport close carries the Frame Type field.
        .frame_type = null,
        .reason = "",
    });
    internal.stop(connection);
    assert(!running(connection));
}

/// Answers a request whose head is late with a 408, and reads no more of it. RFC 9110 §15.5.9:
/// the server "did not receive a complete request message within the time that it was prepared
/// to wait". RFC 9114 §4.1: a server that needs no more of a request may "abort reading the
/// request stream, send a complete response, and cleanly close the sending part of the stream",
/// asking the client to stop with H3_NO_ERROR.
fn refuse_head(connection: *QuicConnection, stream_id: u64) void {
    connection.h3.stop_reading(&connection.transport, stream_id, connection.h3.no_error_code());
    const record = connection.requests.take(stream_id) orelse return reject(connection, stream_id);
    if (!quic_connection_h3.respond_timeout(connection, stream_id)) {
        record.in_use = false;
        return reject(connection, stream_id);
    }
    // The caller never heard of the request, so nothing is reported of it, and its record only
    // waits for the stream to close.
    record.over = true;
    record.ended = true;
}

/// RFC 9114 §4.1.1: a request the server cancels "without performing any application processing"
/// is rejected, with H3_REQUEST_REJECTED. It is what a late head gets when no response fits.
fn reject(connection: *QuicConnection, stream_id: u64) void {
    connection.h3.cancel(&connection.transport, stream_id, h3.constants.error_request_rejected);
}
