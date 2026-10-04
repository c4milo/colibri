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
const std = @import("std");
const assert = std.debug.assert;
const quic = @import("quic");
const h3 = @import("h3");
const http = @import("http");
const deadline = @import("../deadline.zig");
const quic_connection = @import("quic_connection.zig");
const quic_connection_h3 = @import("quic_connection_h3.zig");
const internal = @import("quic_connection_internal.zig");

const QuicConnection = quic_connection.QuicConnection;
const Deadline = deadline.Deadline;

/// RFC 9110 §15.5.9: 408 (Request Timeout).
const request_timeout: u16 = @intFromEnum(http.status.Code.request_timeout);

/// Where a connection stands for its deadlines.
pub const Clock = struct {
    /// The instant the connection started at, with its client's first datagram.
    opened_ns: u64,
    /// A whole request head arrived, so the first-request deadline no longer runs.
    first_request_read: bool,
    /// The instant the connection went idle, with no request open, or null while it is not idle.
    idle_since_ns: ?u64,
    /// The deadline that closed the connection, once one has.
    timed_out: ?Deadline,

    pub fn init(now_ns: u64) Clock {
        return .{ .opened_ns = now_ns, .first_request_read = false, .idle_since_ns = null, .timed_out = null };
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
    // Decision 110: the idle deadline runs between requests, after the first one.
    const idle = running(connection) and clock.first_request_read and !connection.requests.any_open();
    if (!idle) {
        clock.idle_since_ns = null;
    } else if (clock.idle_since_ns == null) {
        clock.idle_since_ns = now_ns;
    }
}

/// The soonest instant a deadline passes, or null when none runs.
pub fn soonest(connection: *QuicConnection) ?u64 {
    if (!running(connection)) return null;
    const clock = &connection.clock;
    const limits = &connection.deadlines;
    var at: ?u64 = null;
    if (!clock.first_request_read) at = earlier(at, clock.opened_ns, limits.first_request_ns);
    if (clock.idle_since_ns) |since| at = earlier(at, since, limits.idle_ns);
    if (head_wait(connection)) |wait| at = earlier(at, wait.since_ns, limits.head_ns);
    return at;
}

/// Closes the connection when its first-request or idle deadline has passed at `now_ns`, and
/// answers each request whose head is late.
pub fn fire(connection: *QuicConnection, now_ns: u64) void {
    if (!running(connection)) return;
    const clock = &connection.clock;
    const limits = &connection.deadlines;
    if (!clock.first_request_read and is_past(clock.opened_ns, limits.first_request_ns, now_ns)) {
        return close(connection, .first_request);
    }
    if (clock.idle_since_ns) |since| {
        if (is_past(since, limits.idle_ns, now_ns)) return close(connection, .idle);
    }
    // Bounded: each pass stops reading one stream, and h3 holds `request_streams_max` of them.
    for (0..h3.constants.request_streams_max) |_| {
        const wait = head_wait(connection) orelse return;
        if (!is_past(wait.since_ns, limits.head_ns, now_ns)) return;
        refuse_head(connection, wait.stream_id);
    }
}

/// Whether the deadlines run: the connection reads requests, and QUIC has not begun to close it.
fn running(connection: *const QuicConnection) bool {
    if (connection.stopped or connection.closed) return false;
    return connection.transport.termination.state == .active;
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

/// Closes a connection that brought no request in time. RFC 9114 §5.1: "Servers SHOULD NOT
/// actively keep connections open", and §8.1 has H3_NO_ERROR say a connection closes with no
/// error to signal. The GOAWAY that decision 110 puts before this close is not sent yet: `quic`
/// writes a CONNECTION_CLOSE alone once it owes one, and the last part of design §8 step 20c
/// owns it (https://github.com/c4milo/colibri/issues/95).
fn close(connection: *QuicConnection, passed: Deadline) void {
    assert(passed == .first_request or passed == .idle);
    connection.clock.timed_out = passed;
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
    quic_connection_h3.respond(connection, stream_id, .{ .status = request_timeout, .end = true }) catch {
        record.in_use = false;
        return reject(connection, stream_id);
    };
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
