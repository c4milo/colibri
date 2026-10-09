//! The deadlines of one server connection over TCP (decision 110, design §8 step 20b): the instant
//! each started at, the soonest one the caller wakes for, and what the connection does when one
//! passes. A deadline starts at the instant of the first call that sees what starts it, `receive`,
//! `send` or `on_instant`, because `respond` and `write_body` take no instant.
//!
//! Only request octets move a deadline. A head's first octet ends the idle wait and starts the
//! head deadline, and a whole head ends both. Nothing else the peer sends, such as an h2 PING or
//! SETTINGS frame, starts or ends one. While a request is open only its body's deadlines run
//! (`connection_bodies.zig`), because the connection otherwise waits on the application.
const std = @import("std");
const assert = std.debug.assert;
const h11 = @import("h11");
const h2 = @import("h2");
const http = @import("http");
const deadline = @import("../deadline.zig");
const connection_module = @import("connection.zig");
const connection_close = @import("connection_close.zig");
const connection_bodies = @import("connection_bodies.zig");
const connection_sends = @import("connection_sends.zig");

const Connection = connection_module.Connection;
const Deadline = deadline.Deadline;
const Deadlines = deadline.Deadlines;

/// RFC 9110 §15.5.9: 408 (Request Timeout).
const request_timeout: u16 = @intFromEnum(http.status.Code.request_timeout);

/// Where a connection stands for its deadlines.
pub const Clock = struct {
    opened_ns: u64,
    /// A whole request head has arrived, so the first-request deadline no longer runs.
    first_request_read: bool,
    /// The instant the first octet of the current request head was seen, or null.
    head_since_ns: ?u64,
    /// The instant the connection went idle after a response, or null while it is not idle.
    idle_since_ns: ?u64,
    /// The deadline that ended the connection, once one has.
    timed_out: ?Deadline,
    /// The instant the connection ended with octets still to send, and whether `linger_ns` has
    /// passed since, after which it closes with them unsent (decision 110).
    linger_since_ns: ?u64,
    lingered: bool,
    /// How long h2's SETTINGS deadline has waited while bodies arrived, and since when it waits
    /// now (decision 110 as amended).
    settings_paused_ns: u64,
    settings_pause_since_ns: ?u64,
    /// The instant the first call after `shutdown` saw it, from which the drain runs.
    drain_since_ns: ?u64,

    pub fn init(now_ns: u64) Clock {
        return .{
            .opened_ns = now_ns,
            .first_request_read = false,
            .head_since_ns = null,
            .idle_since_ns = null,
            .timed_out = null,
            .linger_since_ns = null,
            .lingered = false,
            .settings_paused_ns = 0,
            .settings_pause_since_ns = null,
            .drain_since_ns = null,
        };
    }
};

/// What the connection waits for, read from its protocol.
const Wait = enum {
    /// The TLS handshake, or nothing: the connection is closed.
    handshake,
    /// The rest of a request head that has begun.
    head,
    /// The next request, with none open.
    idle,
    /// The application, or the rest of a request that is open.
    request,
};

fn wait_of(connection: *const Connection) Wait {
    if (connection.phase != .open) return .handshake;
    return switch (connection.session) {
        .h11 => |*session| wait_h11(session),
        .h2 => |*session| wait_h2(session),
        .none => .handshake,
    };
}

fn wait_h11(session: *const h11.Connection) Wait {
    if (session.phase != .head) return .request;
    return if (session.scanner.scanned > 0) .head else .idle;
}

fn wait_h2(session: *const h2.Connection) Wait {
    // RFC 9113 §6.10: a field block that is not whole holds the connection until its last
    // CONTINUATION frame.
    if (session.block.is_in_progress()) return .head;
    return if (session.streams.peer_active == 0) .idle else .request;
}

/// A whole request head arrived. `observe` ends the head's deadline.
pub fn on_request(connection: *Connection) void {
    connection.clock.first_request_read = true;
}

/// Notes the waits that began or ended since the last call, at `now_ns`.
pub fn observe(connection: *Connection, now_ns: u64) void {
    const clock = &connection.clock;
    const wait = wait_of(connection);
    if (wait != .head) {
        clock.head_since_ns = null;
    } else if (clock.head_since_ns == null) {
        clock.head_since_ns = now_ns;
    }
    // Decision 110: the idle deadline runs between requests, after the first one. It starts once
    // the last response's octets are out, since until then the connection waits on the peer to
    // read them, and colibri's own frames written later do not stop it.
    const idle = wait == .idle and clock.first_request_read;
    if (!idle) {
        clock.idle_since_ns = null;
    } else if (clock.idle_since_ns == null and connection.output_len == 0) {
        clock.idle_since_ns = now_ns;
    }
    connection_bodies.observe(connection, now_ns);
    connection_sends.observe(connection, now_ns);
    observe_settings(connection, now_ns);
    // Decision 110: the drain runs from the first call that sees the shutdown.
    if (connection.shutting_down and clock.drain_since_ns == null) clock.drain_since_ns = now_ns;
    // Decision 110: every close is bounded, from the instant the connection ended with octets
    // still to send.
    const ended = connection.stopped or connection.phase == .closed or connection_close.finished(connection);
    if (clock.linger_since_ns == null and ended and connection.output_len > 0) clock.linger_since_ns = now_ns;
}

/// The soonest instant a deadline passes, or null when none runs.
pub fn soonest(connection: *const Connection) ?u64 {
    const linger_end = linger_end_ns(connection);
    if (!running(connection)) return linger_end;
    const clock = &connection.clock;
    const limits = &connection.deadlines;
    var at: ?u64 = null;
    if (!clock.first_request_read) at = earlier(at, clock.opened_ns, limits.first_request_ns);
    if (clock.head_since_ns) |since| at = earlier(at, since, limits.head_ns);
    if (clock.idle_since_ns) |since| at = earlier(at, since, limits.idle_ns);
    if (clock.drain_since_ns) |since| at = earlier(at, since, limits.drain_ns);
    if (settings_deadline_ns(connection)) |settings_ns| at = @min(at orelse settings_ns, settings_ns);
    at = connection_sends.soonest(connection, connection_bodies.soonest(connection, at));
    const end_ns = linger_end orelse return at;
    return @min(at orelse end_ns, end_ns);
}

/// The instant a connection's linger passes, or null when none runs.
fn linger_end_ns(connection: *const Connection) ?u64 {
    const clock = &connection.clock;
    if (clock.lingered) return null;
    const since_ns = clock.linger_since_ns orelse return null;
    const limit_ns = connection.deadlines.linger_ns orelse return null;
    return since_ns + limit_ns;
}

/// Whether the deadlines run: the connection reads on, and its protocol has not closed.
fn running(connection: *const Connection) bool {
    // `end` stops the connection, so a deadline that fired runs no more.
    if (connection.stopped or connection.phase == .closed) return false;
    return switch (connection.session) {
        // RFC 9112 §9.3: h11 closes after a response whose request it did not read whole.
        .h11 => |*session| session.phase != .closed,
        .h2 => |*session| !session.has_failed(),
        .none => true,
    };
}

fn earlier(current: ?u64, since: u64, limit: ?u64) ?u64 {
    const span = limit orelse return current;
    // `Deadlines.validate` bounds every limit, and the caller's instants stay far below the end of
    // a `u64` (design §4.2).
    assert(since <= std.math.maxInt(u64) - span);
    const at = since + span;
    return @min(current orelse at, at);
}

/// Pauses h2's SETTINGS deadline while a request body arrives, since a client's acknowledgment
/// goes out behind the DATA it queued first, and resumes it when none does (decision 110 as
/// amended). The server sends SETTINGS once, so the pauses count toward that frame alone.
fn observe_settings(connection: *Connection, now_ns: u64) void {
    const clock = &connection.clock;
    if (h2_settings_deadline_ns(connection) == null) return;
    const arriving = connection.bodies.waiting > 0;
    if (arriving and clock.settings_pause_since_ns == null) clock.settings_pause_since_ns = now_ns;
    if (!arriving) {
        const since_ns = clock.settings_pause_since_ns orelse return;
        clock.settings_paused_ns += now_ns - since_ns;
        clock.settings_pause_since_ns = null;
    }
}

fn h2_settings_deadline_ns(connection: *const Connection) ?u64 {
    return switch (connection.session) {
        .h2 => |*session| session.settings_deadline_ns(),
        .h11, .none => null,
    };
}

/// The instant h2's SETTINGS acknowledgment is overdue, the pauses added, or null while none is
/// owed or a body arrives (RFC 9113 §6.5.3).
fn settings_deadline_ns(connection: *const Connection) ?u64 {
    if (connection.clock.settings_pause_since_ns != null) return null;
    const deadline_ns = h2_settings_deadline_ns(connection) orelse return null;
    return deadline_ns + connection.clock.settings_paused_ns;
}

/// The deadline that has passed at `now_ns`, or null.
fn due(connection: *const Connection, now_ns: u64) ?Deadline {
    if (!running(connection)) return null;
    const clock = &connection.clock;
    const limits = &connection.deadlines;
    if (!clock.first_request_read and is_past(clock.opened_ns, limits.first_request_ns, now_ns)) {
        return .first_request;
    }
    if (clock.head_since_ns) |since| {
        if (is_past(since, limits.head_ns, now_ns)) return .head;
    }
    if (clock.idle_since_ns) |since| {
        if (is_past(since, limits.idle_ns, now_ns)) return .idle;
    }
    if (clock.drain_since_ns) |since| {
        if (is_past(since, limits.drain_ns, now_ns)) return .drain;
    }
    // RFC 9113 §6.5.3: a SETTINGS frame not acknowledged within a reasonable time may be a
    // connection error of SETTINGS_TIMEOUT; decision 110 as amended pauses it while a body arrives.
    const settings_ns = settings_deadline_ns(connection) orelse return null;
    if (now_ns >= settings_ns) return .settings;
    return null;
}

fn is_past(since: u64, limit: ?u64, now_ns: u64) bool {
    const span = limit orelse return false;
    // Decision 110: a deadline passes at its instant, not a nanosecond later.
    return now_ns >= since + span;
}

/// Ends the connection when a deadline has passed at `now_ns`, and returns whether one had. An h2
/// body's deadline ends its stream alone.
pub fn fire(connection: *Connection, now_ns: u64) bool {
    connection_sends.linger(connection, now_ns);
    if (!running(connection)) return false;
    const passed = due(connection, now_ns) orelse connection_bodies.fire(connection, now_ns) orelse
        connection_sends.fire(connection, now_ns) orelse return false;
    connection.clock.timed_out = passed;
    end(connection, passed);
    assert(!running(connection));
    return true;
}

/// What a deadline does (decision 110): a head that began, or a body that did not arrive in time,
/// gets a 408 in h11, and in h2 a GOAWAY with ENHANCE_YOUR_CALM; a peer that takes too little of
/// what the connection sends ends h11 with nothing more and h2 with the same GOAWAY; with none of
/// these, h11 closes without a response and h2 sends a GOAWAY with NO_ERROR first. Nothing more is
/// read either way.
fn end(connection: *Connection, passed: Deadline) void {
    const wait = wait_of(connection);
    const body = passed == .body_rate or passed == .body;
    const send = passed == .send_rate;
    connection.stopped = true;
    if (wait == .handshake) {
        // No protocol serves the connection: its TLS handshake had not completed, or its first
        // octets had not chosen. It closes with nothing more written, whichever deadline passed.
        connection.phase = .closed;
        return;
    }
    // Decision 110: a drain that passes closes the connection. h2's GOAWAY went out with the
    // shutdown (RFC 9113 §6.8), and h11 says nothing more.
    if (passed == .drain) return;
    switch (connection.session) {
        .h11 => |*session| {
            // RFC 9110 §15.5.9: 408 says the server did not receive a complete request in the time
            // it was prepared to wait; h11 writes none after a response began. RFC 9112 §9.5: an
            // idle connection closes without one, since a 408 there could be read as the answer to
            // a request the client sent meanwhile.
            if (wait == .head or body) {
                const failure = session.fail(error.RequestTimeout, request_timeout);
                assert(failure == error.ConnectionFailed);
            }
            // RFC 9112 §9.6: a server that closes sends nothing after it; a 408 would wait behind
            // the octets the peer has not taken.
            if (send) {
                const failure = session.fail(error.SendTimeout, null);
                assert(failure == error.ConnectionFailed);
            }
        },
        .h2 => |*session| {
            // RFC 9113 §10.5: a field block held open past its deadline, bodies that together
            // arrive under the minimum rate, and a peer that takes too little of what it asked
            // for are excess use of the connection. RFC 9113 §9.1: a server that closes an idle
            // connection sends GOAWAY.
            if (passed == .settings) {
                const failure = session.fail(h2.constants.error_settings_timeout);
                assert(failure == error.ConnectionFailed);
            } else if (wait == .head or body or send) {
                const failure = session.fail(h2.constants.error_enhance_your_calm);
                assert(failure == error.ConnectionFailed);
            } else {
                session.shutdown(h2.constants.error_no_error);
            }
        },
        .none => unreachable,
    }
}
