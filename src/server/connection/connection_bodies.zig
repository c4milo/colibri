//! The request bodies a server connection over TCP waits on its peer for (decision 110, design §8
//! step 20b): each body's rate meter and cap, and in h2 the meter of all of them together. A
//! body's wait starts at the first call after its head is read that sees no 100 (Continue) owed
//! to it, and ends with the body or with its request.
//!
//! Only a body's own octets count: in h11 the octets h11 reads while it reads the body, its
//! framing included, and in h2 the octets of its DATA frames' data, without padding. In h2 the
//! rate waits while colibri holds a WINDOW_UPDATE the peer has not been handed, owed or in the
//! output: the peer's upload then waits on its reading, which the send deadline judges, and the
//! rate starts again with a grace period once the update is out (decision 110 as amended). The
//! cap does not wait.
//!
//! In h11 a body that falls short ends the connection, with a 408 when its response has not
//! begun. In h2 it ends its stream: a 408 that ends the stream and then RST_STREAM with NO_ERROR,
//! or RST_STREAM with CANCEL when the response has begun, and the caller reads `cancelled` for its
//! request. When the bodies together fall short, the h2 connection ends with ENHANCE_YOUR_CALM.
const std = @import("std");
const assert = std.debug.assert;
const h2 = @import("h2");
const http = @import("http");
const constants = @import("../constants.zig");
const event = @import("../event.zig");
const deadline = @import("../deadline.zig");
const rate = @import("../rate.zig");
const connection_module = @import("connection.zig");
const internal = @import("connection_internal.zig");
const connection_coding = @import("connection_coding.zig");
const connection_sends = @import("connection_sends.zig");

const Connection = connection_module.Connection;
const Number = event.Number;
const Deadline = deadline.Deadline;

/// RFC 9110 §15.5.9: 408 (Request Timeout).
const request_timeout: u16 = @intFromEnum(http.status.Code.request_timeout);

/// One body the connection waits for.
const Body = struct {
    /// The request, or 0 for a free entry.
    id: Number = 0,
    /// Whether the wait has started, at `since_ns`: a body owed a 100 (Continue) waits for it.
    started: bool = false,
    since_ns: u64 = 0,
    meter: rate.Meter = .{},
};

pub const Bodies = struct {
    entries: [constants.bodies_max]Body,
    /// The bodies whose wait has started, and in h2 the meter of their octets together.
    waiting: u32,
    together: rate.Meter,
    /// The requests an h2 body deadline ended, oldest first, which `receive` reports before it
    /// reads more.
    cancelled: [constants.bodies_max]Owed,
    cancelled_first: u32,
    cancelled_len: u32,

    pub fn init(bodies: *Bodies) void {
        bodies.entries = @splat(.{});
        bodies.waiting = 0;
        bodies.together = .{};
        bodies.cancelled_first = 0;
        bodies.cancelled_len = 0;
    }

    fn find(bodies: *Bodies, id: Number) ?*Body {
        assert(id != 0);
        return bodies.find_id(id);
    }

    fn find_free(bodies: *Bodies) ?*Body {
        return bodies.find_id(0);
    }

    fn find_id(bodies: *Bodies, id: Number) ?*Body {
        for (&bodies.entries) |*body| {
            if (body.id == id) return body;
        }
        return null;
    }
};

/// Request `id`'s head said a body follows.
pub fn add(connection: *Connection, id: Number) void {
    const bodies = &connection.bodies;
    assert(bodies.find(id) == null);
    // h11 reads one request at a time, and h2 holds `concurrent_streams_max` streams, so a body
    // always finds a free entry.
    const free = bodies.find_free() orelse unreachable;
    free.* = .{ .id = id };
}

/// Request `id`'s body ended, or the request did.
pub fn remove(connection: *Connection, id: Number) void {
    const bodies = &connection.bodies;
    const body = bodies.find(id) orelse return;
    if (body.started) {
        assert(bodies.waiting > 0);
        bodies.waiting -= 1;
        if (bodies.waiting == 0) bodies.together.stop();
    }
    body.* = .{};
}

/// Counts `octets` of request `id`'s body, which arrived at the instant `fire` last moved the
/// meters to. A body's own meter counts nothing before its wait starts, and the bodies' meter
/// counts them while any body waits.
pub fn count(connection: *Connection, id: Number, octets: usize) void {
    const bodies = &connection.bodies;
    const body = bodies.find(id) orelse return;
    body.meter.count(octets);
    bodies.together.count(octets);
}

/// Starts the wait of every body whose head was read and which owes no 100 (Continue), and
/// pauses or resumes the rates, at `now_ns`.
pub fn observe(connection: *Connection, now_ns: u64) void {
    const bodies = &connection.bodies;
    const limits = &connection.deadlines;
    for (&bodies.entries) |*body| {
        if (body.id == 0 or body.started) continue;
        // RFC 9110 §10.1.1: a client that expects 100 (Continue) waits for it before it sends the
        // content, so the wait starts once the 100 is written.
        if (connection.continue_owed == body.id) continue;
        body.started = true;
        body.since_ns = now_ns;
        bodies.waiting += 1;
    }
    if (bodies.waiting == 0) return;
    const rates_run = !update_held(connection);
    for (&bodies.entries) |*body| {
        if (body.started) connection_sends.start_or_stop(&body.meter, rates_run, now_ns, limits);
    }
    if (connection.session == .h2) connection_sends.start_or_stop(&bodies.together, rates_run, now_ns, limits);
}

/// Whether colibri holds a WINDOW_UPDATE its h2 peer has not been handed: owed, or in the output.
fn update_held(connection: *const Connection) bool {
    if (connection.session != .h2) return false;
    return connection.update_held_len > 0 or connection.session.h2.owes_window_update();
}

/// The soonest instant a body deadline passes, or `current` when it is sooner or none does.
pub fn soonest(connection: *const Connection, current: ?u64) ?u64 {
    const bodies = &connection.bodies;
    const limits = &connection.deadlines;
    var at = current;
    for (&bodies.entries) |*body| {
        if (!body.started) continue;
        if (limits.body_ns) |cap_ns| at = earlier(at, body.since_ns + cap_ns);
        const quota = limits.body_quota() orelse continue;
        // A body's rate waits while colibri holds a WINDOW_UPDATE, and its meter is stopped.
        if (body.meter.check_ns(quota, limits.rate_window_ns)) |check_ns| at = earlier(at, check_ns);
    }
    if (limits.body_quota()) |quota| {
        if (bodies.together.check_ns(quota, limits.rate_window_ns)) |check_ns| at = earlier(at, check_ns);
    }
    return at;
}

fn earlier(current: ?u64, candidate: u64) u64 {
    return @min(current orelse candidate, candidate);
}

/// Ends each h2 stream whose body deadline passed at `now_ns`, and returns the deadline that ends
/// the connection: an h11 body's, or in h2 the bodies' together. Null when none does.
pub fn fire(connection: *Connection, now_ns: u64) ?Deadline {
    const bodies = &connection.bodies;
    for (&bodies.entries) |*body| {
        if (!body.started) continue;
        const passed = passed_of(connection, body, now_ns) orelse continue;
        if (connection.session == .h11) return passed;
        cancel_stream(connection, body.id, passed);
    }
    const quota = connection.deadlines.body_quota() orelse return null;
    // Decision 110: h2 checks the minimum rate across the connection too, so many slow streams do
    // not each take a whole grace period and window.
    if (bodies.together.short(now_ns, quota, connection.deadlines.rate_window_ns)) return .body_rate;
    return null;
}

/// The deadline of `body` that passed at `now_ns`, the cap first, or null. It moves the meter to
/// `now_ns`.
fn passed_of(connection: *const Connection, body: *Body, now_ns: u64) ?Deadline {
    const limits = &connection.deadlines;
    if (limits.body_ns) |cap_ns| {
        // Decision 110: a deadline passes at its instant, not a nanosecond later.
        if (now_ns >= body.since_ns + cap_ns) return .body;
    }
    const quota = limits.body_quota() orelse return null;
    return if (body.meter.short(now_ns, quota, limits.rate_window_ns)) .body_rate else null;
}

/// Ends request `id`'s h2 stream for `passed`, and owes the caller its `cancelled` event.
fn cancel_stream(connection: *Connection, id: Number, passed: Deadline) void {
    const session = &connection.session.h2;
    const stream_id: u32 = @intCast(id);
    // RFC 9110 §15.5.9: a server that did not receive a complete request in the time it was
    // prepared to wait answers 408. RFC 9113 §8.1: after a complete response, RST_STREAM with
    // NO_ERROR asks the client to stop sending the request; a response that began, or found no
    // room, is cut short with CANCEL (RFC 9113 §6.4).
    const code = if (write_timeout(connection, stream_id)) h2.constants.error_no_error else h2.constants.error_cancel;
    session.reset_stream(stream_id, code) catch |failure| {
        assert(failure == error.StreamNotSendable);
    };
    connection_coding.forget(connection, id);
    connection_sends.remove(connection, id);
    remove(connection, id);
    owe_cancelled(connection, .{ .id = id, .reason = .{ .deadline = passed } });
}

/// Writes a 408 that ends the stream, and returns whether it went into the output. h2 refuses one
/// after the final response.
fn write_timeout(connection: *Connection, stream_id: u32) bool {
    const written = connection.session.h2.write_response(internal.room(connection), stream_id, request_timeout, &.{}, true) catch {
        return false;
    };
    connection.output_len += written;
    return true;
}

/// A `cancelled` event a deadline owes: the request's number, so the ring stays the size it was
/// before ids named their connection (decision 119), and why.
pub const Owed = struct {
    id: Number,
    reason: event.CancelReason,
};

/// Owes the caller `cancelled`, for a request a deadline ended.
pub fn owe_cancelled(connection: *Connection, cancelled: Owed) void {
    const bodies = &connection.bodies;
    // Each request is cancelled once, and the ring holds one for each h2 stream.
    assert(bodies.cancelled_len < bodies.cancelled.len);
    const slot = (bodies.cancelled_first + bodies.cancelled_len) % bodies.cancelled.len;
    bodies.cancelled[slot] = cancelled;
    bodies.cancelled_len += 1;
}

/// The oldest `cancelled` event a body deadline owes, which the call takes, or null.
pub fn take_cancelled(connection: *Connection) ?event.Cancelled {
    const bodies = &connection.bodies;
    if (bodies.cancelled_len == 0) return null;
    const owed = bodies.cancelled[bodies.cancelled_first];
    bodies.cancelled_first = @intCast((bodies.cancelled_first + 1) % bodies.cancelled.len);
    bodies.cancelled_len -= 1;
    return .{ .id = event.id_of(owed.id), .reason = owed.reason };
}
