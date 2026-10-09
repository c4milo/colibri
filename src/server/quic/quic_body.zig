//! The request bodies a server connection over QUIC waits on its peer for (decision 110 as
//! amended, design §8 step 20c): each body's rate meter and cap, and the meter of all of them
//! together, as `connection_bodies.zig` keeps them over TCP.
//!
//! A body's wait starts at the call that reads its request's head, and ends with the request's
//! content or with its stream. Only the content's own octets count: the data of its DATA frames
//! (RFC 9114 §7.2.1), and only while the caller still hears of the request.
//!
//! A body that falls short ends its request alone, because h3's streams are independent:
//! - with no final response begun, the request gets a 408, and the server asks the client to stop
//!   sending with H3_NO_ERROR (RFC 9114 §4.1);
//! - with a final response begun and not ended, the server resets the stream with
//!   H3_REQUEST_CANCELLED (§4.1.1);
//! - with a response ended, the server asks the client to stop, and the response goes on.
//!
//! The caller reads `cancelled` for a request whose response had not ended. When the bodies
//! together fall short, the connection closes with H3_EXCESSIVE_LOAD (RFC 9114 §10.5), as an h2
//! connection does with ENHANCE_YOUR_CALM.
const std = @import("std");
const assert = std.debug.assert;
const h3 = @import("h3");
const constants = @import("../constants.zig");
const deadline = @import("../deadline.zig");
const rate = @import("../rate.zig");
const connection_sends = @import("../connection/connection_sends.zig");
const quic_connection = @import("quic_connection.zig");
const quic_connection_h3 = @import("quic_connection_h3.zig");
const quic_coding = @import("quic_coding.zig");
const quic_request = @import("quic_request.zig");

const QuicConnection = quic_connection.QuicConnection;
const Request = quic_request.Request;
const Deadline = deadline.Deadline;

/// One body the connection waits for.
const Body = struct {
    /// Whether the wait runs, since `since_ns`.
    waiting: bool = false,
    since_ns: u64 = 0,
    meter: rate.Meter = .{},
};

pub const Bodies = struct {
    /// One entry for each request record, at the record's index.
    entries: [constants.quic_requests_max]Body,
    /// The bodies the connection waits for, and the meter of their octets together.
    waiting: u32,
    together: rate.Meter,

    pub fn init(bodies: *Bodies) void {
        bodies.entries = @splat(.{});
        bodies.waiting = 0;
        bodies.together = .{};
    }
};

/// The head of `record`'s request arrived at `now_ns`, so the wait for its content starts.
pub fn add(connection: *QuicConnection, record: *const Request, now_ns: u64) void {
    const bodies = &connection.bodies;
    const limits = &connection.deadlines;
    const body = &bodies.entries[connection.requests.index_of(record)];
    assert(!body.waiting);
    body.* = .{ .waiting = true, .since_ns = now_ns };
    body.meter.start(now_ns, limits.rate_grace_ns, limits.rate_window_ns);
    if (bodies.waiting == 0) bodies.together.start(now_ns, limits.rate_grace_ns, limits.rate_window_ns);
    bodies.waiting += 1;
}

/// The content of `record`'s request ended, or the request did.
pub fn remove(connection: *QuicConnection, record: *const Request) void {
    const bodies = &connection.bodies;
    const body = &bodies.entries[connection.requests.index_of(record)];
    if (!body.waiting) return;
    body.* = .{};
    assert(bodies.waiting > 0);
    bodies.waiting -= 1;
    if (bodies.waiting == 0) bodies.together.stop();
}

/// Whether the connection waits for the content of `record`'s request.
pub fn waits(connection: *const QuicConnection, record: *const Request) bool {
    return connection.bodies.entries[connection.requests.index_of(record)].waiting;
}

/// Counts `octets` of the content of `record`'s request, which arrived at the instant `fire` last
/// moved the meters to.
pub fn count(connection: *QuicConnection, record: *const Request, octets: usize) void {
    const bodies = &connection.bodies;
    const body = &bodies.entries[connection.requests.index_of(record)];
    if (!body.waiting) return;
    body.meter.count(octets);
    bodies.together.count(octets);
}

/// Stops each body's meter, and the meter of them together, while colibri holds credit its client
/// needs, and starts them at `now_ns` with a grace period once it is out, as h2's are (decision
/// 110 as amended). The caps keep running.
pub fn observe(connection: *QuicConnection, credit_held: bool, now_ns: u64) void {
    const bodies = &connection.bodies;
    if (bodies.waiting == 0) return;
    const limits = &connection.deadlines;
    for (&bodies.entries) |*body| {
        if (body.waiting) connection_sends.start_or_stop(&body.meter, !credit_held, now_ns, limits);
    }
    connection_sends.start_or_stop(&bodies.together, !credit_held, now_ns, limits);
}

/// The soonest instant a body deadline passes, or `current` when it is sooner or none does.
pub fn soonest(connection: *const QuicConnection, current: ?u64) ?u64 {
    const bodies = &connection.bodies;
    if (bodies.waiting == 0) return current;
    const limits = &connection.deadlines;
    const quota = limits.body_quota();
    var at = current;
    for (&bodies.entries) |*body| {
        if (!body.waiting) continue;
        if (limits.body_ns) |cap_ns| at = earlier(at, body.since_ns + cap_ns);
        at = earlier_check(at, &body.meter, quota, limits.rate_window_ns);
    }
    return earlier_check(at, &bodies.together, quota, limits.rate_window_ns);
}

fn earlier(current: ?u64, candidate: u64) u64 {
    return @min(current orelse candidate, candidate);
}

/// `current`, or the instant `meter` next looks at a window when that is sooner.
fn earlier_check(current: ?u64, meter: *const rate.Meter, quota: ?u64, window_ns: u64) ?u64 {
    const check_ns = meter.check_ns(quota orelse return current, window_ns) orelse return current;
    return earlier(current, check_ns);
}

/// Ends each request whose body deadline passed at `now_ns`, and returns `body_rate` when the
/// bodies together fell short, which ends the connection. Null when it goes on.
pub fn fire(connection: *QuicConnection, now_ns: u64) ?Deadline {
    const bodies = &connection.bodies;
    if (bodies.waiting == 0) return null;
    const limits = &connection.deadlines;
    for (&bodies.entries, 0..) |*body, index| {
        if (!body.waiting) continue;
        const passed = passed_of(limits, body, now_ns) orelse continue;
        end_request(connection, index, passed);
        // A response that failed the connection stopped it, and no record is held any more.
        if (connection.stopped) return null;
    }
    const quota = limits.body_quota() orelse return null;
    // Decision 110 as amended: h3 checks the minimum rate across the connection too, as h2 does,
    // so many slow streams do not each take a whole grace period and window.
    if (bodies.together.short(now_ns, quota, limits.rate_window_ns)) return .body_rate;
    return null;
}

/// The deadline of `body` that passed at `now_ns`, the cap first, or null. It moves the meter to
/// `now_ns`.
fn passed_of(limits: *const deadline.Deadlines, body: *Body, now_ns: u64) ?Deadline {
    if (limits.body_ns) |cap_ns| {
        // Decision 110: a deadline passes at its instant, not a nanosecond later.
        if (now_ns >= body.since_ns + cap_ns) return .body;
    }
    const quota = limits.body_quota() orelse return null;
    return if (body.meter.short(now_ns, quota, limits.rate_window_ns)) .body_rate else null;
}

/// Ends the wait for the body of the request at `index`, whose deadline `passed`, and reads no
/// more of the request.
fn end_request(connection: *QuicConnection, index: usize, passed: Deadline) void {
    const record = &connection.requests.records[index];
    assert(record.in_use and !record.ended);
    remove(connection, record);
    const stream_id = record.stream_id;
    if (record.over or record.finished) {
        // RFC 9114 §4.1: a server that "does not need to receive the remainder of the request"
        // may "abort reading the request stream", with H3_NO_ERROR. Its response is whole.
        return connection.h3.stop_reading(&connection.transport, stream_id, connection.h3.no_error_code());
    }
    if (!record.answered and quic_connection_h3.respond_timeout(connection, stream_id)) {
        // RFC 9114 §4.1: after a complete response, the server asks the client to stop.
        connection.h3.stop_reading(&connection.transport, stream_id, connection.h3.no_error_code());
    } else {
        // RFC 9114 §4.1.1: a server that abandons a response it began "SHOULD abort its response
        // stream with the error code H3_REQUEST_CANCELLED".
        connection.h3.cancel(&connection.transport, stream_id, h3.constants.error_request_cancelled);
    }
    record.over = true;
    quic_coding.give_back(connection, record);
    connection.owed.push(.{ .kind = .{ .cancelled = .{ .deadline = passed } }, .id = stream_id });
}
