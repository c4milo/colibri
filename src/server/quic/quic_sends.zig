//! The send deadlines of a server connection over QUIC (decision 110 as amended, design §8 step
//! 20c), as `connection_sends.zig` keeps them over TCP.
//!
//! A QUIC peer takes a response's octets by acknowledging them, and lets them leave by the credit
//! it gives the stream and the connection (RFC 9000 §4.1, §13.2). So the meters count the octets
//! the peer acknowledged:
//! - While any response holds octets the peer may take and has not acknowledged, the peer must
//!   acknowledge the minimum send rate over each window, across the responses. A peer that falls
//!   short acknowledges too little, or holds the responses with the connection's credit, and the
//!   connection closes with H3_EXCESSIVE_LOAD (RFC 9114 §10.5).
//! - A response its stream's credit does not cover has a meter of its own, which counts what the
//!   peer acknowledges of it. It runs only while no other response holds octets the peer may
//!   take, since a peer that takes slowly holds every stream up and the connection's meter
//!   judges that. A stream its credit holds under the rate is reset with H3_REQUEST_CANCELLED
//!   (RFC 9114 §4.1.1), and the caller reads `cancelled`.
//!
//! `look` reads where each response stands when the connection settles its requests, after each
//! datagram, so nothing is counted for each frame.
const std = @import("std");
const assert = std.debug.assert;
const quic = @import("quic");
const h3 = @import("h3");
const constants = @import("../constants.zig");
const deadline = @import("../deadline.zig");
const rate = @import("../rate.zig");
const connection_sends = @import("../connection/connection_sends.zig");
const quic_connection = @import("quic_connection.zig");
const quic_connection_h3 = @import("quic_connection_h3.zig");
const quic_body = @import("quic_body.zig");
const quic_request = @import("quic_request.zig");

const QuicConnection = quic_connection.QuicConnection;
const Request = quic_request.Request;
const Deadline = deadline.Deadline;

/// One response, as `look` last found it.
const Sending = struct {
    /// The octets of the response the peer had acknowledged.
    acknowledged_len: u64 = 0,
    /// Whether the response holds octets the peer may take and has not acknowledged.
    busy: bool = false,
    /// Whether the response holds octets its stream's credit does not cover.
    bound: bool = false,
    meter: rate.Meter = .{},
};

pub const Sends = struct {
    /// What the peer acknowledged of the responses' octets.
    meter: rate.Meter,
    /// The responses that are busy, and those that are bound.
    busy: u32,
    bound: u32,
    /// Whether any meter may run, so a connection with none skips its entries.
    metered: bool,
    /// One entry for each request record, at the record's index.
    entries: [constants.quic_requests_max]Sending,

    pub fn init(sends: *Sends) void {
        sends.meter = .{};
        sends.busy = 0;
        sends.bound = 0;
        sends.metered = false;
        sends.entries = @splat(.{});
    }

    fn set(sends: *Sends, entry: *Sending, busy: bool, bound: bool) void {
        sends.busy = sends.busy - @intFromBool(entry.busy) + @intFromBool(busy);
        sends.bound = sends.bound - @intFromBool(entry.bound) + @intFromBool(bound);
        entry.busy = busy;
        entry.bound = bound;
    }
};

/// Notes where `record`'s response stands on `stream`: the octets the peer acknowledged since the
/// last look, which arrived at the instant `fire` last moved the meters to, and whether the
/// response waits on the peer or on its stream's credit.
pub fn look(connection: *QuicConnection, record: *const Request, stream: *const quic.stream.Stream) void {
    const sends = &connection.sends;
    const entry = &sends.entries[connection.requests.index_of(record)];
    const outgoing = &stream.outgoing;
    assert(outgoing.acknowledged_len >= entry.acknowledged_len);
    const newly = outgoing.acknowledged_len - entry.acknowledged_len;
    entry.acknowledged_len = outgoing.acknowledged_len;
    sends.meter.count(newly);
    entry.meter.count(newly);
    switch (stream.sending.state) {
        .ready, .send, .data_sent => {},
        // RFC 9000 §3.1: the peer acknowledged every octet, or the stream was reset, and either
        // way the response holds nothing for the peer to take.
        .data_recvd, .reset_sent, .reset_recvd => return sends.set(entry, false, false),
    }
    // RFC 9000 §4.1: the stream's limit is the highest offset the peer takes on it.
    const limit = stream.send_flow.limit;
    const allowed = @min(outgoing.supplied_end, limit);
    assert(outgoing.acknowledged_len <= allowed);
    // RFC 9000 §4.5: a FIN spends no credit, so it leaves once every octet before it may.
    const fin_waits = outgoing.finished and !outgoing.fin_acknowledged and outgoing.supplied_end <= limit;
    sends.set(entry, outgoing.acknowledged_len < allowed or fin_waits, outgoing.supplied_end > limit);
}

/// `record`'s stream closed, so its entry holds nothing for the request that takes the record
/// next.
pub fn forget(connection: *QuicConnection, record: *const Request) void {
    const sends = &connection.sends;
    const entry = &sends.entries[connection.requests.index_of(record)];
    sends.set(entry, false, false);
    entry.* = .{};
}

/// Starts or stops each meter at `now_ns`, as `look` last found the responses.
pub fn observe(connection: *QuicConnection, now_ns: u64) void {
    const sends = &connection.sends;
    const limits = &connection.deadlines;
    const wanted = sends.busy > 0 or sends.bound > 0;
    // Nothing runs and nothing would: the common case, a connection whose peer keeps up.
    if (!wanted and !sends.metered) return;
    connection_sends.start_or_stop(&sends.meter, sends.busy > 0, now_ns, limits);
    for (&sends.entries) |*entry| {
        // The connection's meter judges a peer that takes slowly, so a stream's own waits while
        // any other response is busy.
        const others_busy = sends.busy - @intFromBool(entry.busy);
        connection_sends.start_or_stop(&entry.meter, entry.bound and others_busy == 0, now_ns, limits);
    }
    sends.metered = wanted;
}

/// The soonest instant a send deadline passes, or `current` when it is sooner or none does.
pub fn soonest(connection: *const QuicConnection, current: ?u64) ?u64 {
    const sends = &connection.sends;
    if (!sends.metered) return current;
    const quota = connection.deadlines.send_quota() orelse return current;
    const window_ns = connection.deadlines.rate_window_ns;
    var at = current;
    if (sends.meter.check_ns(quota, window_ns)) |check_ns| at = @min(at orelse check_ns, check_ns);
    for (&sends.entries) |*entry| {
        const check_ns = entry.meter.check_ns(quota, window_ns) orelse continue;
        at = @min(at orelse check_ns, check_ns);
    }
    return at;
}

/// Resets each stream its credit held under the rate at `now_ns`, and returns `send_rate` when
/// the connection ends for it: its peer acknowledged too little. Null when it goes on.
pub fn fire(connection: *QuicConnection, now_ns: u64) ?Deadline {
    const sends = &connection.sends;
    if (!sends.metered) return null;
    const quota = connection.deadlines.send_quota() orelse return null;
    const window_ns = connection.deadlines.rate_window_ns;
    if (sends.meter.short(now_ns, quota, window_ns)) return .send_rate;
    for (&sends.entries, 0..) |*entry, index| {
        if (!entry.meter.short(now_ns, quota, window_ns)) continue;
        cancel_stream(connection, index);
    }
    return null;
}

/// RFC 9114 §4.1.1: a server that abandons a response "SHOULD abort its response stream with the
/// error code H3_REQUEST_CANCELLED". The caller reads `cancelled` for a request it still hears
/// of. The stream is reset, so the next `look` finds its response holding nothing.
fn cancel_stream(connection: *QuicConnection, index: usize) void {
    const record = &connection.requests.records[index];
    assert(record.in_use);
    connection.h3.cancel(&connection.transport, record.stream_id, h3.constants.error_request_cancelled);
    quic_body.remove(connection, record);
    if (record.over) return;
    quic_connection_h3.end(connection, record, .{ .cancelled = .{ .deadline = .send_rate } });
}
