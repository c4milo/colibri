//! Delivery rate samples (draft-ietf-ccwg-bbr-06 §4.1). Part of design §8 step 29a.
//!
//! BBR models the path from the rate at which the peer acknowledges data. Each packet records
//! what the connection had delivered when the packet went out, and each ACK frame compares that
//! record with what is delivered now. The difference over the time between gives one sample.
//!
//! The sample takes the longer of two intervals: the one over which the packets went out, and
//! the one over which their acknowledgments came back (§4.1.1.2.4). So it is never above the
//! send rate or the ACK rate, and a burst of compressed ACKs does not raise it.
//!
//! It reads no clock. Every instant is a parameter (non-negotiable 3), and the arithmetic is
//! integer throughout, so one seed replays byte-identically (invariant 5).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("../constants.zig");
const recovery_sent = @import("recovery_sent.zig");

const Record = recovery_sent.Record;

/// draft-ietf-ccwg-bbr-06 §4.1.2.1.3's rate sample `RS`, for one ACK frame that gave one.
pub const Sample = struct {
    /// `RS.delivery_rate`: octets a second.
    rate: u64,
    /// `RS.delivered`: the octets delivered over the interval.
    delivered_len: u64,
    /// `RS.interval`: the longer of the send interval and the ACK interval.
    interval_ns: u64,
    /// `RS.is_app_limited`: whether the application, and not the path, bounded the sample.
    application_limited: bool,
};

/// draft-ietf-ccwg-bbr-06 §4.1.2.1.1's per-connection state.
pub const Delivery = struct {
    /// `C.delivered`: the octets the peer has acknowledged over the connection.
    delivered_len: u64,
    /// `C.delivered_time`: the instant `delivered_len` last rose, or 0 before anything is sent.
    delivered_at_ns: u64,
    /// `C.first_send_time`: the instant the newest acknowledged packet went out, or, after an
    /// idle period, the instant the first packet after it went out.
    first_sent_at_ns: u64,
    /// `C.app_limited`: the value of `delivered_len` past which the application no longer limits
    /// the samples, or 0 when it does not limit them.
    application_limited_until: u64,

    pub fn init(delivery: *Delivery) void {
        delivery.* = .{ .delivered_len = 0, .delivered_at_ns = 0, .first_sent_at_ns = 0, .application_limited_until = 0 };
    }

    /// draft-ietf-ccwg-bbr-06 §4.1.2.2's `OnPacketSent`: writes the connection's state into the
    /// record of a packet sent at `sent.sent_at_ns`. `in_flight_len` is the octets in flight
    /// before the packet went out.
    pub fn on_packet_sent(delivery: *Delivery, sent: *Record, in_flight_len: u64) void {
        // The caller works forward in time (invariant 24).
        assert(sent.sent_at_ns >= delivery.first_sent_at_ns);
        // §4.1.2.2: "If there is no data in flight yet, then we can start the delivery rate
        // interval at the current time". The draft reads `C.inflight` after this packet counts,
        // which is never 0, so colibri reads it before, as the sentence above means.
        if (in_flight_len == 0) {
            delivery.first_sent_at_ns = sent.sent_at_ns;
            delivery.delivered_at_ns = sent.sent_at_ns;
        }
        sent.first_sent_at_ns = delivery.first_sent_at_ns;
        sent.delivered_at_ns = delivery.delivered_at_ns;
        sent.delivered_len = delivery.delivered_len;
        sent.application_limited = delivery.application_limited_until != 0;
    }

    /// draft-ietf-ccwg-bbr-06 §4.1.2.3: `UpdateRateSample` over the packets one ACK frame took
    /// out of flight, then `GenerateRateSample`. `newest` is the largest of them, which went out
    /// last (RFC 9000 §12.3), and `acknowledged_len` is their octets in flight. Null when the
    /// ACK frame gives no reliable sample.
    pub fn on_ack(delivery: *Delivery, newest: Record, acknowledged_len: u64, now_ns: u64, min_rtt_ns: u64) ?Sample {
        assert(now_ns >= newest.sent_at_ns);
        assert(newest.sent_at_ns >= newest.first_sent_at_ns);
        // `UpdateRateSample`: each packet adds its octets, and the newest one gives the sample.
        // A frame's newest packet is the newest of all the frame took, so one test does for each.
        delivery.delivered_len +|= acknowledged_len;
        delivery.delivered_at_ns = now_ns;
        delivery.first_sent_at_ns = newest.sent_at_ns;
        // `GenerateRateSample`: "Clear app-limited field if bubble is ACKed and gone."
        if (delivery.application_limited_until != 0 and delivery.delivered_len > delivery.application_limited_until) {
            delivery.application_limited_until = 0;
        }
        // §4.1.2.3: a packet sent before anything was delivered or sent has no prior instant.
        if (newest.delivered_at_ns == 0) return null;
        const send_elapsed_ns = newest.sent_at_ns - newest.first_sent_at_ns;
        const ack_elapsed_ns = now_ns - newest.delivered_at_ns;
        const interval_ns = @max(send_elapsed_ns, ack_elapsed_ns);
        // §4.1.2.3: "if (RS.interval < C.min_rtt) return /* no reliable rate sample */".
        if (interval_ns < min_rtt_ns or interval_ns == 0) return null;
        const delivered_len = delivery.delivered_len - newest.delivered_len;
        return .{
            .rate = rate_of(delivered_len, interval_ns),
            .delivered_len = delivered_len,
            .interval_ns = interval_ns,
            .application_limited = newest.application_limited,
        };
    }

    /// draft-ietf-ccwg-bbr-06 §4.1.2.4's `CheckIfApplicationLimited`, at an instant the sender
    /// would send if it had data. `unsent` says whether it holds data or retransmissions it has
    /// not sent, and the window is RFC 9002's.
    pub fn check_application_limited(delivery: *Delivery, unsent: bool, in_flight_len: u64, window_len: u64) void {
        if (unsent) return;
        if (in_flight_len >= window_len) return;
        // §4.1.2.4's `MarkConnectionAppLimited`: "C.app_limited = max(C.delivered + C.inflight, 1)".
        delivery.application_limited_until = @max(delivery.delivered_len +| in_flight_len, 1);
        assert(delivery.application_limited_until != 0);
    }
};

/// Octets a second, from octets over nanoseconds. The product is taken in 128 bits, so no
/// sample overflows, and the quotient saturates at the largest `u64`.
pub fn rate_of(delivered_len: u64, interval_ns: u64) u64 {
    assert(interval_ns > 0);
    const rate = @as(u128, delivered_len) * core.constants.nanoseconds_per_second / interval_ns;
    return @intCast(@min(rate, std.math.maxInt(u64)));
}

const testing = std.testing;

const test_datagram_len: u64 = 1_200;
const test_start_ns: u64 = 1_000_000_000;
const test_millisecond_ns: u64 = constants.nanoseconds_per_millisecond;

/// A record sent at `sent_at_ns`, as `Recovery.on_packet_sent` writes it. Test-only.
fn test_send(delivery: *Delivery, number: u64, sent_at_ns: u64, in_flight_len: u64) Record {
    var sent: Record = .{
        .number = number,
        .sent_at_ns = sent_at_ns,
        .sent_len = test_datagram_len,
        .ack_eliciting = true,
        .in_flight = true,
    };
    delivery.on_packet_sent(&sent, in_flight_len);
    return sent;
}

test "§4.1.2.2: the first packet in flight starts the interval at its own instant" {
    var delivery: Delivery = undefined;
    delivery.init();
    const first = test_send(&delivery, 0, test_start_ns, 0);
    try testing.expectEqual(test_start_ns, first.first_sent_at_ns);
    try testing.expectEqual(test_start_ns, first.delivered_at_ns);
    // A packet behind it takes the same start: the interval runs from the first.
    const second = test_send(&delivery, 1, test_start_ns + test_millisecond_ns, test_datagram_len);
    try testing.expectEqual(test_start_ns, second.first_sent_at_ns);
    try testing.expectEqual(0, second.delivered_len);
}

test "§4.1.2.3: the sample spans from the newest packet's snapshot to the ACK" {
    var delivery: Delivery = undefined;
    delivery.init();
    // Ten packets 1 ms apart, all acknowledged 50 ms after the last went out.
    var newest: Record = undefined;
    for (0..10) |number| {
        newest = test_send(&delivery, number, test_start_ns + number * test_millisecond_ns, number * test_datagram_len);
    }
    const ack_ns = newest.sent_at_ns + 50 * test_millisecond_ns;
    const sample = delivery.on_ack(newest, 10 * test_datagram_len, ack_ns, 40 * test_millisecond_ns).?;
    // The ACK interval, 59 ms, is longer than the send interval, 9 ms, so it bounds the rate.
    try testing.expectEqual(59 * test_millisecond_ns, sample.interval_ns);
    try testing.expectEqual(10 * test_datagram_len, sample.delivered_len);
    try testing.expectEqual(rate_of(10 * test_datagram_len, 59 * test_millisecond_ns), sample.rate);
    try testing.expectEqual(10 * test_datagram_len, delivery.delivered_len);
    try testing.expectEqual(newest.sent_at_ns, delivery.first_sent_at_ns);
}

test "§4.1.1.2.4: compressed ACKs are held at the send rate" {
    var delivery: Delivery = undefined;
    delivery.init();
    // Ten packets went out over 100 ms, and the ACK frame for them comes 1 ms after the last ACK
    // frame, so the ACK interval alone would give a rate a hundred times the send rate.
    const ack_ns = test_start_ns + 150 * test_millisecond_ns;
    const newest: Record = .{
        .number = 9,
        .sent_at_ns = test_start_ns + 100 * test_millisecond_ns,
        .sent_len = test_datagram_len,
        .ack_eliciting = true,
        .in_flight = true,
        .first_sent_at_ns = test_start_ns,
        .delivered_at_ns = ack_ns - test_millisecond_ns,
    };
    const sample = delivery.on_ack(newest, 10 * test_datagram_len, ack_ns, 0).?;
    try testing.expectEqual(100 * test_millisecond_ns, sample.interval_ns);
    try testing.expectEqual(rate_of(10 * test_datagram_len, 100 * test_millisecond_ns), sample.rate);
}

test "§4.1.2.3: an interval shorter than min_rtt gives no sample" {
    var delivery: Delivery = undefined;
    delivery.init();
    const sent = test_send(&delivery, 0, test_start_ns, 0);
    const ack_ns = test_start_ns + 10 * test_millisecond_ns;
    try testing.expectEqual(null, delivery.on_ack(sent, test_datagram_len, ack_ns, 20 * test_millisecond_ns));
    // The octets still count as delivered: only the sample is withheld.
    try testing.expectEqual(test_datagram_len, delivery.delivered_len);
}

test "§4.1.2.4: the mark of an application limit holds until its packets are delivered" {
    var delivery: Delivery = undefined;
    delivery.init();
    const first = test_send(&delivery, 0, test_start_ns, 0);
    // A full window marks nothing, and data still unsent marks nothing.
    delivery.check_application_limited(false, 10 * test_datagram_len, 10 * test_datagram_len);
    delivery.check_application_limited(true, test_datagram_len, 10 * test_datagram_len);
    try testing.expectEqual(0, delivery.application_limited_until);
    // The sender ran out of data with room in the window.
    delivery.check_application_limited(false, test_datagram_len, 10 * test_datagram_len);
    try testing.expectEqual(test_datagram_len, delivery.application_limited_until);
    const second = test_send(&delivery, 1, test_start_ns + test_millisecond_ns, test_datagram_len);
    try testing.expect(second.application_limited);
    try testing.expect(!first.application_limited);
    // Delivering the first packet reaches the mark but does not pass it.
    const ack_ns = test_start_ns + 50 * test_millisecond_ns;
    const sample = delivery.on_ack(first, test_datagram_len, ack_ns, 0).?;
    try testing.expect(!sample.application_limited);
    try testing.expectEqual(test_datagram_len, delivery.application_limited_until);
    // Delivering the second passes it, and its sample is marked.
    const later = delivery.on_ack(second, test_datagram_len, ack_ns + test_millisecond_ns, 0).?;
    try testing.expect(later.application_limited);
    try testing.expectEqual(0, delivery.application_limited_until);
}

test "§4.1.2.4: an empty connection marks a limit of 1" {
    var delivery: Delivery = undefined;
    delivery.init();
    delivery.check_application_limited(false, 0, 10 * test_datagram_len);
    try testing.expectEqual(1, delivery.application_limited_until);
}

test "the rate saturates rather than overflows" {
    try testing.expectEqual(std.math.maxInt(u64), rate_of(std.math.maxInt(u64), 1));
    try testing.expectEqual(1_200_000, rate_of(1_200, test_millisecond_ns));
}

const Tokens = std.mem.TokenIterator(u8, .scalar);
const decimal: u8 = 10;

fn field(fields: *Tokens) !u64 {
    return std.fmt.parseUnsigned(u64, fields.next() orelse return error.TestVectorShort, decimal);
}

/// The sample `on_ack` gives for one vector line, from a record whose send interval and ACK
/// interval are the line's. Test-only.
fn vector_sample(delivered_len: u64, send_elapsed_ns: u64, ack_elapsed_ns: u64, min_rtt_ns: u64) ?Sample {
    var delivery: Delivery = undefined;
    delivery.init();
    const newest: Record = .{
        .number = 0,
        .sent_at_ns = test_start_ns + send_elapsed_ns,
        .sent_len = 0,
        .ack_eliciting = true,
        .in_flight = true,
        .first_sent_at_ns = test_start_ns,
        .delivered_at_ns = test_start_ns + send_elapsed_ns,
    };
    return delivery.on_ack(newest, delivered_len, newest.delivered_at_ns + ack_elapsed_ns, min_rtt_ns);
}

/// One `sample` line: the sample, or `none`.
fn expect_sample_line(fields: *Tokens) !void {
    const delivered_len = try field(fields);
    const send_elapsed_ns = try field(fields);
    const ack_elapsed_ns = try field(fields);
    const min_rtt_ns = try field(fields);
    const taken = vector_sample(delivered_len, send_elapsed_ns, ack_elapsed_ns, min_rtt_ns);
    const first = fields.peek() orelse return error.TestVectorShort;
    if (std.mem.eql(u8, first, "none")) return testing.expectEqual(null, taken);
    const sample = taken orelse return error.TestExpectedSample;
    try testing.expectEqual(try field(fields), sample.rate);
    try testing.expectEqual(try field(fields), sample.interval_ns);
    try testing.expectEqual(delivered_len, sample.delivered_len);
}

/// One `mark` line: the mark a sender that ran out of data sets.
fn expect_mark_line(fields: *Tokens) !void {
    var delivery: Delivery = undefined;
    delivery.init();
    delivery.delivered_len = try field(fields);
    const in_flight_len = try field(fields);
    delivery.check_application_limited(false, in_flight_len, in_flight_len + 1);
    try testing.expectEqual(try field(fields), delivery.application_limited_until);
}

/// One `cleared` line: the mark after an ACK frame raised the octets delivered.
fn expect_cleared_line(fields: *Tokens) !void {
    var delivery: Delivery = undefined;
    delivery.init();
    const delivered_len = try field(fields);
    delivery.application_limited_until = try field(fields);
    _ = delivery.on_ack(.{ .number = 0, .sent_at_ns = 0, .sent_len = 0, .ack_eliciting = true, .in_flight = true }, delivered_len, 0, 0);
    try testing.expectEqual(try field(fields), delivery.application_limited_until);
}

test "decision 77: rate samples are what spec/lean/Colibri/Quic/DeliveryRate.lean proves them" {
    var lines = std.mem.splitScalar(u8, @embedFile("delivery_vectors.txt"), '\n');
    var counts: [3]usize = @splat(0);
    // Bounded by the file, which spec/lean/Vectors.lean writes.
    while (lines.next()) |line| {
        if (line.len == 0 or line[0] == '#') continue;
        var fields = std.mem.tokenizeScalar(u8, line, ' ');
        const kind = fields.next().?;
        if (std.mem.eql(u8, kind, "sample")) {
            try expect_sample_line(&fields);
            counts[0] += 1;
        } else if (std.mem.eql(u8, kind, "mark")) {
            try expect_mark_line(&fields);
            counts[1] += 1;
        } else {
            try testing.expectEqualStrings("cleared", kind);
            try expect_cleared_line(&fields);
            counts[2] += 1;
        }
    }
    // Every kind of line the file holds was read.
    for (counts) |count| try testing.expect(count > 0);
}
