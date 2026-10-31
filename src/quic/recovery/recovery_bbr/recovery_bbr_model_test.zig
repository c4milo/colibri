//! Tests of `recovery_bbr_model.zig`, one for each estimate of draft-ietf-ccwg-bbr-06 §5.5.
const std = @import("std");
const testing = std.testing;
const constants = @import("../../constants.zig");
const recovery_bbr_filter = @import("recovery_bbr_filter.zig");
const recovery_bbr_model = @import("recovery_bbr_model.zig");
const recovery_delivery = @import("../recovery_delivery.zig");

const Model = recovery_bbr_model.Model;
const Sample = recovery_delivery.Sample;
const bbr = constants.recovery.bbr;

const test_start_ns: u64 = 1_000_000_000;
const test_millisecond_ns: u64 = constants.nanoseconds_per_millisecond;
const test_datagram_len: u64 = 1_200;
const test_round_trip_ns: u64 = 50_000_000;

/// A rate sample from a packet sent when `prior_delivered_len` octets were delivered, with
/// `delivered_len` octets delivered since. Test-only.
fn test_sample(prior_delivered_len: u64, delivered_len: u64, rate: u64, application_limited: bool) Sample {
    return .{
        .rate = rate,
        .delivered_len = delivered_len,
        .interval_ns = if (rate == 0) 0 else test_round_trip_ns,
        .application_limited = application_limited,
        .prior_delivered_len = prior_delivered_len,
        .acknowledged_len = test_datagram_len,
        .rtt_ns = test_round_trip_ns,
        .tx_in_flight_len = 0,
        .lost_len = 0,
    };
}

test "§5.5.1: a round ends when a packet sent after it began is acknowledged" {
    var model: Model = undefined;
    model.init(test_start_ns);
    // The first ACK frame starts round 1, which ends once 10 datagrams are delivered.
    model.update_round(test_sample(0, 10 * test_datagram_len, 0, false));
    try testing.expect(model.round_start);
    try testing.expectEqual(1, model.round_count);
    try testing.expectEqual(10 * test_datagram_len, model.next_round_delivered_len);
    // A packet sent before those 10 were delivered belongs to round 1.
    model.update_round(test_sample(9 * test_datagram_len, 11 * test_datagram_len, 0, false));
    try testing.expect(!model.round_start);
    try testing.expectEqual(1, model.round_count);
    // A packet sent once they were delivered ends it.
    model.update_round(test_sample(10 * test_datagram_len, 2 * test_datagram_len, 0, false));
    try testing.expect(model.round_start);
    try testing.expectEqual(2, model.round_count);
    try testing.expectEqual(12 * test_datagram_len, model.next_round_delivered_len);
}

test "§5.5.4: an application-limited sample counts only above the estimate" {
    var model: Model = undefined;
    model.init(test_start_ns);
    model.update_max_bw(test_sample(0, test_datagram_len, 1_000_000, false));
    try testing.expectEqual(1_000_000, model.max_bw);
    model.update_max_bw(test_sample(0, test_datagram_len, 500_000, true));
    try testing.expectEqual(1_000_000, model.max_bw);
    model.update_max_bw(test_sample(0, test_datagram_len, 2_000_000, true));
    try testing.expectEqual(2_000_000, model.max_bw);
    // §5.5.5: a sample with no rate leaves the estimate.
    model.update_max_bw(test_sample(0, test_datagram_len, 0, false));
    try testing.expectEqual(2_000_000, model.max_bw);
}

test "§5.5.6: BBR.max_bw forgets a sample two probe cycles old" {
    var model: Model = undefined;
    model.init(test_start_ns);
    model.update_max_bw(test_sample(0, test_datagram_len, 3_000_000, false));
    model.advance_max_bw_filter();
    // One cycle on, the previous cycle's sample still holds.
    model.update_max_bw(test_sample(0, test_datagram_len, 1_000_000, false));
    try testing.expectEqual(3_000_000, model.max_bw);
    model.advance_max_bw_filter();
    model.update_max_bw(test_sample(0, test_datagram_len, 500_000, false));
    try testing.expectEqual(1_000_000, model.max_bw);
}

test "§5.5.4: an application-limited sample below the estimate stays out of the filter" {
    var model: Model = undefined;
    model.init(test_start_ns);
    model.update_max_bw(test_sample(0, test_datagram_len, 3_000_000, false));
    model.advance_max_bw_filter();
    // Below the estimate and limited by the application, so the filter does not take it.
    model.update_max_bw(test_sample(0, test_datagram_len, 1_000_000, true));
    model.advance_max_bw_filter();
    // Once the 3,000,000 sample leaves the window, only this cycle's sample is left.
    model.update_max_bw(test_sample(0, test_datagram_len, 500_000, false));
    try testing.expectEqual(500_000, model.max_bw);
}

test "§5.3.4.3: BBR.min_rtt takes a lower sample at once and a higher one after 10 s" {
    var model: Model = undefined;
    model.init(test_start_ns);
    try testing.expectEqual(recovery_bbr_model.rtt_unknown_ns, model.min_rtt_ns);
    model.update_min_rtt(40 * test_millisecond_ns, test_start_ns);
    try testing.expectEqual(40 * test_millisecond_ns, model.min_rtt_ns);
    // A higher sample within ProbeRTTInterval moves nothing.
    model.update_min_rtt(60 * test_millisecond_ns, test_start_ns + bbr.probe_rtt_interval_ns);
    try testing.expectEqual(40 * test_millisecond_ns, model.probe_rtt_min_delay_ns);
    try testing.expect(!model.probe_rtt_expired);
    // Past it, the probe's minimum takes the higher sample, and BBR.min_rtt keeps the old one.
    const expired_ns = test_start_ns + bbr.probe_rtt_interval_ns + 1;
    model.update_min_rtt(60 * test_millisecond_ns, expired_ns);
    try testing.expect(model.probe_rtt_expired);
    try testing.expectEqual(60 * test_millisecond_ns, model.probe_rtt_min_delay_ns);
    try testing.expectEqual(40 * test_millisecond_ns, model.min_rtt_ns);
    // Past MinRTTFilterLen, BBR.min_rtt takes the probe's minimum and its instant.
    model.update_min_rtt(null, test_start_ns + bbr.min_rtt_filter_len_ns + 1);
    try testing.expectEqual(60 * test_millisecond_ns, model.min_rtt_ns);
    try testing.expectEqual(expired_ns, model.min_rtt_at_ns);
    // A lower sample takes both at once.
    model.update_min_rtt(30 * test_millisecond_ns, test_start_ns + bbr.min_rtt_filter_len_ns + 2);
    try testing.expectEqual(30 * test_millisecond_ns, model.min_rtt_ns);
}

test "§5.5.9: an ACK frame above the expected rate adds to BBR.extra_acked, up to the window" {
    var model: Model = undefined;
    model.init(test_start_ns);
    const bw: u64 = 1_200_000;
    const window_len = 4 * test_datagram_len;
    // At 1,200,000 octets a second, 10 ms deliver 12,000 octets. Nothing came, so the interval
    // starts again at this frame, and its datagram counts whole.
    const sample = test_sample(0, test_datagram_len, bw, false);
    model.update_ack_aggregation(sample, test_start_ns + 10 * test_millisecond_ns, bw, window_len, true);
    try testing.expectEqual(test_datagram_len, model.extra_acked_len);
    try testing.expectEqual(test_start_ns + 10 * test_millisecond_ns, model.extra_acked_interval_start_ns);
    // Five frames 0.1 ms apart deliver five datagrams where one tenth of one is expected.
    for (1..6) |frame| {
        const now_ns = test_start_ns + 10 * test_millisecond_ns + frame * test_millisecond_ns / 10;
        model.update_ack_aggregation(sample, now_ns, bw, window_len, true);
    }
    // The extra is 6 datagrams less the half datagram expected over 0.5 ms, held at the window.
    try testing.expectEqual(window_len, model.extra_acked_len);
    model.update_ack_aggregation(sample, test_start_ns + 11 * test_millisecond_ns, bw, 100 * test_datagram_len, true);
    try testing.expectEqual(7 * test_datagram_len - test_datagram_len, model.extra_acked_len);
}

test "§5.5.9: in Startup BBR.extra_acked remembers one round, and after it ten" {
    var model: Model = undefined;
    model.init(test_start_ns);
    const window_len = 100 * test_datagram_len;
    const bw: u64 = 1_200_000;
    const burst = test_sample(0, test_datagram_len, 0, false);
    // A burst of three datagrams in round 1, with no rate to expect anything from.
    model.update_round(test_sample(0, test_datagram_len, 0, false));
    for (0..3) |_| model.update_ack_aggregation(burst, test_start_ns, 0, window_len, false);
    try testing.expectEqual(3 * test_datagram_len, model.extra_acked_len);
    // In round 2 a second later, far less came than expected, so the interval starts again.
    model.update_round(test_sample(test_datagram_len, test_datagram_len, 0, false));
    try testing.expectEqual(2, model.round_count);
    const later_ns = test_start_ns + bbr.probe_rtt_interval_ns;
    model.update_ack_aggregation(burst, later_ns, bw, window_len, false);
    // In Startup the burst of round 1 is out of the window.
    try testing.expectEqual(test_datagram_len, model.extra_acked_len);
    // Once Startup has ended, the window covers round 1 too.
    model.update_ack_aggregation(burst, later_ns, bw, window_len, true);
    try testing.expectEqual(3 * test_datagram_len, model.extra_acked_len);
}

test "§5.5.9: the expected octets saturate rather than overflow" {
    try testing.expectEqual(std.math.maxInt(u64), recovery_bbr_model.expected_delivered_len(std.math.maxInt(u64), std.math.maxInt(u64)));
    try testing.expectEqual(1_200, recovery_bbr_model.expected_delivered_len(1_200_000, test_millisecond_ns));
}

test "§5.5.8.2: QUIC's offload budget is the send quantum" {
    try testing.expectEqual(2 * test_datagram_len, recovery_bbr_model.offload_budget_len(2 * test_datagram_len));
}

const Tokens = std.mem.TokenIterator(u8, .scalar);
const decimal: u8 = 10;

fn field(fields: *Tokens) !u64 {
    return std.fmt.parseUnsigned(u64, fields.next() orelse return error.TestVectorShort, decimal);
}

/// One `filter` line: a filter of `slots` slots, and each update's answer.
fn expect_filter_line(fields: *Tokens) !void {
    const slots = try field(fields);
    const steps = try field(fields);
    var small: recovery_bbr_filter.MaxFilter(bbr.max_bw_filter_cycles) = undefined;
    var large: recovery_bbr_filter.MaxFilter(bbr.extra_acked_filter_rounds) = undefined;
    small.init();
    large.init();
    for (0..steps) |_| {
        const value = try field(fields);
        const time = try field(fields);
        const window = try field(fields);
        const answer = if (slots == bbr.max_bw_filter_cycles)
            small.update(value, time, window)
        else
            large.update(value, time, window);
        try testing.expectEqual(try field(fields), answer);
    }
}

/// One `round` line: the round after an ACK frame's sample.
fn expect_round_line(fields: *Tokens) !void {
    var model: Model = undefined;
    model.init(test_start_ns);
    model.next_round_delivered_len = try field(fields);
    model.round_count = try field(fields);
    const prior_delivered_len = try field(fields);
    const delivered_len = try field(fields);
    model.update_round(test_sample(prior_delivered_len, delivered_len, 0, false));
    try testing.expectEqual(try field(fields), model.next_round_delivered_len);
    try testing.expectEqual(try field(fields), model.round_count);
    const started = fields.next() orelse return error.TestVectorShort;
    try testing.expectEqual(std.mem.eql(u8, started, "true"), model.round_start);
}

/// One `minrtt` line: the four instants and delays after `update_min_rtt`.
fn expect_min_rtt_line(fields: *Tokens) !void {
    var model: Model = undefined;
    model.init(0);
    model.min_rtt_ns = try field(fields);
    model.min_rtt_at_ns = try field(fields);
    model.probe_rtt_min_delay_ns = try field(fields);
    model.probe_rtt_min_at_ns = try field(fields);
    const shown = fields.peek() orelse return error.TestVectorShort;
    const rtt_ns: ?u64 = if (std.mem.eql(u8, shown, "none")) none: {
        _ = fields.next();
        break :none null;
    } else try field(fields);
    model.update_min_rtt(rtt_ns, try field(fields));
    try testing.expectEqual(try field(fields), model.min_rtt_ns);
    try testing.expectEqual(try field(fields), model.min_rtt_at_ns);
    try testing.expectEqual(try field(fields), model.probe_rtt_min_delay_ns);
    try testing.expectEqual(try field(fields), model.probe_rtt_min_at_ns);
}

/// One `aggregation` line: the interval and the extra octets after one ACK frame. A filter that
/// holds one value answers with it.
fn expect_aggregation_line(fields: *Tokens) !void {
    var model: Model = undefined;
    model.init(0);
    model.extra_acked_delivered_len = try field(fields);
    model.extra_acked_interval_start_ns = try field(fields);
    var sample = test_sample(0, 0, 0, false);
    sample.acknowledged_len = try field(fields);
    const now_ns = try field(fields);
    const bw = try field(fields);
    const window_len = try field(fields);
    model.update_ack_aggregation(sample, now_ns, bw, window_len, true);
    try testing.expectEqual(try field(fields), model.extra_acked_delivered_len);
    try testing.expectEqual(try field(fields), model.extra_acked_interval_start_ns);
    try testing.expectEqual(try field(fields), model.extra_acked_len);
}

test "spec/lean/Colibri/Quic/BbrModel.lean: the model gives the proved definitions' answers" {
    var lines = std.mem.splitScalar(u8, @embedFile("bbr_model_vectors.txt"), '\n');
    var checked: usize = 0;
    // Bounded: the embedded file has a fixed number of lines.
    while (lines.next()) |line| {
        if (line.len == 0 or line[0] == '#') continue;
        var fields = std.mem.tokenizeScalar(u8, line, ' ');
        const kind = fields.next().?;
        if (std.mem.eql(u8, kind, "filter")) {
            try expect_filter_line(&fields);
        } else if (std.mem.eql(u8, kind, "round")) {
            try expect_round_line(&fields);
        } else if (std.mem.eql(u8, kind, "minrtt")) {
            try expect_min_rtt_line(&fields);
        } else if (std.mem.eql(u8, kind, "aggregation")) {
            try expect_aggregation_line(&fields);
        } else if (std.mem.eql(u8, kind, "expected")) {
            const bw = try field(&fields);
            const interval_ns = try field(&fields);
            try testing.expectEqual(try field(&fields), recovery_bbr_model.expected_delivered_len(bw, interval_ns));
        } else {
            return error.TestVectorKind;
        }
        try testing.expectEqual(null, fields.next());
        checked += 1;
    }
    try testing.expectEqual(738, checked);
}
