//! Tests of BBRv3's control parameters: one for each rule of draft-ietf-ccwg-bbr-06 §5.6.
const std = @import("std");
const testing = std.testing;
const constants = @import("../../constants.zig");
const recovery_delivery = @import("../recovery_delivery.zig");
const recovery_bbr_control = @import("recovery_bbr_control.zig");
const support = @import("recovery_bbr_test_support.zig");

const Driver = support.Driver;
const bbr = constants.recovery.bbr;
const test_round_trip_ns = support.test_round_trip_ns;
const test_datagram_len = support.test_datagram_len;
const test_initial_window_len = support.test_initial_window_len;
const test_rate = support.test_rate;
const test_bdp_len = support.test_bdp_len;
const test_acknowledged_len = support.test_acknowledged_len;

/// A sample of `test_acknowledged_len` octets with no rate. Test-only.
fn test_sample() recovery_delivery.Sample {
    var sample = std.mem.zeroes(recovery_delivery.Sample);
    sample.acknowledged_len = test_acknowledged_len;
    return sample;
}

test "§5.6.2: a smoothed round trip of 0 is no first sample, and keeps the rate over 1 ms" {
    var driver: Driver = undefined;
    driver.init();
    recovery_bbr_control.update(&driver.state, test_sample(), driver.path(0), 0);
    try testing.expectEqual(33_240_000, driver.state.pacing_rate);
    try testing.expect(!driver.state.has_seen_rtt);
    recovery_bbr_control.init_pacing_rate(&driver.state, test_initial_window_len, 0);
    try testing.expectEqual(33_240_000, driver.state.pacing_rate);
}

test "§5.6.2: the pacing rate starts at Startup's gain over 1 ms, and again over the first round trip" {
    var driver: Driver = undefined;
    driver.init();
    // 12,000 octets over 1 ms is 12,000,000 octets a second, and 2.77 times that.
    try testing.expectEqual(33_240_000, driver.state.pacing_rate);
    recovery_bbr_control.update(&driver.state, test_sample(), driver.path(0), test_round_trip_ns);
    // Over 50 ms, 240,000 octets a second, and 2.77 times that.
    try testing.expectEqual(664_800, driver.state.pacing_rate);
    try testing.expect(driver.state.has_seen_rtt);
    // A later sample does not start it again.
    recovery_bbr_control.update(&driver.state, test_sample(), driver.path(0), 0);
    try testing.expectEqual(664_800, driver.state.pacing_rate);
    recovery_bbr_control.update(&driver.state, test_sample(), driver.path(0), 1);
    try testing.expectEqual(664_800, driver.state.pacing_rate);
}

test "§5.6.2: before a full pipe the pacing rate only rises, and after it follows the estimate" {
    var driver: Driver = undefined;
    driver.init();
    driver.state.pacing_rate = test_rate;
    driver.state.bw = test_rate / 2;
    recovery_bbr_control.set_pacing_rate_with_gain(&driver.state, bbr.gain_denominator);
    try testing.expectEqual(test_rate, driver.state.pacing_rate);
    driver.state.full_bw_reached = true;
    recovery_bbr_control.set_pacing_rate_with_gain(&driver.state, bbr.gain_denominator);
    // 1% below the estimate.
    try testing.expectEqual(test_rate / 2 / 100 * 99, driver.state.pacing_rate);
    recovery_bbr_control.set_pacing_rate_with_gain(&driver.state, bbr.probe_bw_up_pacing_gain);
    try testing.expectEqual(test_rate / 2 / 100 * 125 / 100 * 99, driver.state.pacing_rate);
}

test "§5.6.3: the send quantum is 1 ms of the pacing rate, between 2 datagrams and 64 KB" {
    var driver: Driver = undefined;
    driver.init();
    driver.state.pacing_rate = test_rate;
    recovery_bbr_control.set_send_quantum(&driver.state, test_datagram_len);
    try testing.expectEqual(test_rate / 1_000, driver.state.send_quantum_len);
    driver.state.pacing_rate = 1_000;
    recovery_bbr_control.set_send_quantum(&driver.state, test_datagram_len);
    try testing.expectEqual(2 * test_datagram_len, driver.state.send_quantum_len);
    driver.state.pacing_rate = 1_000_000_000;
    recovery_bbr_control.set_send_quantum(&driver.state, test_datagram_len);
    try testing.expectEqual(bbr.send_quantum_max_len, driver.state.send_quantum_len);
}

test "§5.6.4.6: in Startup the window grows by what is acknowledged, up to the BDP at the cwnd gain" {
    var driver: Driver = undefined;
    driver.init();
    driver.state.model.min_rtt_ns = test_round_trip_ns;
    driver.state.bw = test_rate;
    recovery_bbr_control.set_window(&driver.state, test_sample(), driver.path(0));
    try testing.expectEqual(test_initial_window_len + test_acknowledged_len, driver.state.window_len);
    // The cap is twice the BDP.
    try testing.expectEqual(2 * test_bdp_len, driver.state.max_inflight_len);
    driver.state.window_len = 2 * test_bdp_len;
    driver.delivered_len = test_initial_window_len;
    recovery_bbr_control.set_window(&driver.state, test_sample(), driver.path(0));
    try testing.expectEqual(2 * test_bdp_len, driver.state.window_len);
    // While less than the initial window was delivered, it grows past the cap.
    driver.delivered_len = 0;
    recovery_bbr_control.set_window(&driver.state, test_sample(), driver.path(0));
    try testing.expectEqual(2 * test_bdp_len + test_acknowledged_len, driver.state.window_len);
}

test "§5.6.4.6: once the pipe is full the window is held at the cap, and never below 4 datagrams" {
    var driver: Driver = undefined;
    driver.init();
    driver.state.model.min_rtt_ns = test_round_trip_ns;
    driver.state.bw = test_rate;
    driver.state.full_bw_reached = true;
    driver.state.window_len = 3 * test_bdp_len;
    recovery_bbr_control.set_window(&driver.state, test_sample(), driver.path(0));
    try testing.expectEqual(2 * test_bdp_len, driver.state.window_len);
    driver.state.bw = 0;
    driver.state.window_len = test_datagram_len;
    recovery_bbr_control.set_window(&driver.state, test_sample(), driver.path(0));
    try testing.expectEqual(bbr.min_pipe_cwnd_datagrams * test_datagram_len, driver.state.window_len);
}

test "§5.6.4.2: BBR.max_inflight makes room for the octets acknowledged in a burst" {
    var driver: Driver = undefined;
    driver.init();
    driver.state.model.min_rtt_ns = test_round_trip_ns;
    driver.state.bw = test_rate;
    driver.state.model.extra_acked_len = test_acknowledged_len;
    recovery_bbr_control.set_window(&driver.state, test_sample(), driver.path(0));
    try testing.expectEqual(2 * test_bdp_len + test_acknowledged_len, driver.state.max_inflight_len);
}

test "§5.6.4.5, §5.6.4.7: ProbeRTT and the model bound the window" {
    var driver: Driver = undefined;
    driver.init();
    driver.state.model.min_rtt_ns = test_round_trip_ns;
    driver.state.bw = test_rate;
    driver.state.full_bw_reached = true;
    driver.state.window_len = test_bdp_len;
    driver.state.state = .probe_rtt;
    recovery_bbr_control.set_window(&driver.state, test_sample(), driver.path(0));
    // Half the BDP.
    try testing.expectEqual(test_bdp_len / 2, driver.state.window_len);
    // In UP the long-term bound caps it, and the short-term bound caps it everywhere.
    driver.state.state = .probe_bw_up;
    driver.state.window_len = test_bdp_len;
    driver.state.inflight_longterm_len = test_bdp_len / 4;
    recovery_bbr_control.set_window(&driver.state, test_sample(), driver.path(0));
    try testing.expectEqual(test_bdp_len / 4, driver.state.window_len);
    driver.state.state = .probe_bw_cruise;
    driver.state.window_len = test_bdp_len;
    recovery_bbr_control.set_window(&driver.state, test_sample(), driver.path(0));
    // CRUISE keeps the headroom: 0.85 of the bound.
    try testing.expectEqual(test_bdp_len / 4 / 100 * 85, driver.state.window_len);
    driver.state.inflight_longterm_len = std.math.maxInt(u64);
    driver.state.inflight_shortterm_len = test_bdp_len / 8;
    driver.state.window_len = test_bdp_len;
    recovery_bbr_control.set_window(&driver.state, test_sample(), driver.path(0));
    try testing.expectEqual(test_bdp_len / 8, driver.state.window_len);
}

test "§5.4.1: after an idle period in ProbeBW BBR paces at its estimate" {
    var driver: Driver = undefined;
    driver.init();
    driver.reach_probe_bw();
    driver.state.pacing_rate = 1;
    driver.state.bw = test_rate;
    driver.delivery.mark_application_limited(0);
    driver.state.on_transmit(driver.path(0), &driver.delivery);
    try testing.expectEqual(test_rate / 100 * 99, driver.state.pacing_rate);
}

const Tokens = std.mem.TokenIterator(u8, .scalar);
const decimal: u8 = 10;

fn field(fields: *Tokens) !u64 {
    return std.fmt.parseUnsigned(u64, fields.next() orelse return error.TestVectorShort, decimal);
}

fn expect_window_line(fields: *Tokens) !void {
    const full = fields.next() orelse return error.TestVectorShort;
    const inputs: recovery_bbr_control.WindowInputs = .{
        .full_bw_reached = std.mem.eql(u8, full, "true"),
        .window_len = try field(fields),
        .acknowledged_len = try field(fields),
        .max_inflight_len = try field(fields),
        .delivered_len = try field(fields),
        .initial_window_len = try field(fields),
        .min_pipe_len = try field(fields),
        .probe_rtt_cap_len = try field(fields),
        .model_cap_len = try field(fields),
    };
    try testing.expectEqual(try field(fields), recovery_bbr_control.next_window(inputs));
}

fn expect_quantum_line(fields: *Tokens) !void {
    var driver: Driver = undefined;
    driver.init();
    driver.state.pacing_rate = try field(fields);
    recovery_bbr_control.set_send_quantum(&driver.state, try field(fields));
    try testing.expectEqual(try field(fields), driver.state.send_quantum_len);
}

fn expect_pacing_line(fields: *Tokens) !void {
    var driver: Driver = undefined;
    driver.init();
    driver.state.full_bw_reached = true;
    driver.state.bw = try field(fields);
    recovery_bbr_control.set_pacing_rate_with_gain(&driver.state, try field(fields));
    try testing.expectEqual(try field(fields), driver.state.pacing_rate);
}

test "spec/lean/Colibri/Quic/BbrControl.lean: the controls give the proved definitions' answers" {
    var lines = std.mem.splitScalar(u8, @embedFile("bbr_control_vectors.txt"), '\n');
    var checked: usize = 0;
    // Bounded: the embedded file has a fixed number of lines.
    while (lines.next()) |line| {
        if (line.len == 0 or line[0] == '#') continue;
        var fields = std.mem.tokenizeScalar(u8, line, ' ');
        const kind = fields.next().?;
        if (std.mem.eql(u8, kind, "window")) {
            try expect_window_line(&fields);
        } else if (std.mem.eql(u8, kind, "quantum")) {
            try expect_quantum_line(&fields);
        } else if (std.mem.eql(u8, kind, "pacing")) {
            try expect_pacing_line(&fields);
        } else {
            return error.TestVectorKind;
        }
        try testing.expectEqual(null, fields.next());
        checked += 1;
    }
    try testing.expectEqual(254, checked);
}
