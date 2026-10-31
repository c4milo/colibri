//! Tests of the bounds BBRv3's probes keep (draft-ietf-ccwg-bbr-06 §5.3.1.2, §5.3.3, §5.3.4):
//! one for each rule a mutation of design §8 step 29b.2 found no test for.
const std = @import("std");
const testing = std.testing;
const constants = @import("../../constants.zig");
const recovery_delivery = @import("../recovery_delivery.zig");
const recovery_bbr_startup = @import("recovery_bbr_startup.zig");
const support = @import("recovery_bbr_test_support.zig");

const Driver = support.Driver;
const bbr = constants.recovery.bbr;
const test_round_trip_ns = support.test_round_trip_ns;
const test_datagram_len = support.test_datagram_len;
const test_rate = support.test_rate;
const test_bdp_len = support.test_bdp_len;
const test_queue_len = support.test_queue_len;
/// More ACK frames than any probe wait takes to reach UP.
const test_acks_max: u64 = 100;

test "§5.3.1.2: a rate of exactly 1.25 times the baseline still grows" {
    var driver: Driver = undefined;
    driver.init();
    driver.state.full_bw = test_rate;
    driver.state.full_bw_count = 2;
    driver.state.model.round_start = true;
    var sample = std.mem.zeroes(recovery_delivery.Sample);
    sample.rate = test_rate / 4 * 5;
    recovery_bbr_startup.check_full_bw_reached(&driver.state, sample);
    try testing.expectEqual(0, driver.state.full_bw_count);
    try testing.expectEqual(sample.rate, driver.state.full_bw);
}

test "§5.3.3.8.2: the Reno bound is 63 rounds once the BDP is larger" {
    var driver: Driver = undefined;
    driver.init();
    driver.reach_probe_bw();
    // The BDP is 166 datagrams and the window larger, so the bound is 63 rounds.
    driver.state.window_len = 100 * test_bdp_len;
    // Each ACK frame counts one round before the bound is read.
    driver.state.rounds_since_probe_up = 61;
    driver.ack(1, test_rate, 0);
    try testing.expectEqual(.probe_bw_cruise, driver.state.state);
    driver.ack(1, test_rate, 0);
    try testing.expectEqual(.probe_bw_refill, driver.state.state);
}

test "§5.3.3.9: DOWN keeps the headroom below BBR.inflight_longterm before it cruises" {
    var driver: Driver = undefined;
    driver.init();
    driver.fill_pipe();
    for (0..4) |_| driver.ack(test_round_trip_ns, test_rate, test_queue_len);
    try testing.expectEqual(.probe_bw_down, driver.state.state);
    // One BDP less 15% is 170,000 octets: 190,000 fits the BDP but not the headroom.
    driver.state.inflight_longterm_len = test_bdp_len;
    driver.ack(1, test_rate, 190_000);
    try testing.expectEqual(.probe_bw_down, driver.state.state);
    driver.ack(1, test_rate, 170_000);
    try testing.expectEqual(.probe_bw_cruise, driver.state.state);
}

test "§5.3.3.9: REFILL waits for its round to end before UP" {
    var driver: Driver = undefined;
    driver.init();
    driver.reach_probe_bw();
    while (driver.state.state != .probe_bw_refill) driver.ack(test_round_trip_ns, test_rate, 0);
    driver.ack_within_round(test_round_trip_ns, test_rate, 0);
    try testing.expectEqual(.probe_bw_refill, driver.state.state);
    driver.ack(test_round_trip_ns, test_rate, 0);
    try testing.expectEqual(.probe_bw_up, driver.state.state);
}

/// UP with BBR.inflight_longterm at `window_len` and a full window. Test-only.
fn reach_up_at_window(driver: *Driver, window_len: u64) void {
    driver.init();
    driver.state.window_len = window_len;
    driver.reach_probe_bw();
    var acks: u64 = 0;
    while (driver.state.state != .probe_bw_up and acks < test_acks_max) : (acks += 1) {
        driver.ack(test_round_trip_ns, test_rate, 0);
    }
    driver.state.inflight_longterm_len = window_len;
    driver.window_limited = true;
}

test "§5.3.3.9: UP held at BBR.inflight_longterm by a full window does not go down" {
    var driver: Driver = undefined;
    reach_up_at_window(&driver, test_bdp_len);
    try testing.expectEqual(.probe_bw_up, driver.state.state);
    // Three rounds with no growth would fill the pipe, but the bound held the window.
    driver.state.full_bw_now = true;
    driver.ack(test_round_trip_ns, test_rate, 0);
    try testing.expectEqual(.probe_bw_up, driver.state.state);
    try testing.expect(!driver.state.full_bw_now);
    try testing.expectEqual(test_rate, driver.state.full_bw);
}

test "§5.3.3.9: UP raises BBR.inflight_longterm faster each round" {
    var driver: Driver = undefined;
    reach_up_at_window(&driver, test_bdp_len);
    // Entering UP set 200,000 octets per datagram of growth, and each round halves it: 100,000,
    // then 50,000, then 25,000. Each ACK frame acknowledges 12,000 octets, so the fourth frame
    // brings 48,000, past the step of 25,000.
    const window_len = driver.state.window_len;
    for (0..3) |_| driver.ack(test_round_trip_ns, test_rate, 0);
    try testing.expectEqual(window_len, driver.state.inflight_longterm_len);
    try testing.expectEqual(4, driver.state.bw_probe_up_rounds);
    driver.ack(test_round_trip_ns, test_rate, 0);
    try testing.expectEqual(window_len + test_datagram_len, driver.state.inflight_longterm_len);
    try testing.expectEqual(5, driver.state.bw_probe_up_rounds);
}

test "§5.3.4.3: ProbeRTT paces at the estimate and ends only after its round" {
    var driver: Driver = undefined;
    driver.init();
    driver.reach_probe_bw();
    driver.ack(bbr.probe_rtt_interval_ns, test_rate, 0);
    try testing.expectEqual(.probe_rtt, driver.state.state);
    try testing.expectEqual(bbr.probe_rtt_pacing_gain, driver.state.pacing_gain);
    const done_at_ns = driver.state.probe_rtt_done_at_ns;
    try testing.expect(done_at_ns != 0);
    // Past the 200 ms, but no round has ended.
    driver.ack_within_round(done_at_ns + 1 - driver.now_ns, test_rate, 0);
    try testing.expectEqual(.probe_rtt, driver.state.state);
    driver.ack(1, test_rate, 0);
    try testing.expectEqual(.probe_bw_cruise, driver.state.state);
}

test "§5.3.4.3: ProbeRTT ends after its 200 ms, not at them" {
    var driver: Driver = undefined;
    driver.init();
    driver.reach_probe_bw();
    driver.ack(bbr.probe_rtt_interval_ns, test_rate, 0);
    const done_at_ns = driver.state.probe_rtt_done_at_ns;
    driver.ack(done_at_ns - driver.now_ns, test_rate, 0);
    try testing.expectEqual(.probe_rtt, driver.state.state);
    driver.ack(1, test_rate, 0);
    try testing.expectEqual(.probe_bw_cruise, driver.state.state);
}

test "§5.6.4.4: ProbeRTT keeps the larger saved window and restores it" {
    var driver: Driver = undefined;
    driver.init();
    driver.reach_probe_bw();
    const prior_len = 2 * driver.state.window_len;
    driver.state.prior_window_len = prior_len;
    driver.ack(bbr.probe_rtt_interval_ns, test_rate, 0);
    try testing.expectEqual(.probe_rtt, driver.state.state);
    try testing.expectEqual(prior_len, driver.state.prior_window_len);
    // ProbeRTT's window is smaller (29b.4 sets it), and the end restores the saved one.
    driver.state.window_len = 4 * test_datagram_len;
    driver.ack(bbr.probe_rtt_duration_ns + 1, test_rate, 0);
    try testing.expectEqual(.probe_bw_cruise, driver.state.state);
    try testing.expectEqual(prior_len, driver.state.window_len);
}
