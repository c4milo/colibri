//! Tests of BBRv3's states: one for each move of draft-ietf-ccwg-bbr-06 §5.3 and §5.4.
const std = @import("std");
const testing = std.testing;
const constants = @import("../../constants.zig");
const recovery_delivery = @import("../recovery_delivery.zig");
const recovery_bbr = @import("recovery_bbr.zig");
const recovery_bbr_inflight = @import("recovery_bbr_inflight.zig");
const support = @import("recovery_bbr_test_support.zig");

const Driver = support.Driver;
const Sample = recovery_delivery.Sample;
const bbr = constants.recovery.bbr;
const test_round_trip_ns = support.test_round_trip_ns;
const test_datagram_len = support.test_datagram_len;
const test_initial_window_len = support.test_initial_window_len;
const test_rate = support.test_rate;
const test_bdp_len = support.test_bdp_len;
const test_waits = support.test_waits;
const test_queue_len = support.test_queue_len;

test "§5.2.1: BBR starts in Startup, with no bound on the octets in flight" {
    var driver: Driver = undefined;
    driver.init();
    try testing.expectEqual(.startup, driver.state.state);
    try testing.expectEqual(bbr.startup_pacing_gain, driver.state.pacing_gain);
    try testing.expectEqual(bbr.default_cwnd_gain, driver.state.cwnd_gain);
    try testing.expectEqual(recovery_bbr.unbounded_len, driver.state.inflight_longterm_len);
    try testing.expectEqual(test_initial_window_len, driver.state.window_len);
}

test "§5.3.1.2: three rounds that do not grow the rate by a quarter fill the pipe" {
    var driver: Driver = undefined;
    driver.init();
    for ([_]u64{ 1_000_000, 2_000_000, 4_000_000, 4_900_000, 4_900_000 }) |rate| {
        driver.ack(test_round_trip_ns, rate, 4 * test_bdp_len);
    }
    // 4,900,000 is below 1.25 × 4,000,000, so two rounds count, and the third fills the pipe.
    try testing.expectEqual(2, driver.state.full_bw_count);
    try testing.expectEqual(.startup, driver.state.state);
    driver.ack(test_round_trip_ns, 4_900_000, 4 * test_bdp_len);
    try testing.expect(driver.state.full_bw_reached);
    try testing.expectEqual(.drain, driver.state.state);
    try testing.expectEqual(bbr.drain_pacing_gain, driver.state.pacing_gain);
}

test "§5.3.1.2: a sample the application limited does not count toward a full pipe" {
    var driver: Driver = undefined;
    driver.init();
    driver.ack(test_round_trip_ns, test_rate, 0);
    driver.state.model.round_start = true;
    var sample: Sample = undefined;
    sample = .{ .rate = test_rate, .delivered_len = 1, .interval_ns = 1, .application_limited = true, .prior_delivered_len = 0, .acknowledged_len = 1, .rtt_ns = 1, .tx_in_flight_len = 1, .lost_len = 0 };
    @import("recovery_bbr_startup.zig").check_full_bw_reached(&driver.state, sample);
    try testing.expectEqual(0, driver.state.full_bw_count);
}

test "§5.3.2: Drain ends once the octets in flight fit one BDP" {
    var driver: Driver = undefined;
    driver.init();
    driver.fill_pipe();
    try testing.expectEqual(.drain, driver.state.state);
    driver.ack(test_round_trip_ns, test_rate, test_bdp_len + 1);
    try testing.expectEqual(.drain, driver.state.state);
    // One BDP in flight ends Drain, and in the same ACK frame DOWN finds no queue left.
    driver.ack(test_round_trip_ns, test_rate, test_bdp_len);
    try testing.expectEqual(.probe_bw_cruise, driver.state.state);
    try testing.expectEqual(1, driver.state.probe_waits_drawn);
}

test "§5.3.2: Drain ends 3 rounds on, whatever is in flight" {
    var driver: Driver = undefined;
    driver.init();
    driver.fill_pipe();
    for (0..3) |_| driver.ack(test_round_trip_ns, test_rate, 4 * test_bdp_len);
    try testing.expectEqual(.drain, driver.state.state);
    driver.ack(test_round_trip_ns, test_rate, 4 * test_bdp_len);
    try testing.expectEqual(.probe_bw_down, driver.state.state);
}

test "§5.3.3.9: DOWN cruises once the queue is gone" {
    var driver: Driver = undefined;
    driver.init();
    driver.fill_pipe();
    for (0..4) |_| driver.ack(test_round_trip_ns, test_rate, 4 * test_bdp_len);
    try testing.expectEqual(.probe_bw_down, driver.state.state);
    try testing.expectEqual(bbr.probe_bw_down_pacing_gain, driver.state.pacing_gain);
    driver.ack(test_round_trip_ns / 10, test_rate, test_bdp_len + 1);
    try testing.expectEqual(.probe_bw_down, driver.state.state);
    driver.ack(test_round_trip_ns / 10, test_rate, test_bdp_len);
    try testing.expectEqual(.probe_bw_cruise, driver.state.state);
    try testing.expectEqual(bbr.probe_bw_steady_pacing_gain, driver.state.pacing_gain);
}

test "§5.3.3.8.2: the wall clock wait moves CRUISE to REFILL, and one round moves it to UP" {
    var driver: Driver = undefined;
    driver.init();
    driver.reach_probe_bw();
    // A window of 100 BDPs puts the Reno bound at 63 rounds, past the wait.
    driver.state.window_len = 100 * test_bdp_len;
    driver.ack(1, test_rate, 0);
    try testing.expectEqual(.probe_bw_cruise, driver.state.state);
    const wait_ns = driver.state.bw_probe_wait_ns;
    try testing.expect(wait_ns >= bbr.probe_wait_min_ns and wait_ns < bbr.probe_wait_min_ns + bbr.probe_wait_spread_ns);
    driver.ack(driver.state.cycle_start_ns + wait_ns - driver.now_ns, test_rate, 0);
    try testing.expectEqual(.probe_bw_cruise, driver.state.state);
    driver.ack(1, test_rate, 0);
    try testing.expectEqual(.probe_bw_refill, driver.state.state);
    try testing.expectEqual(.refilling, driver.state.ack_phase);
    driver.ack(test_round_trip_ns, test_rate, 0);
    try testing.expectEqual(.probe_bw_up, driver.state.state);
    try testing.expectEqual(bbr.probe_bw_up_pacing_gain, driver.state.pacing_gain);
    try testing.expectEqual(bbr.probe_bw_up_cwnd_gain, driver.state.cwnd_gain);
    try testing.expect(driver.state.is_bw_probe_sample);
}

test "§5.3.3.8.2: a Reno flow's round trips bound the wait before the wall clock does" {
    var driver: Driver = undefined;
    driver.init();
    driver.reach_probe_bw();
    // The window is 10 datagrams, so a Reno flow needs 10 rounds: at most 10 more ACK frames.
    var rounds: u64 = 0;
    while (driver.state.state != .probe_bw_refill and rounds < 12) : (rounds += 1) {
        driver.ack(test_round_trip_ns, test_rate, 0);
    }
    try testing.expectEqual(.probe_bw_refill, driver.state.state);
    try testing.expect(rounds <= test_initial_window_len / test_datagram_len);
    try testing.expect(driver.now_ns < driver.state.cycle_start_ns + bbr.probe_wait_min_ns);
}

test "§5.3.3.9: UP goes DOWN once three rounds no longer grow the rate" {
    var driver: Driver = undefined;
    driver.init();
    driver.reach_probe_bw();
    while (driver.state.state != .probe_bw_up) driver.ack(test_round_trip_ns, test_rate, 0);
    for (0..3) |_| driver.ack(test_round_trip_ns, test_rate, 0);
    try testing.expectEqual(.probe_bw_down, driver.state.state);
    try testing.expect(!driver.state.prev_probe_too_high);
    try testing.expectEqual(.probe_stopping, driver.state.ack_phase);
}

test "§5.3.3.9: BBR.max_bw's cycle advances one round after a probe stops" {
    var driver: Driver = undefined;
    driver.init();
    driver.fill_pipe();
    const cycles = driver.state.model.cycle_count;
    // Drain ends, DOWN starts a round, and the ACK frame that ends it advances the filter.
    driver.ack(test_round_trip_ns, test_rate, test_bdp_len);
    driver.ack(test_round_trip_ns, test_rate, test_bdp_len);
    try testing.expectEqual(cycles + 1, driver.state.model.cycle_count);
    try testing.expectEqual(.init, driver.state.ack_phase);
}

test "§5.3.3.9: a safe loss rate raises BBR.inflight_longterm to what was in flight" {
    var driver: Driver = undefined;
    driver.init();
    driver.reach_probe_bw();
    driver.state.inflight_longterm_len = test_bdp_len;
    driver.ack(test_round_trip_ns, test_rate, 2 * test_bdp_len);
    try testing.expectEqual(2 * test_bdp_len, driver.state.inflight_longterm_len);
}

test "§5.5.10.2: more than 2% of the octets in flight lost is too high" {
    var sample: Sample = .{ .rate = 0, .delivered_len = 0, .interval_ns = 0, .application_limited = false, .prior_delivered_len = 0, .acknowledged_len = 0, .rtt_ns = 0, .tx_in_flight_len = 100_000, .lost_len = 2_000 };
    try testing.expect(!recovery_bbr_inflight.is_inflight_too_high(sample));
    sample.lost_len = 2_001;
    try testing.expect(recovery_bbr_inflight.is_inflight_too_high(sample));
}

test "§5.6.4.2: the volumes start at the initial window and keep a floor of 4 datagrams" {
    var driver: Driver = undefined;
    driver.init();
    const at = driver.path(0);
    try testing.expectEqual(test_initial_window_len, recovery_bbr_inflight.bdp_multiple(&driver.state, at, test_rate, bbr.gain_denominator));
    driver.state.model.min_rtt_ns = test_round_trip_ns;
    try testing.expectEqual(test_bdp_len, recovery_bbr_inflight.inflight(&driver.state, at, test_rate, bbr.gain_denominator));
    try testing.expectEqual(4 * test_datagram_len, recovery_bbr_inflight.inflight(&driver.state, at, 0, bbr.gain_denominator));
    driver.state.state = .probe_bw_up;
    try testing.expectEqual(6 * test_datagram_len, recovery_bbr_inflight.inflight(&driver.state, at, 0, bbr.gain_denominator));
}

test "§5.3.3.9: the headroom is 15% of BBR.inflight_longterm, and at least one datagram" {
    var driver: Driver = undefined;
    driver.init();
    const at = driver.path(0);
    try testing.expectEqual(recovery_bbr.unbounded_len, recovery_bbr_inflight.inflight_with_headroom(&driver.state, at));
    driver.state.inflight_longterm_len = 100 * test_datagram_len;
    try testing.expectEqual(85 * test_datagram_len, recovery_bbr_inflight.inflight_with_headroom(&driver.state, at));
    driver.state.inflight_longterm_len = 5 * test_datagram_len;
    try testing.expectEqual(4 * test_datagram_len, recovery_bbr_inflight.inflight_with_headroom(&driver.state, at));
}

test "§5.3.4.3: ProbeRTT comes 5 s after the last lower round trip, and lasts 200 ms and a round" {
    var driver: Driver = undefined;
    driver.init();
    driver.reach_probe_bw();
    driver.state.window_len = 100 * test_bdp_len;
    const window_len = driver.state.window_len;
    // Every sample equals the minimum, so none refreshes it, and 5 s later the probe expires.
    driver.ack(bbr.probe_rtt_interval_ns, test_rate, 4 * test_bdp_len);
    try testing.expectEqual(.probe_rtt, driver.state.state);
    try testing.expectEqual(bbr.probe_rtt_cwnd_gain, driver.state.cwnd_gain);
    try testing.expectEqual(window_len, driver.state.prior_window_len);
    try testing.expectEqual(0, driver.state.probe_rtt_done_at_ns);
    // Once in flight falls to half the BDP, the 200 ms start.
    driver.ack(test_round_trip_ns, test_rate, test_bdp_len / 2);
    try testing.expectEqual(driver.now_ns + bbr.probe_rtt_duration_ns, driver.state.probe_rtt_done_at_ns);
    driver.ack(test_round_trip_ns, test_rate, 0);
    try testing.expectEqual(.probe_rtt, driver.state.state);
    driver.ack(bbr.probe_rtt_duration_ns, test_rate, 0);
    try testing.expectEqual(.probe_bw_cruise, driver.state.state);
    try testing.expectEqual(driver.now_ns, driver.state.model.probe_rtt_min_at_ns);
    try testing.expectEqual(window_len, driver.state.window_len);
}

test "§5.3.4.3: ProbeRTT marks the connection limited by the application" {
    var driver: Driver = undefined;
    driver.init();
    driver.reach_probe_bw();
    driver.ack(bbr.probe_rtt_interval_ns, test_rate, 4 * test_bdp_len);
    try testing.expectEqual(.probe_rtt, driver.state.state);
    try testing.expect(driver.delivery.application_limited_until != 0);
}

test "§5.3.4.4: ProbeRTT before a full pipe goes back to Startup" {
    var driver: Driver = undefined;
    driver.init();
    // The rate doubles each round, so the pipe never fills.
    driver.ack(test_round_trip_ns, test_rate, 0);
    // §5.3.4.3: "Now() > BBR.probe_rtt_min_stamp + BBR.ProbeRTTInterval".
    driver.ack(bbr.probe_rtt_interval_ns, 2 * test_rate, 0);
    try testing.expectEqual(.startup, driver.state.state);
    driver.ack(1, 4 * test_rate, 0);
    try testing.expectEqual(.probe_rtt, driver.state.state);
    driver.ack(test_round_trip_ns, 8 * test_rate, 0);
    driver.ack(bbr.probe_rtt_duration_ns + 1, 16 * test_rate, 0);
    try testing.expect(!driver.state.full_bw_reached);
    try testing.expectEqual(.startup, driver.state.state);
    try testing.expectEqual(bbr.startup_pacing_gain, driver.state.pacing_gain);
}

test "§5.4: a restart from idle keeps BBR out of ProbeRTT and starts the aggregation interval" {
    var driver: Driver = undefined;
    driver.init();
    driver.reach_probe_bw();
    driver.now_ns += bbr.probe_rtt_interval_ns;
    driver.delivery.mark_application_limited(0);
    // Data in flight is no idle period.
    driver.state.on_transmit(driver.path(test_datagram_len), &driver.delivery);
    try testing.expect(!driver.state.idle_restart);
    driver.state.on_transmit(driver.path(0), &driver.delivery);
    try testing.expect(driver.state.idle_restart);
    try testing.expectEqual(driver.now_ns, driver.state.model.extra_acked_interval_start_ns);
    driver.ack(0, test_rate, test_datagram_len);
    // The probe's minimum expired and took this frame's sample, so the idle period counts as the
    // drain ProbeRTT would have made, and the next ProbeRTT is 5 s away.
    try testing.expect(driver.state.state != .probe_rtt);
    try testing.expectEqual(driver.now_ns, driver.state.model.probe_rtt_min_at_ns);
    // The ACK frame delivered data, so the restart is over.
    try testing.expect(!driver.state.idle_restart);
}

test "§5.4: an idle period ends a ProbeRTT whose time has passed" {
    var driver: Driver = undefined;
    driver.init();
    driver.reach_probe_bw();
    driver.ack(bbr.probe_rtt_interval_ns, test_rate, 0);
    driver.ack(test_round_trip_ns, test_rate, 0);
    try testing.expect(driver.state.probe_rtt_done_at_ns != 0);
    driver.now_ns = driver.state.probe_rtt_done_at_ns + 1;
    driver.delivery.mark_application_limited(0);
    driver.state.on_transmit(driver.path(0), &driver.delivery);
    try testing.expectEqual(.probe_bw_cruise, driver.state.state);
}

test "decision 136: each probe wait takes the next draw" {
    var driver: Driver = undefined;
    driver.init();
    driver.reach_probe_bw();
    try testing.expectEqual(1, driver.state.probe_waits_drawn);
    const drawn = @import("recovery_bbr_wait.zig").draw(test_waits, 0);
    try testing.expectEqual(drawn.wait_ns, driver.state.bw_probe_wait_ns);
}
