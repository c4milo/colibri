//! Tests of BBRv3's response to loss: one for each rule of draft-ietf-ccwg-bbr-06 §5.3.1.3,
//! §5.5.10 and §5.5.11.
const std = @import("std");
const testing = std.testing;
const constants = @import("../../constants.zig");
const recovery_delivery = @import("../recovery_delivery.zig");
const recovery_bbr = @import("recovery_bbr.zig");
const recovery_bbr_loss = @import("recovery_bbr_loss.zig");
const recovery_bbr_probe_bw = @import("recovery_bbr_probe_bw.zig");
const support = @import("recovery_bbr_test_support.zig");

const Driver = support.Driver;
const bbr = constants.recovery.bbr;
const test_round_trip_ns = support.test_round_trip_ns;
const test_datagram_len = support.test_datagram_len;
const test_rate = support.test_rate;
const test_acknowledged_len = support.test_acknowledged_len;
const unbounded_len = recovery_bbr.unbounded_len;
/// Octets in flight when a lost packet went out: its own loss alone is more than 2% of them.
const test_small_flight_len: u64 = 50_000;
/// Startup's rates in the rounds of loss recovery: each doubles, so the pipe does not fill.
const test_second_rate: u64 = 8_000_000;
const test_third_rate: u64 = 16_000_000;
/// Octets in flight when each of Startup's lost packets went out.
const test_startup_flight_len: u64 = 48_000;

test "§5.5.10.3: a round with loss outside a probe lowers the short-term model by Beta" {
    var driver: Driver = undefined;
    driver.init();
    driver.reach_probe_bw();
    try testing.expectEqual(.probe_bw_cruise, driver.state.state);
    try testing.expectEqual(unbounded_len, driver.state.bw_shortterm);
    // Each round starts the latest rate again: the faster round before is forgotten.
    driver.ack(test_round_trip_ns, test_rate, 0);
    driver.ack(test_round_trip_ns, test_rate / 4, 0);
    driver.lose(100, test_small_flight_len, 0);
    driver.ack(test_round_trip_ns, test_rate / 4, 0);
    // max(the round's rate, 0.7 × BBR.max_bw), and the window it started from.
    try testing.expectEqual(test_rate / 10 * 7, driver.state.bw_shortterm);
    try testing.expectEqual(driver.state.bw_shortterm, driver.state.bw);
    try testing.expectEqual(driver.state.window_len, driver.state.inflight_shortterm_len);
    try testing.expect(!driver.state.is_loss_in_round);
    // A round with no loss leaves it.
    driver.ack(test_round_trip_ns, test_rate / 4, 0);
    try testing.expectEqual(test_rate / 10 * 7, driver.state.bw_shortterm);
}

test "§5.5.10.3: a loss in Startup does not lower the short-term model" {
    var driver: Driver = undefined;
    driver.init();
    driver.ack(test_round_trip_ns, test_rate, 0);
    driver.lose(1, test_small_flight_len, 0);
    driver.ack(test_round_trip_ns, 2 * test_rate, 0);
    try testing.expectEqual(unbounded_len, driver.state.bw_shortterm);
    try testing.expectEqual(driver.state.model.max_bw, driver.state.bw);
}

test "§5.5.10.2: the loss crossed 2% inside the lost packet" {
    var sample = std.mem.zeroes(recovery_delivery.Sample);
    sample.tx_in_flight_len = 100_000;
    sample.lost_len = 3_000;
    // inflight_prev 98,800 and lost_prev 1,800: (2 × 98,800 − 100 × 1,800) / 98 is 179.
    try testing.expectEqual(98_979, recovery_bbr_loss.inflight_at_loss(sample, test_datagram_len));
    // Losses before the packet already crossed 2%, so the answer is below what preceded it.
    sample.lost_len = 10_000;
    try testing.expect(recovery_bbr_loss.inflight_at_loss(sample, test_datagram_len) < 98_800);
    // Never below 0.
    sample.tx_in_flight_len = test_datagram_len;
    sample.lost_len = 1_000_000;
    try testing.expectEqual(0, recovery_bbr_loss.inflight_at_loss(sample, test_datagram_len));
}

/// UP, where every sample is a bandwidth probe sample. Test-only.
fn reach_up(driver: *Driver) void {
    driver.init();
    driver.reach_probe_bw();
    while (driver.state.state != .probe_bw_up) driver.ack(test_round_trip_ns, test_rate, 0);
    std.debug.assert(driver.state.is_bw_probe_sample);
}

test "§5.5.10.2: too much loss in UP lowers BBR.inflight_longterm and goes DOWN" {
    var driver: Driver = undefined;
    reach_up(&driver);
    driver.lose(500, test_small_flight_len, 0);
    try testing.expect(driver.state.prev_probe_too_high);
    try testing.expect(!driver.state.is_bw_probe_sample);
    // InflightAtLoss: 48,800 in flight before it, and (2 × 48,800) / 98 more is 995.
    try testing.expectEqual(49_795, driver.state.inflight_longterm_len);
    try testing.expectEqual(.probe_bw_down, driver.state.state);
    try testing.expectEqual(.probe_bw_up, driver.state.undo_state.?);
    // "only react once per bw probe".
    driver.lose(501, 2 * test_small_flight_len, 0);
    try testing.expectEqual(49_795, driver.state.inflight_longterm_len);
}

test "§5.5.10.2: BBR.inflight_longterm stays at least Beta of the target" {
    var driver: Driver = undefined;
    reach_up(&driver);
    driver.state.window_len = 100 * test_small_flight_len;
    driver.lose(500, test_datagram_len, 0);
    // The target is the BDP, 200,000 octets, and 0.7 of it is 140,000.
    try testing.expectEqual(140_000, driver.state.inflight_longterm_len);
}

test "§5.5.10.2: a lost packet the application limited sets no bound" {
    var driver: Driver = undefined;
    reach_up(&driver);
    driver.delivery.on_lost(test_datagram_len);
    const record: @import("../recovery_sent.zig").Record = .{
        .number = 500,
        .sent_at_ns = driver.now_ns,
        .sent_len = test_datagram_len,
        .ack_eliciting = true,
        .in_flight = true,
        .tx_in_flight_len = test_small_flight_len,
        .application_limited = true,
    };
    driver.state.on_packet_lost(record, driver.delivery.lost_len, true, driver.path(0));
    try testing.expect(driver.state.prev_probe_too_high);
    try testing.expectEqual(unbounded_len, driver.state.inflight_longterm_len);
}

test "§5.5.10.2: losses before the lost packet went out are not its round's" {
    var driver: Driver = undefined;
    reach_up(&driver);
    // 5,000 octets were lost before the packet went out with 100,000 in flight. Its own 1,200
    // are 1.2% of that, below 2%.
    driver.delivery.on_lost(5_000);
    driver.lose(500, 2 * test_small_flight_len, 5_000);
    try testing.expect(!driver.state.prev_probe_too_high);
    try testing.expectEqual(.probe_bw_up, driver.state.state);
}

test "§5.5.10.2: a loss outside a probe sets no bound" {
    var driver: Driver = undefined;
    driver.init();
    driver.reach_probe_bw();
    driver.lose(100, test_small_flight_len, 0);
    try testing.expect(!driver.state.prev_probe_too_high);
    try testing.expectEqual(unbounded_len, driver.state.inflight_longterm_len);
}

test "§5.5.11.1: the first loss of a round saves the state, and a second keeps it" {
    var driver: Driver = undefined;
    driver.init();
    driver.reach_probe_bw();
    driver.state.bw_shortterm = test_rate;
    driver.state.undo_state = .probe_bw_up;
    driver.lose(100, test_small_flight_len, 0);
    try testing.expectEqual(test_rate, driver.state.undo_bw_shortterm);
    try testing.expectEqual(null, driver.state.undo_state);
    try testing.expectEqual(driver.delivered_len, driver.state.loss_round_delivered_len);
    driver.state.bw_shortterm = test_rate / 2;
    driver.lose(102, test_small_flight_len, 0);
    try testing.expectEqual(test_rate, driver.state.undo_bw_shortterm);
}

/// Startup in its second full round of loss recovery, with `lost_numbers` lost in the round that
/// ends at the last ACK frame, which keeps a queue in flight so Drain does not end at once.
/// Test-only.
fn startup_round_of_loss(driver: *Driver, lost_numbers: []const u64) void {
    driver.init();
    driver.ack(test_round_trip_ns, test_rate, 0);
    driver.in_recovery = true;
    driver.state.on_enter_recovery(driver.path(0));
    driver.ack(test_round_trip_ns, test_second_rate, 0);
    for (lost_numbers) |number| driver.lose(number, test_startup_flight_len, 0);
    driver.ack(test_round_trip_ns, test_third_rate, support.test_queue_len);
}

test "§5.3.1.3: six ranges of loss above 2% in a full round of recovery end Startup" {
    var driver: Driver = undefined;
    startup_round_of_loss(&driver, &.{ 10, 12, 14, 16, 18, 20 });
    try testing.expectEqual(.drain, driver.state.state);
    try testing.expect(driver.state.full_bw_reached);
    try testing.expectEqual(.startup, driver.state.undo_state.?);
    try testing.expect(driver.state.inflight_longterm_len >= test_acknowledged_len);
    try testing.expect(driver.state.inflight_longterm_len != unbounded_len);
}

test "§5.3.1.3: Startup ends on loss only inside a recovery period" {
    var driver: Driver = undefined;
    driver.init();
    driver.ack(test_round_trip_ns, test_rate, 0);
    driver.in_recovery = true;
    driver.state.on_enter_recovery(driver.path(0));
    driver.ack(test_round_trip_ns, test_second_rate, 0);
    for ([_]u64{ 10, 12, 14, 16, 18, 20 }) |number| driver.lose(number, test_startup_flight_len, 0);
    driver.in_recovery = false;
    driver.ack(test_round_trip_ns, test_third_rate, support.test_queue_len);
    try testing.expectEqual(.startup, driver.state.state);
}

test "§5.3.1.3: the bound after high loss is at least the round's largest delivery" {
    var driver: Driver = undefined;
    driver.init();
    driver.ack(test_round_trip_ns, test_rate, 0);
    driver.in_recovery = true;
    driver.state.on_enter_recovery(driver.path(0));
    driver.ack(test_round_trip_ns, test_second_rate, 0);
    for ([_]u64{ 10, 12, 14, 16, 18, 20 }) |number| driver.lose(number, test_startup_flight_len, 0);
    // A delivery far above the BDP in the round.
    driver.state.inflight_latest_len = 100 * support.test_bdp_len;
    driver.ack(test_round_trip_ns, test_third_rate, support.test_queue_len);
    try testing.expectEqual(.drain, driver.state.state);
    try testing.expectEqual(100 * support.test_bdp_len, driver.state.inflight_longterm_len);
}

test "§5.3.1.3: consecutive lost packets are one range" {
    var driver: Driver = undefined;
    startup_round_of_loss(&driver, &.{ 10, 11, 12, 13, 14, 15, 17 });
    try testing.expectEqual(.startup, driver.state.state);
    try testing.expectEqual(0, driver.state.round_lost_ranges);
}

test "§5.3.1.3: Startup waits for a full round of recovery" {
    var driver: Driver = undefined;
    driver.init();
    driver.ack(test_round_trip_ns, test_rate, 0);
    driver.in_recovery = true;
    driver.state.on_enter_recovery(driver.path(0));
    for ([_]u64{ 10, 12, 14, 16, 18, 20 }) |number| driver.lose(number, 4 * test_acknowledged_len, 0);
    driver.ack(test_round_trip_ns, 2 * test_rate, 0);
    try testing.expectEqual(.startup, driver.state.state);
}

test "§5.3.1.3: a loss of 2% or less does not end Startup" {
    var driver: Driver = undefined;
    driver.init();
    driver.ack(test_round_trip_ns, test_rate, 0);
    driver.in_recovery = true;
    driver.state.on_enter_recovery(driver.path(0));
    driver.ack(test_round_trip_ns, 2 * test_rate, 0);
    for ([_]u64{ 10, 12, 14, 16, 18, 20 }) |number| driver.lose(number, 4 * test_acknowledged_len, 0);
    // 7,200 lost of 12,000 acknowledged is 37%; raise the acknowledged octets to 360,000.
    driver.state.round_acknowledged_len = 360_000 - test_acknowledged_len;
    driver.ack(test_round_trip_ns, 4 * test_rate, 0);
    try testing.expectEqual(.startup, driver.state.state);
}

test "§5.5.11.2: a spurious episode that ended Startup returns to it" {
    var driver: Driver = undefined;
    startup_round_of_loss(&driver, &.{ 10, 12, 14, 16, 18, 20 });
    const prior_len = 3 * driver.state.window_len;
    driver.state.prior_window_len = prior_len;
    driver.state.on_spurious_loss(driver.path(0));
    try testing.expectEqual(.startup, driver.state.state);
    try testing.expect(!driver.state.full_bw_reached);
    try testing.expectEqual(null, driver.state.undo_state);
    try testing.expectEqual(prior_len, driver.state.window_len);
    try testing.expectEqual(0, driver.state.full_bw_count);
}

test "§5.5.11.2: a spurious episode that ended UP refills, with the old bounds back" {
    var driver: Driver = undefined;
    reach_up(&driver);
    driver.lose(500, test_small_flight_len, 0);
    try testing.expectEqual(.probe_bw_down, driver.state.state);
    driver.state.on_spurious_loss(driver.path(0));
    try testing.expectEqual(.probe_bw_refill, driver.state.state);
    // The bound saved before the loss was unbounded, so the larger one is too.
    try testing.expectEqual(unbounded_len, driver.state.inflight_longterm_len);
}

test "§5.3.3.9: REFILL and the end of ProbeRTT reset the short-term model, DOWN the signals" {
    var driver: Driver = undefined;
    driver.init();
    driver.reach_probe_bw();
    driver.state.bw_shortterm = test_rate / 2;
    driver.state.inflight_shortterm_len = test_acknowledged_len;
    recovery_bbr_probe_bw.start_refill(&driver.state, driver.path(0));
    try testing.expectEqual(unbounded_len, driver.state.bw_shortterm);
    try testing.expectEqual(unbounded_len, driver.state.inflight_shortterm_len);
    driver.state.is_loss_in_round = true;
    driver.state.bw_latest = test_rate;
    recovery_bbr_probe_bw.start_down(&driver.state, driver.path(0));
    try testing.expect(!driver.state.is_loss_in_round);
    try testing.expectEqual(0, driver.state.bw_latest);
    driver.ack(bbr.probe_rtt_interval_ns, test_rate, 0);
    try testing.expectEqual(.probe_rtt, driver.state.state);
    driver.state.bw_shortterm = test_rate / 2;
    driver.ack(bbr.probe_rtt_duration_ns + 1, test_rate, 0);
    try testing.expectEqual(.probe_bw_cruise, driver.state.state);
    try testing.expectEqual(unbounded_len, driver.state.bw_shortterm);
}

const Tokens = std.mem.TokenIterator(u8, .scalar);
const decimal: u8 = 10;

fn field(fields: *Tokens) !u64 {
    return std.fmt.parseUnsigned(u64, fields.next() orelse return error.TestVectorShort, decimal);
}

fn expect_at_loss_line(fields: *Tokens) !void {
    var sample = std.mem.zeroes(recovery_delivery.Sample);
    sample.tx_in_flight_len = try field(fields);
    sample.lost_len = try field(fields);
    const size_len = try field(fields);
    try testing.expectEqual(try field(fields), recovery_bbr_loss.inflight_at_loss(sample, size_len));
}

test "spec/lean/Colibri/Quic/BbrLoss.lean: the loss arithmetic gives the proved definitions' answers" {
    var lines = std.mem.splitScalar(u8, @embedFile("bbr_loss_vectors.txt"), '\n');
    var checked: usize = 0;
    // Bounded: the embedded file has a fixed number of lines.
    while (lines.next()) |line| {
        if (line.len == 0 or line[0] == '#') continue;
        var fields = std.mem.tokenizeScalar(u8, line, ' ');
        const kind = fields.next().?;
        if (std.mem.eql(u8, kind, "atloss")) {
            try expect_at_loss_line(&fields);
        } else if (std.mem.eql(u8, kind, "lower")) {
            const latest = try field(&fields);
            const bound = try field(&fields);
            try testing.expectEqual(try field(&fields), recovery_bbr_loss.lower(latest, bound));
        } else {
            return error.TestVectorKind;
        }
        try testing.expectEqual(null, fields.next());
        checked += 1;
    }
    try testing.expectEqual(74, checked);
}
