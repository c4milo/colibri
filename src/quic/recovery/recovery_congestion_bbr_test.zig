//! BBRv3 inside RFC 9002's loss recovery (design §8 step 29b.4): each event of
//! `recovery_congestion_bbr.zig` driven through `Recovery`'s entry points.
const std = @import("std");
const constants = @import("../constants.zig");
const space = @import("../space/space.zig");
const frame_ack = @import("../frame/frame_ack.zig");
const recovery = @import("recovery.zig");
const recovery_ack = @import("recovery_ack.zig");
const recovery_congestion = @import("recovery_congestion.zig");
const recovery_sent = @import("recovery_sent.zig");

const Kind = space.Kind;
const Record = recovery_sent.Record;
const testing = std.testing;
const bbr_constants = constants.recovery.bbr;

var test_recovery: recovery.Recovery align(@alignOf(recovery.Recovery)) = undefined;
var test_acknowledged: [constants.limits.sent_packets_max]Record align(@alignOf(Record)) = undefined;
var test_lost: [constants.limits.sent_packets_max]Record align(@alignOf(Record)) = undefined;
const test_datagram_len: u16 = 1_200;
const test_start_ns: u64 = 1_000_000_000;
const test_round_trip_ns: u64 = 100_000_000;
const test_long_after_ns: u64 = 100_000_000_000;
const test_waits: u64 = 7;

/// A connection's recovery under BBRv3, started at `test_start_ns`. Test-only.
fn init_bbr() void {
    test_recovery.init(test_datagram_len);
    test_recovery.congestion.select(.{ .controller = .bbr, .bandwidth_probe_waits = test_waits }, test_start_ns);
}

fn eliciting(number: u64, sent_at_ns: u64) Record {
    return .{ .number = number, .sent_at_ns = sent_at_ns, .sent_len = test_datagram_len, .ack_eliciting = true, .in_flight = true };
}

fn ack_of(smallest: u64, largest: u64) recovery_ack.Ack {
    const ranges: frame_ack.AckRanges = .{ .largest_acknowledged = largest, .first_range = largest - smallest, .octets = &.{}, .count = 0 };
    return .{ .ranges = ranges, .delay_ns = 0, .ecn = null };
}

fn send(first: u64, count: u64, from_ns: u64, interval_ns: u64) !void {
    for (0..count) |step| {
        const at_ns = from_ns + step * interval_ns;
        try test_recovery.on_packet_sent(.application, eliciting(first + step, at_ns), at_ns);
    }
}

fn bbr() *@import("recovery_bbr/recovery_bbr.zig").Bbr {
    return &test_recovery.congestion.state.bbr;
}

test "decision 136: BBRv3 paces at its own rate, with its send quantum as the burst" {
    init_bbr();
    const rate = test_recovery.rate();
    try testing.expectEqual(bbr().pacing_rate, rate.period_len);
    // 1 ms of 33,240,000 octets a second, the initial window over 1 ms at Startup's gain.
    try testing.expectEqual(33_240, rate.burst_len);
    try testing.expectEqual(recovery_congestion.initial_window(test_datagram_len), test_recovery.congestion.window);
    try testing.expectEqual(test_recovery.congestion.window, bbr().window_len);
}

test "§5.2.3: an ACK frame runs BBRv3's model and sets the window" {
    init_bbr();
    try send(0, 4, test_start_ns, 1);
    const at_ns = test_start_ns + test_round_trip_ns;
    _ = recovery_ack.on_ack_received(&test_recovery, .application, ack_of(0, 3), .full, at_ns, &test_acknowledged, &test_lost);
    // Startup grows the window by what was acknowledged, and both copies agree.
    try testing.expectEqual(recovery_congestion.initial_window(test_datagram_len) + 4 * test_datagram_len, test_recovery.congestion.window);
    try testing.expectEqual(test_recovery.congestion.window, bbr().window_len);
    try testing.expectEqual(1, bbr().model.round_count);
    try testing.expect(bbr().has_seen_rtt);
}

test "§5.2.4: a loss starts a recovery period without CUBIC's decrease, and BBRv3 saves its window" {
    init_bbr();
    try send(0, 5, test_start_ns, test_round_trip_ns);
    const window = test_recovery.congestion.window;
    const at_ns = test_start_ns + 5 * test_round_trip_ns;
    const outcome = recovery_ack.on_ack_received(&test_recovery, .application, ack_of(4, 4), .full, at_ns, &test_acknowledged, &test_lost);
    try testing.expectEqual(4, outcome.lost.count);
    try testing.expectEqual(at_ns, test_recovery.congestion.recovery_started_at_ns.?);
    try testing.expect(test_recovery.congestion.window >= window);
    try testing.expectEqual(window, bbr().prior_window_len);
    // BBRv3 took each lost packet, and the period started its `OnEnterFastRecovery`.
    try testing.expectEqual(3, bbr().last_lost_number.?);
    try testing.expectEqual(0, bbr().recovery_start_round.?);
}

test "§5.2.5: a spurious episode restores the window BBRv3 saved" {
    init_bbr();
    try send(0, 5, test_start_ns, test_round_trip_ns);
    const at_ns = test_start_ns + 5 * test_round_trip_ns;
    _ = recovery_ack.on_ack_received(&test_recovery, .application, ack_of(4, 4), .full, at_ns, &test_acknowledged, &test_lost);
    const saved = bbr().prior_window_len;
    test_recovery.congestion.set_window(test_datagram_len);
    const late = recovery_ack.on_ack_received(&test_recovery, .application, ack_of(0, 3), .full, at_ns + 1, &test_acknowledged, &test_lost);
    try testing.expect(late.spurious);
    try testing.expectEqual(saved, test_recovery.congestion.window);
    try testing.expectEqual(saved, bbr().window_len);
}

test "RFC 9002 §7.6.2: persistent congestion puts BBRv3's window at the minimum, after it saves it" {
    init_bbr();
    test_recovery.timer.handshake_confirmed = true;
    try send(0, 1, test_start_ns, 0);
    _ = recovery_ack.on_ack_received(&test_recovery, .application, ack_of(0, 0), .full, test_start_ns + test_round_trip_ns, &test_acknowledged, &test_lost);
    const run: u64 = 16;
    try send(1, run, test_start_ns + 2 * test_round_trip_ns, test_round_trip_ns);
    try send(run + 1, 1, test_long_after_ns, 0);
    const window = test_recovery.congestion.window;
    const outcome = recovery_ack.on_ack_received(&test_recovery, .application, ack_of(run + 1, run + 1), .full, test_long_after_ns + test_round_trip_ns, &test_acknowledged, &test_lost);
    try testing.expect(outcome.lost.is_persistent_congestion(test_recovery.rtt.persistent_congestion_ns()));
    try testing.expect(bbr().prior_window_len >= window);
    // The same frame's acknowledgment then runs BBRv3, whose floor is 4 datagrams.
    try testing.expectEqual(bbr_constants.min_pipe_cwnd_datagrams * test_datagram_len, test_recovery.congestion.window);
    try testing.expectEqual(test_recovery.congestion.window, bbr().window_len);
}

test "RFC 9000 §9.4: a new path starts BBRv3 again, not CUBIC" {
    init_bbr();
    try send(0, 4, test_start_ns, 1);
    _ = recovery_ack.on_ack_received(&test_recovery, .application, ack_of(0, 3), .full, test_start_ns + test_round_trip_ns, &test_acknowledged, &test_lost);
    test_recovery.on_path_changed();
    try testing.expectEqual(.bbr, std.meta.activeTag(test_recovery.congestion.state));
    try testing.expectEqual(0, bbr().model.round_count);
    try testing.expectEqual(test_waits, bbr().bandwidth_probe_waits);
    try testing.expectEqual(test_start_ns + test_round_trip_ns, bbr().model.min_rtt_at_ns);
}

test "RFC 9002 §7.2: a smaller datagram puts BBRv3's window back to the initial one too" {
    init_bbr();
    test_recovery.congestion.set_max_datagram_len(2 * test_datagram_len);
    test_recovery.congestion.set_window(10 * recovery_congestion.initial_window(test_datagram_len));
    test_recovery.congestion.set_max_datagram_len(constants.protocol.datagram_len_min);
    try testing.expectEqual(recovery_congestion.initial_window(constants.protocol.datagram_len_min), bbr().window_len);
    _ = Kind;
}

test "§5.3.1.3: an ACK frame of a packet sent inside a recovery period can end Startup on loss" {
    init_bbr();
    try send(0, 1, test_start_ns, 0);
    const first_ns = test_start_ns + test_round_trip_ns;
    _ = recovery_ack.on_ack_received(&test_recovery, .application, ack_of(0, 0), .full, first_ns, &test_acknowledged, &test_lost);
    try send(1, 1, first_ns + 1, 0);
    // A recovery period that started after packet 1 went out, in round 0, and a round of heavy
    // loss in six ranges.
    test_recovery.congestion.recovery_started_at_ns = first_ns + 2;
    const state = bbr();
    state.recovery_start_round = 0;
    state.round_lost_len = 100 * @as(u64, test_datagram_len);
    state.round_lost_ranges = 6;
    _ = recovery_ack.on_ack_received(&test_recovery, .application, ack_of(1, 1), .full, first_ns + test_round_trip_ns, &test_acknowledged, &test_lost);
    // Startup ended on loss. Nothing is in flight, so Drain ended in the same frame too.
    try testing.expect(state.full_bw_reached);
    try testing.expectEqual(.startup, state.undo_state.?);
    try testing.expect(state.state != .startup);
}

test "§5.3.3.9: an ACK frame the window bounded is one BBRv3 reads as `C.is_cwnd_limited`" {
    init_bbr();
    try send(0, 2, test_start_ns, 1);
    _ = recovery_ack.on_ack_received(&test_recovery, .application, ack_of(0, 0), .full, test_start_ns + test_round_trip_ns, &test_acknowledged, &test_lost);
    // UP, held at BBR.inflight_longterm by the window, after three rounds with no growth.
    const state = bbr();
    state.state = .probe_bw_up;
    state.full_bw_reached = true;
    state.full_bw_now = true;
    state.inflight_longterm_len = test_recovery.congestion.window;
    _ = recovery_ack.on_ack_received(&test_recovery, .application, ack_of(1, 1), .full, test_start_ns + 2 * test_round_trip_ns, &test_acknowledged, &test_lost);
    try testing.expectEqual(.probe_bw_up, state.state);
    try testing.expect(!state.full_bw_now);
}
