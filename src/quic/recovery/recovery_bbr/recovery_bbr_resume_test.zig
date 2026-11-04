//! The tests of Careful Resume under BBRv3 (`recovery_bbr_resume.zig` and
//! `recovery_resume_phases.zig`, RFC 9959 Appendix C), driven through `Recovery`'s entry points.
const std = @import("std");
const constants = @import("../../constants.zig");
const frame_ack = @import("../../frame/frame_ack.zig");
const recovery = @import("../recovery.zig");
const recovery_ack = @import("../recovery_ack.zig");
const recovery_congestion = @import("../recovery_congestion.zig");
const recovery_resume = @import("../recovery_resume.zig");
const recovery_resume_phases = @import("../recovery_resume_phases.zig");
const recovery_sent = @import("../recovery_sent.zig");
const recovery_bbr = @import("recovery_bbr.zig");
const recovery_bbr_resume = @import("recovery_bbr_resume.zig");
const recovery_bbr_startup = @import("recovery_bbr_startup.zig");

const Record = recovery_sent.Record;
const testing = std.testing;

var test_recovery: recovery.Recovery align(@alignOf(recovery.Recovery)) = undefined;
var acknowledged: [constants.limits.sent_packets_max]Record align(@alignOf(Record)) = undefined;
var lost: [constants.limits.sent_packets_max]Record align(@alignOf(Record)) = undefined;

const datagram_len: u16 = 1_200;
const start_ns: u64 = 1_000_000_000;
const rtt_ns: u64 = 100_000_000;
const waits: u64 = 7;
const initial_packets: u64 = recovery_congestion.initial_window(datagram_len) / datagram_len;
/// A saved window of 400,000 octets over 100 ms: a jump of 200,000, so a probing rate of
/// 2,000,000 octets a second.
const saved_window_len: u64 = 400_000;
const probing_rate: u64 = 2_000_000;
const saved: recovery_resume.ResumeState = .{ .window_len = saved_window_len, .rtt_ns = rtt_ns, .saved_at_ns = start_ns };

fn start() void {
    test_recovery.init(datagram_len);
    test_recovery.congestion.select(.{ .controller = .bbr, .bandwidth_probe_waits = waits }, start_ns);
    test_recovery.careful_resume.init(saved, .{}, start_ns);
}

fn bbr() *recovery_bbr.Bbr {
    return &test_recovery.congestion.state.bbr;
}

fn phase() recovery_resume.Phase {
    return test_recovery.careful_resume.phase;
}

fn send(first: u64, count: u64, at_ns: u64) !void {
    for (first..first + count) |number| {
        const record: Record = .{ .number = number, .sent_at_ns = at_ns, .sent_len = datagram_len, .ack_eliciting = true, .in_flight = true };
        try test_recovery.on_packet_sent(.application, record, at_ns);
    }
}

fn acknowledge(smallest: u64, largest: u64, at_ns: u64) void {
    const ranges: frame_ack.AckRanges = .{ .largest_acknowledged = largest, .first_range = largest - smallest, .octets = &.{}, .count = 0 };
    _ = recovery_ack.on_ack_received(&test_recovery, .application, .{ .ranges = ranges, .delay_ns = 0, .ecn = null }, .full, at_ns, &acknowledged, &lost);
}

/// One round: `count` packets from `first` sent at `at_ns` and acknowledged a round trip later.
fn round(first: u64, count: u64, at_ns: u64) !u64 {
    try send(first, count, at_ns);
    acknowledge(first, first + count - 1, at_ns + rtt_ns);
    return at_ns + rtt_ns;
}

test "RFC 9959 Appendix C.1: the probing rate is half the saved window over the saved round trip" {
    try testing.expectEqual(probing_rate, recovery_bbr_resume.probing_rate(saved_window_len / 2, rtt_ns));
}

test "RFC 9959 Appendix C.1: a confirmed path sets the flag at the next round, raising pacing and window" {
    start();
    const confirmed_ns = try round(0, initial_packets, start_ns);
    try testing.expectEqual(.unvalidated, phase());
    try testing.expect(bbr().resuming.pending);
    try testing.expect(!bbr().resuming.active);
    _ = try round(initial_packets, initial_packets, confirmed_ns);
    try testing.expect(bbr().resuming.active);
    try testing.expect(bbr().pacing_rate >= probing_rate);
    // C.1: the window covers the probing rate over BBR.min_rtt at Startup's cwnd gain.
    const covered = probing_rate * rtt_ns / 1_000_000_000 * constants.recovery.bbr.default_cwnd_gain / constants.recovery.bbr.gain_denominator;
    try testing.expect(test_recovery.congestion.window >= covered);
}

test "RFC 9959 Appendix C.1: the flag clears two rounds after it is set, and Careful Resume ends" {
    start();
    var at_ns = try round(0, initial_packets, start_ns);
    var next = initial_packets;
    var count = 2 * initial_packets;
    // Bounded by the rounds the flag waits and lasts. Each round doubles, as Startup's does, so
    // BBRv3 stays in Startup.
    for (0..constants.recovery.bbr.resume_rounds + 1) |_| {
        at_ns = try round(next, count, at_ns);
        next += count;
        count *= 2;
    }
    try testing.expectEqual(.startup, bbr().state);
    try testing.expect(!bbr().resuming.active);
    try testing.expectEqual(.off, phase());
    try testing.expect(!test_recovery.careful_resume.retreated);
}

test "RFC 9959 Appendix C.3: congestion with the flag set enters Drain, the Safe Retreat Phase" {
    start();
    var at_ns = try round(0, initial_packets, start_ns);
    at_ns = try round(initial_packets, 2 * initial_packets, at_ns);
    try testing.expect(bbr().resuming.active);
    const first = 3 * initial_packets;
    // Eight initial windows go out. The first is lost, three behind the largest acknowledged
    // (RFC 9002 §6.1.1), and the second half stays in flight, more than one BDP, so Drain lasts.
    try send(first, 8 * initial_packets, at_ns);
    acknowledge(first + 1, first + 4 * initial_packets, at_ns + rtt_ns);
    try testing.expectEqual(.drain, bbr().state);
    try testing.expectEqual(.safe_retreat, phase());
    try testing.expect(test_recovery.careful_resume.retreated);
    // C.3: Drain discards its delivery rates while the flag is set.
    try testing.expect(recovery_bbr_resume.discards_rates(bbr()));
}

test "RFC 9959 Appendix C.3: leaving Drain clears the flag and ends the Safe Retreat Phase" {
    start();
    bbr().resuming = .{ .active = true, .rate = probing_rate };
    recovery_bbr_startup.enter_drain(bbr());
    test_recovery.careful_resume.phase = .safe_retreat;
    // Nothing in flight fits any BDP, so the next ACK frame's CheckDrainDone leaves Drain.
    _ = try round(0, 1, start_ns);
    try testing.expect(bbr().state != .drain);
    try testing.expect(!bbr().resuming.active);
    try testing.expectEqual(.off, phase());
}

test "RFC 9959 Appendix C.1: a BBRv3 connection past Startup does not resume" {
    start();
    recovery_bbr_startup.enter_drain(bbr());
    _ = try round(0, initial_packets, start_ns);
    try testing.expectEqual(.off, phase());
    try testing.expect(!bbr().resuming.pending and !bbr().resuming.active);
}

test "RFC 9959 §3.6: persistent congestion clears the flag" {
    start();
    _ = try round(0, initial_packets, start_ns);
    recovery_resume_phases.on_persistent_congestion(&test_recovery);
    try testing.expectEqual(.off, phase());
    try testing.expect(!bbr().resuming.pending and !bbr().resuming.active);
}

test "RFC 9959 Appendix C.1: the flag waits for a round to start, not for the next ACK frame" {
    start();
    // One packet more than the initial window goes out in the first round.
    try send(0, initial_packets + 1, start_ns);
    acknowledge(0, initial_packets - 1, start_ns + rtt_ns);
    try testing.expectEqual(.unvalidated, phase());
    try testing.expect(bbr().resuming.pending);
    // The last packet of the same round is no round's start, so the flag still waits.
    acknowledge(initial_packets, initial_packets, start_ns + rtt_ns + 1);
    try testing.expect(!bbr().model.round_start);
    try testing.expect(bbr().resuming.pending and !bbr().resuming.active);
}
