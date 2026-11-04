//! The tests of Careful Resume's phases under CUBIC and NewReno (`recovery_resume_phases.zig`,
//! RFC 9959 §3.2 to §3.6), driven through `Recovery`'s entry points as a connection drives them.
const std = @import("std");
const constants = @import("../constants.zig");
const frame_ack = @import("../frame/frame_ack.zig");
const recovery = @import("recovery.zig");
const recovery_ack = @import("recovery_ack.zig");
const recovery_congestion = @import("recovery_congestion.zig");
const recovery_resume = @import("recovery_resume.zig");
const recovery_resume_phases = @import("recovery_resume_phases.zig");
const recovery_sent = @import("recovery_sent.zig");

const Record = recovery_sent.Record;
const testing = std.testing;

var test_recovery: recovery.Recovery align(@alignOf(recovery.Recovery)) = undefined;
var acknowledged: [constants.limits.sent_packets_max]Record align(@alignOf(Record)) = undefined;
var lost: [constants.limits.sent_packets_max]Record align(@alignOf(Record)) = undefined;

const datagram_len: u16 = 1_200;
/// The same, in the unit windows are counted in.
const octets: u64 = datagram_len;
const start_ns: u64 = 1_000_000_000;
const rtt_ns: u64 = 100_000_000;
/// The initial window: ten datagrams of 1,200 octets (RFC 9002 §7.2).
const initial_window = recovery_congestion.initial_window(datagram_len);
const initial_packets: u64 = initial_window / datagram_len;
/// A saved window of 400,000 octets, so the jump is 200,000: 166 datagrams of 1,200.
const saved_window_len: u64 = 400_000;
const jump_len: u64 = saved_window_len / constants.protocol.resume_jump_divisor;
const jump_packets: u64 = jump_len / datagram_len;
const saved: recovery_resume.ResumeState = .{ .window_len = saved_window_len, .rtt_ns = rtt_ns, .saved_at_ns = start_ns };

fn start(controller: recovery_congestion.Controller) void {
    test_recovery.init(datagram_len);
    test_recovery.congestion.select(.{ .controller = controller }, start_ns);
    test_recovery.careful_resume.init(saved, .{}, start_ns);
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

/// The initial window sent at `start_ns` and acknowledged one round trip later.
fn confirm() !u64 {
    try send(0, initial_packets, start_ns);
    const at_ns = start_ns + rtt_ns;
    acknowledge(0, initial_packets - 1, at_ns);
    return at_ns;
}

test "RFC 9959 §3.2, §3.3: an acknowledged initial window confirms the path, and the window jumps" {
    inline for (.{ .cubic, .newreno }) |controller| {
        start(controller);
        try testing.expectEqual(.reconnaissance, phase());
        _ = try confirm();
        try testing.expectEqual(.unvalidated, phase());
        try testing.expectEqual(jump_len, test_recovery.congestion.window);
        try testing.expectEqual(0, test_recovery.careful_resume.pipe_len);
    }
}

test "RFC 9959 §3.3: max_jump bounds the jump" {
    start(.cubic);
    test_recovery.careful_resume.bounds.jump_len_max = 5 * initial_window;
    _ = try confirm();
    try testing.expectEqual(5 * initial_window, test_recovery.congestion.window);
}

test "RFC 9959 §3.2: a round trip at or below half the saved one, or past ten of it, ends Careful Resume" {
    start(.cubic);
    test_recovery.careful_resume.saved.rtt_ns = 2 * rtt_ns;
    _ = try confirm();
    try testing.expectEqual(.off, phase());
    start(.cubic);
    test_recovery.careful_resume.saved.rtt_ns = rtt_ns / 11;
    _ = try confirm();
    try testing.expectEqual(.off, phase());
    // Just above half confirms.
    start(.cubic);
    test_recovery.careful_resume.saved.rtt_ns = 2 * rtt_ns - 2;
    _ = try confirm();
    try testing.expectEqual(.unvalidated, phase());
}

test "RFC 9959 §3.2: congestion before the path is confirmed ends Careful Resume" {
    start(.newreno);
    try send(0, initial_packets, start_ns);
    // Packet 0 is three behind the largest acknowledged, so it is lost (RFC 9002 §6.1.1).
    acknowledge(1, initial_packets - 1, start_ns + rtt_ns);
    try testing.expectEqual(.off, phase());
}

test "RFC 9959 §3.3: a full window ends the Unvalidated Phase, and the Validating Phase ends clean" {
    inline for (.{ .cubic, .newreno }) |controller| {
        start(controller);
        const at_ns = try confirm();
        try send(initial_packets, jump_packets, at_ns);
        try testing.expectEqual(.validating, phase());
        try testing.expectEqual(jump_packets * octets, test_recovery.congestion.window);
        const last = initial_packets + jump_packets - 1;
        try testing.expectEqual(last, test_recovery.careful_resume.last_unvalidated.?);
        acknowledge(initial_packets, last, at_ns + rtt_ns);
        try testing.expectEqual(.off, phase());
        try testing.expect(!test_recovery.careful_resume.retreated);
    }
}

test "RFC 9959 §3.3: the first unvalidated packet acknowledged with the jump unused ends at PipeSize" {
    start(.cubic);
    const at_ns = try confirm();
    try send(initial_packets, 2, at_ns);
    acknowledge(initial_packets, initial_packets + 1, at_ns + rtt_ns / 2);
    // Nothing is in flight, below the initial window, so the window is PipeSize held at the IW.
    try testing.expectEqual(.off, phase());
    try testing.expectEqual(initial_window, test_recovery.congestion.window);
}

test "RFC 9959 §3.5: congestion in the Validating Phase retreats to half of PipeSize, and holds" {
    inline for (.{ .cubic, .newreno }) |controller| {
        start(controller);
        const at_ns = try confirm();
        try send(initial_packets, jump_packets, at_ns);
        const last = initial_packets + jump_packets - 1;
        // The first unvalidated packet is lost; the next 90 arrive.
        acknowledge(initial_packets + 1, initial_packets + 90, at_ns + rtt_ns);
        try testing.expectEqual(.safe_retreat, phase());
        try testing.expect(test_recovery.careful_resume.retreated);
        const retreat_window = test_recovery.congestion.window;
        try testing.expectEqual(90 * octets / 2, retreat_window);
        // §3.5: the window does not grow while the phase lasts.
        acknowledge(initial_packets + 91, initial_packets + 120, at_ns + rtt_ns + 1);
        try testing.expectEqual(retreat_window, test_recovery.congestion.window);
        try testing.expectEqual(.safe_retreat, phase());
        // The last unvalidated packet ends it, with ssthresh at PipeSize times the controller's β.
        acknowledge(initial_packets + 121, last, at_ns + rtt_ns + 2);
        try testing.expectEqual(.off, phase());
        const pipe = test_recovery.careful_resume.pipe_len;
        try testing.expectEqual((jump_packets - 1) * octets, pipe);
        const beta_threshold = switch (controller) {
            .cubic => pipe / 10 * 7,
            .newreno => pipe / 2,
            else => unreachable,
        };
        try testing.expect(test_recovery.congestion.slow_start_threshold <= beta_threshold);
    }
}

test "RFC 9959 §3.6: persistent congestion ends Careful Resume" {
    start(.cubic);
    _ = try confirm();
    recovery_resume_phases.on_persistent_congestion(&test_recovery);
    try testing.expectEqual(.off, phase());
}

test "RFC 9959 §3.3: a jump no larger than the window changes nothing" {
    start(.cubic);
    test_recovery.careful_resume.saved.window_len = initial_window;
    _ = try confirm();
    try testing.expectEqual(.off, phase());
    try testing.expect(test_recovery.congestion.window > initial_window);
}

test "RFC 9959 §3.5: a packet sent after the retreat grows no window while the phase lasts" {
    start(.cubic);
    const at_ns = try confirm();
    try send(initial_packets, jump_packets, at_ns);
    const last = initial_packets + jump_packets - 1;
    acknowledge(initial_packets + 1, initial_packets + 90, at_ns + rtt_ns);
    try testing.expectEqual(.safe_retreat, phase());
    const retreat_window = test_recovery.congestion.window;
    // Two packets sent after the recovery period started, which RFC 9002 would let grow the
    // window, are acknowledged in the frame that ends the phase.
    const later_ns = at_ns + rtt_ns + 1;
    try send(last + 1, 2, later_ns);
    acknowledge(last + 1, last + 2, later_ns + rtt_ns);
    try testing.expectEqual(.off, phase());
    try testing.expectEqual(retreat_window, test_recovery.congestion.window);
}
