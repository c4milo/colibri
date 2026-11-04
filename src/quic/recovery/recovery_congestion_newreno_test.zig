//! The tests of NewReno (`recovery_congestion_newreno.zig`, RFC 9002 §7.3 and Appendix B),
//! through the shared state of `recovery_congestion.zig`, as a connection drives it.
const std = @import("std");
const constants = @import("../constants.zig");
const recovery_congestion = @import("recovery_congestion.zig");

const Congestion = recovery_congestion.Congestion;
const testing = std.testing;

/// The controller the tests drive. Test-only.
threadlocal var test_congestion: Congestion align(@alignOf(Congestion)) = undefined;
/// RFC 9000 §14.1's floor, the initial window ten of them come to, and the minimum window.
const datagram_len: u64 = constants.protocol.datagram_len_min;
const initial_window: u64 = datagram_len * constants.recovery.congestion_window_initial_datagrams;
const minimum_window: u64 = datagram_len * constants.recovery.congestion_window_minimum_datagrams;
/// Instants the tests order by eye, and the round trip they pass, which NewReno does not read.
const early_ns: u64 = 1_000;
const late_ns: u64 = 2_000;
const rtt_ns: u64 = 50_000_000;

fn start() void {
    test_congestion.init(datagram_len);
    test_congestion.select(.{ .controller = .newreno }, early_ns);
}

fn acknowledge(sent_at_ns: u64, sent_len: u64, used: recovery_congestion.Utilization) void {
    test_congestion.on_ack(sent_at_ns, sent_len, used, late_ns, rtt_ns, null);
}

test "RFC 9002 §7.3.1: in slow start the window grows by what was acknowledged" {
    start();
    try testing.expectEqual(initial_window, test_congestion.window);
    acknowledge(early_ns, datagram_len, .full);
    try testing.expectEqual(initial_window + datagram_len, test_congestion.window);
}

test "RFC 9002 §7.8 and Appendix B.5: a limited sender's acknowledgment grows nothing" {
    start();
    acknowledge(early_ns, datagram_len, .limited);
    try testing.expectEqual(initial_window, test_congestion.window);
}

test "RFC 9002 Appendix B.6: a congestion event halves the window, and holds it at the minimum" {
    start();
    try testing.expect(test_congestion.on_congestion_event(early_ns, late_ns));
    try testing.expectEqual(initial_window / 2, test_congestion.slow_start_threshold);
    try testing.expectEqual(initial_window / 2, test_congestion.window);
    try testing.expect(test_congestion.past_window_allowed);
    // Appendix B.6: a packet sent inside the period starts no second one.
    try testing.expect(!test_congestion.on_congestion_event(early_ns, late_ns + 1));
    try testing.expectEqual(initial_window / 2, test_congestion.window);
    // Each new period halves again, down to kMinimumWindow and no further.
    for (0..8) |round| {
        const sent_at_ns = late_ns + 2 + 2 * round;
        _ = test_congestion.on_congestion_event(sent_at_ns, sent_at_ns + 1);
    }
    try testing.expectEqual(minimum_window, test_congestion.window);
    try testing.expect(test_congestion.slow_start_threshold < minimum_window);
}

test "RFC 9002 Appendix B.5: the window does not grow on a packet sent inside the recovery period" {
    start();
    _ = test_congestion.on_congestion_event(early_ns, late_ns);
    const reduced = test_congestion.window;
    // Sent before the period started at `late_ns`, so it is in the period.
    test_congestion.on_ack(late_ns, datagram_len, .full, late_ns + 10, rtt_ns, null);
    try testing.expectEqual(reduced, test_congestion.window);
    // Sent after it, so it ends the period and grows the window.
    test_congestion.on_ack(late_ns + 1, datagram_len, .full, late_ns + 10, rtt_ns, null);
    try testing.expect(test_congestion.window > reduced);
}

test "RFC 9002 §7.3.3: a window of acknowledgments adds at most one datagram" {
    start();
    _ = test_congestion.on_congestion_event(early_ns, late_ns);
    const window = test_congestion.window;
    try testing.expectEqual(window, test_congestion.slow_start_threshold);
    // Appendix B.5: one datagram acknowledged adds `max_datagram_size × sent_bytes / window`.
    test_congestion.on_ack(late_ns + 1, datagram_len, .full, late_ns + 10, rtt_ns, null);
    try testing.expectEqual(window + datagram_len * datagram_len / window, test_congestion.window);
    // The rest of the window adds less than the datagram, because each increase widens it.
    // Bounded by the datagrams of one window. Each is sent after the period started.
    for (1..window / datagram_len) |_| {
        test_congestion.on_ack(late_ns + 1, datagram_len, .full, late_ns + 10, rtt_ns, null);
    }
    try testing.expect(test_congestion.window <= window + datagram_len);
    try testing.expect(test_congestion.window > window + datagram_len * 9 / 10);
}

test "RFC 9002 §7.3.3: the carry adds what acknowledgments too small to add an octet sum to" {
    start();
    _ = test_congestion.on_congestion_event(early_ns, late_ns);
    const window = test_congestion.window;
    // One octet acknowledged adds `datagram_len / window` of an octet, below one.
    const per_octet = window / datagram_len;
    for (0..per_octet - 1) |_| test_congestion.on_ack(late_ns + 1, 1, .full, late_ns + 10, rtt_ns, null);
    try testing.expectEqual(window, test_congestion.window);
    test_congestion.on_ack(late_ns + 1, 1, .full, late_ns + 10, rtt_ns, null);
    try testing.expectEqual(window + 1, test_congestion.window);
}

test "RFC 9002 §7.6.2: persistent congestion leaves the minimum window and no recovery period" {
    start();
    _ = test_congestion.on_congestion_event(early_ns, late_ns);
    test_congestion.on_persistent_congestion();
    try testing.expectEqual(minimum_window, test_congestion.window);
    try testing.expectEqual(null, test_congestion.recovery_started_at_ns);
    try testing.expectEqual(0, test_congestion.state.newreno.growth_numerator);
}
