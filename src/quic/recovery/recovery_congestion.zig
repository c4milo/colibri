//! The congestion window of RFC 9002 §7, which is NewReno as its Appendix B writes it. Part of
//! design §8 step 10.
//!
//! One number decides how much may be outstanding: the window. It doubles over a round trip
//! while it is below the slow start threshold, grows by about one maximum datagram per round
//! trip above it, and halves when the path signals congestion. §7.3 draws the three states and
//! Appendix B gives them as code.
//!
//! **The octets in flight are not held here.** `recovery_sent.zig` knows what is outstanding
//! because it holds the records, and RFC 9002 Appendix B.2's `bytes_in_flight` is the sum over
//! the three spaces. Keeping a second count here would be a second thing to get wrong, so the
//! caller passes the sum in where a decision needs it.
//!
//! It reads no clock: every instant is a parameter (non-negotiable 3).
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");

/// What §7.8 calls underutilizing the window: the sender had less to send than the window
/// allowed, so an acknowledgment says nothing about what the path can carry and the window
/// SHOULD NOT grow on it. Whether that happened is the caller's to say.
pub const Utilization = enum {
    /// The window bounded what was sent, so the acknowledgment measures the path.
    full,
    /// The application or flow control bounded it, so the acknowledgment does not.
    limited,
};

pub const Congestion = struct {
    /// RFC 9002 Appendix B.2's `max_datagram_size`: the largest payload this endpoint will send
    /// on this path, UDP and IP headers excluded. RFC 9000 §14.1 puts its floor at 1200.
    max_datagram_len: u64,
    /// RFC 9002 Appendix B.2's `congestion_window`: the most that may be in flight.
    window: u64,
    /// RFC 9002 Appendix B.2's `ssthresh`. Below it the window is in slow start and grows by
    /// what was acknowledged; at or above it §7.3.2's congestion avoidance governs. It starts at
    /// the largest a `u64` holds, which is Appendix B.3's `infinite`.
    slow_start_threshold: u64,
    /// RFC 9002 Appendix B.2's `congestion_recovery_start_time`, or null outside a recovery
    /// period. A packet sent after it, once acknowledged, ends the period.
    recovery_started_at_ns: ?u64,
    /// The octets acknowledged in congestion avoidance that have not yet grown the window.
    /// RFC 9002 Appendix B.5 writes the growth as a division and says in the same paragraph that
    /// an integer window should be careful with it and may count octets instead, which is what
    /// this is: its expression truncates to no growth at all once the window passes the maximum
    /// datagram size squared, which is under two megabytes on an ordinary path.
    avoidance_acknowledged_len: u64,
    /// Whether one datagram may still go out past the window. RFC 9002 §7.3.2: "If the congestion
    /// window is reduced immediately, a single packet can be sent prior to reduction", which a
    /// recovery period's start allows and the first datagram past the window spends.
    past_window_allowed: bool,

    pub fn init(congestion: *Congestion, max_datagram_len: u64) void {
        assert(max_datagram_len >= constants.datagram_len_min);
        congestion.* = .{
            .max_datagram_len = max_datagram_len,
            .window = initial_window(max_datagram_len),
            .slow_start_threshold = std.math.maxInt(u64),
            .recovery_started_at_ns = null,
            .avoidance_acknowledged_len = 0,
            .past_window_allowed = false,
        };
    }

    /// RFC 9002 §7.2: the window is recalculated when the path's maximum datagram changes, and
    /// a decrease made to complete the handshake sets the window back to the initial one.
    pub fn set_max_datagram_len(congestion: *Congestion, max_datagram_len: u64) void {
        assert(max_datagram_len >= constants.datagram_len_min);
        // §7.2 names one case: a decrease, which is what completing the handshake can force.
        // It says nothing about an increase, so an increase leaves the window where it is and
        // changes only what the initial and minimum windows would be.
        const smaller = max_datagram_len < congestion.max_datagram_len;
        congestion.max_datagram_len = max_datagram_len;
        if (smaller) congestion.window = initial_window(max_datagram_len);
    }

    /// How many more octets may be put in flight, given how many already are.
    pub fn available_len(congestion: *const Congestion, in_flight_len: u64) u64 {
        return congestion.window -| in_flight_len;
    }

    /// RFC 9002 Appendix B.5's `InCongestionRecovery`: whether a packet sent at `sent_at_ns`
    /// went out during the recovery period this endpoint is in.
    pub fn in_recovery(congestion: *const Congestion, sent_at_ns: u64) bool {
        const started_at_ns = congestion.recovery_started_at_ns orelse return false;
        return sent_at_ns <= started_at_ns;
    }

    /// Takes one acknowledged packet (RFC 9002 Appendix B.5's `OnPacketAcked`).
    pub fn on_ack(congestion: *Congestion, sent_at_ns: u64, sent_len: u64, used: Utilization) void {
        // RFC 9002 §7.8: an acknowledgment of a packet sent while the sender had less to send
        // than the window allowed says nothing about the path, so the window does not grow.
        if (used == .limited) return;
        // RFC 9002 Appendix B.5: the window does not grow inside a recovery period either.
        if (congestion.in_recovery(sent_at_ns)) return;
        if (congestion.window < congestion.slow_start_threshold) {
            // RFC 9002 §7.3.1: in slow start the window grows by what was acknowledged.
            congestion.window +|= sent_len;
            return;
        }
        congestion.grow_in_avoidance(sent_len);
    }

    /// RFC 9002 §7.3.2: in congestion avoidance the window grows by about one maximum datagram
    /// per window of data acknowledged.
    fn grow_in_avoidance(congestion: *Congestion, sent_len: u64) void {
        congestion.avoidance_acknowledged_len +|= sent_len;
        if (congestion.avoidance_acknowledged_len < congestion.window) return;
        congestion.avoidance_acknowledged_len -= congestion.window;
        congestion.window +|= congestion.max_datagram_len;
    }

    /// Starts a recovery period (RFC 9002 Appendix B.6's `OnCongestionEvent`), which is what a
    /// loss and an increase in the peer's ECN-CE count both lead to. `sent_at_ns` is when the
    /// packet that signalled it was sent, and `now_ns` the instant the period starts.
    pub fn on_congestion_event(congestion: *Congestion, sent_at_ns: u64, now_ns: u64) void {
        // RFC 9002 Appendix B.6: a packet sent inside the period this endpoint is already in
        // does not start a second one, which is what keeps one round trip of loss to one halving.
        if (congestion.in_recovery(sent_at_ns)) return;
        congestion.recovery_started_at_ns = now_ns;
        congestion.slow_start_threshold = congestion.window / constants.congestion_loss_reduction_divisor;
        congestion.window = @max(congestion.slow_start_threshold, congestion.minimum_window());
        congestion.avoidance_acknowledged_len = 0;
        // RFC 9002 §7.3.2: "This speeds up loss recovery if the data in the lost packet is
        // retransmitted."
        congestion.past_window_allowed = true;
    }

    /// RFC 9002 §7.6 and Appendix B.8: on persistent congestion the window MUST fall to the
    /// minimum, and the recovery period ends, because every packet over a long span was lost and
    /// what the window held is no longer evidence of anything.
    pub fn on_persistent_congestion(congestion: *Congestion) void {
        congestion.window = congestion.minimum_window();
        congestion.recovery_started_at_ns = null;
        congestion.avoidance_acknowledged_len = 0;
    }

    /// RFC 9002 §7.2: the smallest the window falls to.
    pub fn minimum_window(congestion: *const Congestion) u64 {
        return minimum_window_of(congestion.max_datagram_len);
    }
};

/// RFC 9002 §7.2: ten maximum datagrams, held to the larger of 14,720 octets and two of them.
pub fn initial_window(max_datagram_len: u64) u64 {
    assert(max_datagram_len >= constants.datagram_len_min);
    const ten = max_datagram_len *| constants.congestion_window_initial_datagrams;
    const floor = @max(constants.congestion_window_initial_len_max, minimum_window_of(max_datagram_len));
    return @min(ten, floor);
}

fn minimum_window_of(max_datagram_len: u64) u64 {
    return max_datagram_len *| constants.congestion_window_minimum_datagrams;
}

const testing = std.testing;

/// The controller the tests drive. Test-only.
var test_congestion: Congestion = undefined;
/// The path's maximum datagram in these tests, which is RFC 9000 §14.1's floor, and the window
/// ten of them come to.
const test_datagram_len: u64 = constants.datagram_len_min;
const test_initial_window: u64 = test_datagram_len * constants.congestion_window_initial_datagrams;
const test_minimum_window: u64 = test_datagram_len * constants.congestion_window_minimum_datagrams;
/// Instants the tests order by eye.
const test_early_ns: u64 = 1_000;
const test_late_ns: u64 = 2_000;

test "§7.2: the initial window is ten datagrams, held to a floor and a ceiling" {
    // At RFC 9000 §14.1's smallest datagram, ten of them are below 14,720, so ten is the window.
    try testing.expectEqual(test_initial_window, initial_window(test_datagram_len));
    // A larger datagram reaches the ceiling, and the window stops at it.
    try testing.expectEqual(constants.congestion_window_initial_len_max, initial_window(1_500));
    // A datagram large enough that two of it exceed the ceiling raises the floor instead, which
    // is what keeps the window at two datagrams however large one is.
    const jumbo: u64 = 9_000;
    try testing.expectEqual(2 * jumbo, initial_window(jumbo));
    test_congestion.init(test_datagram_len);
    try testing.expectEqual(test_initial_window, test_congestion.window);
    try testing.expectEqual(test_minimum_window, test_congestion.minimum_window());
    // RFC 9002 Appendix B.3: the threshold starts at `infinite`, so the connection is in slow
    // start, and nothing is outstanding.
    try testing.expectEqual(std.math.maxInt(u64), test_congestion.slow_start_threshold);
    try testing.expectEqual(test_initial_window, test_congestion.available_len(0));
    try testing.expectEqual(0, test_congestion.available_len(test_initial_window + 1));
}

test "§7.3.1: in slow start the window grows by what was acknowledged" {
    test_congestion.init(test_datagram_len);
    test_congestion.on_ack(test_early_ns, test_datagram_len, .full);
    try testing.expectEqual(test_initial_window + test_datagram_len, test_congestion.window);
    // Ten more acknowledgments double it, which is what slow start is.
    for (0..9) |_| test_congestion.on_ack(test_early_ns, test_datagram_len, .full);
    try testing.expectEqual(2 * test_initial_window, test_congestion.window);
}

test "§7.8: an acknowledgment of what the window did not bound does not grow it" {
    test_congestion.init(test_datagram_len);
    test_congestion.on_ack(test_early_ns, test_datagram_len, .limited);
    try testing.expectEqual(test_initial_window, test_congestion.window);
}

test "B.6: a congestion event halves the window and starts a recovery period" {
    test_congestion.init(test_datagram_len);
    test_congestion.on_congestion_event(test_early_ns, test_late_ns);
    try testing.expectEqual(test_initial_window / 2, test_congestion.slow_start_threshold);
    try testing.expectEqual(test_initial_window / 2, test_congestion.window);
    try testing.expectEqual(test_late_ns, test_congestion.recovery_started_at_ns);
    // RFC 9002 §7.3.2: "a single packet can be sent prior to reduction".
    try testing.expect(test_congestion.past_window_allowed);
    test_congestion.past_window_allowed = false;
    // A packet sent at or before the period began is inside it; one sent after is not.
    try testing.expect(test_congestion.in_recovery(test_late_ns));
    try testing.expect(!test_congestion.in_recovery(test_late_ns + 1));
    // A second event over a packet from inside the period does not halve it again, which is
    // what holds one round trip of loss to one reduction.
    test_congestion.on_congestion_event(test_early_ns, test_late_ns + 1);
    try testing.expectEqual(test_initial_window / 2, test_congestion.window);
    try testing.expectEqual(test_late_ns, test_congestion.recovery_started_at_ns);
    // Nor does it allow a second packet past the window: that is the period's, and was spent.
    try testing.expect(!test_congestion.past_window_allowed);
    // An event over a packet sent after the period starts a new one and halves again.
    test_congestion.on_congestion_event(test_late_ns + 1, test_late_ns + 2);
    try testing.expectEqual(test_initial_window / 4, test_congestion.window);
}

test "§7.2: the window never falls below two datagrams" {
    test_congestion.init(test_datagram_len);
    // Halving it repeatedly reaches the minimum and stops there, whatever the threshold does.
    var at_ns: u64 = test_early_ns;
    for (0..16) |_| {
        at_ns += 1;
        test_congestion.on_congestion_event(at_ns, at_ns);
    }
    try testing.expectEqual(test_minimum_window, test_congestion.window);
    try testing.expect(test_congestion.slow_start_threshold < test_minimum_window);
}

test "B.5: the window does not grow inside a recovery period" {
    test_congestion.init(test_datagram_len);
    test_congestion.on_congestion_event(test_early_ns, test_late_ns);
    const held = test_congestion.window;
    // A packet sent before the period began carries no news about the path since.
    test_congestion.on_ack(test_early_ns, test_datagram_len, .full);
    try testing.expectEqual(held, test_congestion.window);
    // One sent after it ends the period's hold. The threshold is now at the window, so §7.3.2's
    // congestion avoidance governs rather than slow start and the window moves only once a
    // window of octets has been acknowledged.
    test_congestion.on_ack(test_late_ns + 1, test_datagram_len, .full);
    try testing.expectEqual(held, test_congestion.window);
    var acknowledged_len: u64 = test_datagram_len;
    // Bounded: one window of datagrams, and the window is a named multiple of the datagram.
    while (acknowledged_len < held) : (acknowledged_len += test_datagram_len) {
        test_congestion.on_ack(test_late_ns + 1, test_datagram_len, .full);
    }
    try testing.expectEqual(held + test_datagram_len, test_congestion.window);
}

test "§7.3.2: congestion avoidance adds a datagram per window acknowledged" {
    test_congestion.init(test_datagram_len);
    // Put the connection in congestion avoidance with a window of five datagrams.
    test_congestion.on_congestion_event(test_early_ns, test_early_ns);
    const window = test_congestion.window;
    try testing.expect(window >= test_congestion.slow_start_threshold);
    // Four datagrams acknowledged is less than that window, so the window has not moved.
    for (0..4) |_| test_congestion.on_ack(test_late_ns, test_datagram_len, .full);
    try testing.expectEqual(window, test_congestion.window);
    // The fifth completes a window and buys exactly one datagram.
    test_congestion.on_ack(test_late_ns, test_datagram_len, .full);
    const grown = window + test_datagram_len;
    try testing.expectEqual(grown, test_congestion.window);
    // The octets that bought it are spent, so the next datagram costs a whole window again —
    // now a wider one. Five more acknowledgments are one short of it.
    for (0..5) |_| test_congestion.on_ack(test_late_ns, test_datagram_len, .full);
    try testing.expectEqual(grown, test_congestion.window);
    test_congestion.on_ack(test_late_ns, test_datagram_len, .full);
    try testing.expectEqual(grown + test_datagram_len, test_congestion.window);
}

test "B.5: a window past the datagram size squared still grows" {
    test_congestion.init(test_datagram_len);
    // RFC 9002 Appendix B.5 writes the growth as `max_datagram_size * sent_bytes / window`,
    // which is zero once the window passes the datagram size squared — under two megabytes
    // here. Counting the octets instead is the alternative B.5 points at in the same paragraph.
    test_congestion.window = test_datagram_len * test_datagram_len * 2;
    test_congestion.slow_start_threshold = 0;
    const window = test_congestion.window;
    var acknowledged_len: u64 = 0;
    // Bounded: one window of datagrams, and the window is a named multiple of the datagram.
    while (acknowledged_len < window) : (acknowledged_len += test_datagram_len) {
        test_congestion.on_ack(test_late_ns, test_datagram_len, .full);
    }
    try testing.expectEqual(window + test_datagram_len, test_congestion.window);
}

test "§7.6: persistent congestion puts the window back to the minimum" {
    test_congestion.init(test_datagram_len);
    test_congestion.on_congestion_event(test_early_ns, test_late_ns);
    test_congestion.on_persistent_congestion();
    try testing.expectEqual(test_minimum_window, test_congestion.window);
    // The recovery period ends with it, so the next acknowledgment grows the window again
    // rather than being held by a period that is no longer meaningful.
    try testing.expectEqual(null, test_congestion.recovery_started_at_ns);
    try testing.expect(!test_congestion.in_recovery(0));
}

test "§7.2: a smaller datagram puts the window back to the initial one" {
    test_congestion.init(test_datagram_len);
    for (0..4) |_| test_congestion.on_ack(test_early_ns, test_datagram_len, .full);
    try testing.expect(test_congestion.window > test_initial_window);
    // §7.2 names the decrease that completing the handshake forces, and the window follows it.
    const larger: u64 = 1_500;
    test_congestion.set_max_datagram_len(larger);
    try testing.expect(test_congestion.window > test_initial_window);
    try testing.expectEqual(larger, test_congestion.max_datagram_len);
    test_congestion.set_max_datagram_len(test_datagram_len);
    try testing.expectEqual(test_initial_window, test_congestion.window);
}
