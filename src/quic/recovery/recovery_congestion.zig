//! The congestion window of RFC 9002 §7, with CUBIC (RFC 9438) in place of NewReno's congestion
//! avoidance and decrease (decision 133). Part of design §8 steps 10 and 27.
//!
//! One number decides how much may be outstanding: the window. It doubles over a round trip
//! while it is below the slow start threshold, as RFC 9002 §7.3.1 has it. Above it, RFC 9438 §4.2
//! grows it along a cubic curve that aims back at W_max, the window before the last congestion
//! event, and §4.3 keeps it at least where Reno would be. A congestion event scales it to 0.7
//! (§4.6). The recovery period, persistent congestion and the minimum window are RFC 9002's, and
//! `recovery_cubic.zig` holds RFC 9438's arithmetic.
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
const recovery_cubic = @import("recovery_cubic.zig");

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
    /// on this path, UDP and IP headers excluded. RFC 9000 §14.1 puts its floor at 1200. It is
    /// RFC 9438's segment (§4.1).
    max_datagram_len: u64,
    /// RFC 9002 Appendix B.2's `congestion_window`: the most that may be in flight.
    window: u64,
    /// RFC 9002 Appendix B.2's `ssthresh`. Below it the window is in slow start and grows by
    /// what was acknowledged; at or above it CUBIC's congestion avoidance governs. It starts at
    /// the largest a `u64` holds, which is Appendix B.3's `infinite`.
    slow_start_threshold: u64,
    /// RFC 9002 Appendix B.2's `congestion_recovery_start_time`, or null outside a recovery
    /// period. A packet sent after it, once acknowledged, ends the period.
    recovery_started_at_ns: ?u64,
    /// Whether one datagram may still go out past the window. RFC 9002 §7.3.2: "If the congestion
    /// window is reduced immediately, a single packet can be sent prior to reduction", which a
    /// recovery period's start allows and the first datagram past the window spends.
    past_window_allowed: bool,
    /// RFC 9438 §4.1.2's W_max, the window just before the last congestion event, lowered by fast
    /// convergence (§4.7). 0 before any, and after persistent congestion (§4.8).
    w_max: u64,
    /// §4.1.2's cwnd_prior: the window just before the last congestion event.
    prior_len: u64,
    /// §4.1.2's t_epoch, when the current congestion avoidance stage started, moved later by each
    /// span the sender was limited (§4.2), or null before the stage's first acknowledgment.
    epoch_ns: ?u64,
    /// The curve of the current stage: W_max and K (§4.2).
    curve: recovery_cubic.Curve,
    /// §4.3's W_est, the window Reno would have, in octets.
    estimate_len: u64,
    /// The octets of §4.4's and §4.5's per-acknowledgment increase that have not yet made a whole
    /// octet of window: the increase is `(target − window) × acknowledged / window`.
    growth_numerator: u64,
    /// When the acknowledgments started to say the sender was limited, which §4.2 leaves out of
    /// the stage's time, or null while they say it was not.
    limited_since_ns: ?u64,

    pub fn init(congestion: *Congestion, max_datagram_len: u64) void {
        assert(max_datagram_len >= constants.datagram_len_min);
        congestion.* = .{
            .max_datagram_len = max_datagram_len,
            .window = initial_window(max_datagram_len),
            .slow_start_threshold = std.math.maxInt(u64),
            .recovery_started_at_ns = null,
            .past_window_allowed = false,
            .w_max = 0,
            .prior_len = 0,
            .epoch_ns = null,
            .curve = .{ .w_max = 0, .k_us = 0, .datagram_len = max_datagram_len },
            .estimate_len = 0,
            .growth_numerator = 0,
            .limited_since_ns = null,
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
        // RFC 9438 counts in segments, so a new segment starts the stage again.
        congestion.epoch_ns = null;
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

    /// Takes the acknowledgment of `sent_len` octets, the largest of them sent at `sent_at_ns`
    /// (RFC 9002 Appendix B.5's `OnPacketAcked`), at `now_ns`, with the connection's smoothed
    /// round trip, which RFC 9438 §4.2 reads.
    pub fn on_ack(congestion: *Congestion, sent_at_ns: u64, sent_len: u64, used: Utilization, now_ns: u64, smoothed_rtt_ns: u64) void {
        // RFC 9002 §7.8: an acknowledgment of a packet sent while the sender had less to send
        // than the window allowed says nothing about the path, so the window does not grow.
        // RFC 9438 §4.2: "The elapsed time t ... MUST NOT include periods during which cwnd has
        // not been updated due to application-limited behavior".
        if (used == .limited) {
            if (congestion.limited_since_ns == null) congestion.limited_since_ns = now_ns;
            return;
        }
        congestion.end_limited(now_ns);
        // RFC 9002 Appendix B.5: the window does not grow inside a recovery period either.
        if (congestion.in_recovery(sent_at_ns)) return;
        if (congestion.window < congestion.slow_start_threshold) {
            // RFC 9002 §7.3.1: in slow start the window grows by what was acknowledged.
            congestion.window +|= sent_len;
            return;
        }
        congestion.grow_in_avoidance(sent_len, now_ns, smoothed_rtt_ns);
    }

    /// Moves the stage's start later by the span the sender was limited, which §4.2 leaves out.
    fn end_limited(congestion: *Congestion, now_ns: u64) void {
        const since_ns = congestion.limited_since_ns orelse return;
        congestion.limited_since_ns = null;
        assert(now_ns >= since_ns);
        if (congestion.epoch_ns) |epoch_ns| congestion.epoch_ns = epoch_ns +| (now_ns - since_ns);
    }

    /// RFC 9438 §4.2 to §4.5: the larger of the cubic curve's target and the Reno-friendly
    /// estimate.
    fn grow_in_avoidance(congestion: *Congestion, sent_len: u64, now_ns: u64, smoothed_rtt_ns: u64) void {
        const epoch_ns = congestion.epoch_ns orelse congestion.start_epoch(now_ns);
        const t_us = (now_ns -| epoch_ns) / constants.nanoseconds_per_microsecond;
        const rtt_us = smoothed_rtt_ns / constants.nanoseconds_per_microsecond;
        const window = congestion.window;
        // §4.3, Figure 4: W_est grows by α per window acknowledged, and by 1 once it reaches
        // cwnd_prior.
        congestion.estimate_len +|= recovery_cubic.estimate_gain(sent_len, window, congestion.max_datagram_len, congestion.estimate_len >= congestion.prior_len);
        // §4.3: "If [W_cubic(t) is less than W_est], CUBIC is in the Reno-friendly region and
        // cwnd SHOULD be set to W_est".
        if (congestion.curve.window_at(t_us) < congestion.estimate_len) {
            congestion.window = @max(window, congestion.estimate_len);
            return;
        }
        // §4.4, §4.5: in the concave and convex regions the window grows by
        // (target − cwnd) / cwnd per segment acknowledged.
        const target = congestion.curve.target(t_us, rtt_us, window);
        congestion.growth_numerator +|= (target - window) *| sent_len;
        congestion.window += congestion.growth_numerator / window;
        congestion.growth_numerator %= window;
    }

    /// Starts a congestion avoidance stage at `now_ns` (§4.1.2's t_epoch, cwnd_epoch and K).
    fn start_epoch(congestion: *Congestion, now_ns: u64) u64 {
        congestion.curve = .of(congestion.w_max, congestion.window, congestion.max_datagram_len);
        congestion.w_max = congestion.curve.w_max;
        congestion.estimate_len = congestion.window;
        congestion.growth_numerator = 0;
        congestion.epoch_ns = now_ns;
        return now_ns;
    }

    /// Starts a recovery period (RFC 9002 Appendix B.6's `OnCongestionEvent`), which is what a
    /// loss and an increase in the peer's ECN-CE count both lead to. `sent_at_ns` is when the
    /// packet that signalled it was sent, and `now_ns` the instant the period starts.
    pub fn on_congestion_event(congestion: *Congestion, sent_at_ns: u64, now_ns: u64) void {
        // RFC 9002 Appendix B.6: a packet sent inside the period this endpoint is already in
        // does not start a second one, which is what keeps one round trip of loss to one decrease.
        if (congestion.in_recovery(sent_at_ns)) return;
        congestion.recovery_started_at_ns = now_ns;
        // RFC 9438 §4.7, §4.6: W_max and cwnd_prior first, then the decrease of Figure 5, which
        // RFC 9002 §7.2's minimum holds up.
        congestion.w_max = recovery_cubic.w_max_after(congestion.window, congestion.w_max);
        congestion.prior_len = congestion.window;
        congestion.slow_start_threshold = @max(recovery_cubic.reduced(congestion.window), congestion.minimum_window());
        congestion.window = congestion.slow_start_threshold;
        congestion.epoch_ns = null;
        // RFC 9002 §7.3.2: "This speeds up loss recovery if the data in the lost packet is
        // retransmitted."
        congestion.past_window_allowed = true;
    }

    /// RFC 9002 §7.6 and Appendix B.8: on persistent congestion the window MUST fall to the
    /// minimum, and the recovery period ends, because every packet over a long span was lost and
    /// what the window held is no longer evidence of anything. RFC 9438 §4.8 then starts the
    /// next stage with K = 0 and W_max at the window it starts from.
    pub fn on_persistent_congestion(congestion: *Congestion) void {
        congestion.window = congestion.minimum_window();
        congestion.recovery_started_at_ns = null;
        congestion.w_max = 0;
        congestion.epoch_ns = null;
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
threadlocal var test_congestion: Congestion align(@alignOf(Congestion)) = undefined;
/// The path's maximum datagram in these tests, which is RFC 9000 §14.1's floor, and the window
/// ten of them come to.
const test_datagram_len: u64 = constants.datagram_len_min;
const test_initial_window: u64 = test_datagram_len * constants.congestion_window_initial_datagrams;
const test_minimum_window: u64 = test_datagram_len * constants.congestion_window_minimum_datagrams;
/// Instants the tests order by eye, and the round trip they pass.
const test_early_ns: u64 = 1_000;
const test_late_ns: u64 = 2_000;
const test_rtt_ns: u64 = 50_000_000;
/// Round trips a test's sender stays limited. Test-only.
const test_limited_round_trips: u64 = 20;

/// Acknowledges one full datagram sent at `sent_at_ns`, at `now_ns`. Test-only.
fn acknowledge(sent_at_ns: u64, now_ns: u64) void {
    test_congestion.on_ack(sent_at_ns, test_datagram_len, .full, now_ns, test_rtt_ns);
}

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
    acknowledge(test_early_ns, test_late_ns);
    try testing.expectEqual(test_initial_window + test_datagram_len, test_congestion.window);
    // Ten more acknowledgments double it, which is what slow start is.
    for (0..9) |_| acknowledge(test_early_ns, test_late_ns);
    try testing.expectEqual(2 * test_initial_window, test_congestion.window);
}

test "§7.8: an acknowledgment of what the window did not bound does not grow it" {
    test_congestion.init(test_datagram_len);
    test_congestion.on_ack(test_early_ns, test_datagram_len, .limited, test_late_ns, test_rtt_ns);
    try testing.expectEqual(test_initial_window, test_congestion.window);
}

test "RFC 9438 §4.6: a congestion event scales the window to 0.7 and starts a recovery period" {
    test_congestion.init(test_datagram_len);
    test_congestion.on_congestion_event(test_early_ns, test_late_ns);
    const reduced = test_initial_window / 10 * 7;
    try testing.expectEqual(reduced, test_congestion.slow_start_threshold);
    try testing.expectEqual(reduced, test_congestion.window);
    try testing.expectEqual(test_initial_window, test_congestion.w_max);
    try testing.expectEqual(test_initial_window, test_congestion.prior_len);
    try testing.expectEqual(test_late_ns, test_congestion.recovery_started_at_ns);
    // RFC 9002 §7.3.2: "a single packet can be sent prior to reduction".
    try testing.expect(test_congestion.past_window_allowed);
    test_congestion.past_window_allowed = false;
    // A packet sent at or before the period began is inside it; one sent after is not.
    try testing.expect(test_congestion.in_recovery(test_late_ns));
    try testing.expect(!test_congestion.in_recovery(test_late_ns + 1));
    // A second event over a packet from inside the period does not reduce it again.
    test_congestion.on_congestion_event(test_early_ns, test_late_ns + 1);
    try testing.expectEqual(reduced, test_congestion.window);
    try testing.expect(!test_congestion.past_window_allowed);
    // An event over a packet sent after the period starts a new one. The window fell short of
    // W_max, so fast convergence (§4.7) lowers W_max to (1 + β) / 2 of the window.
    test_congestion.on_congestion_event(test_late_ns + 1, test_late_ns + 2);
    try testing.expectEqual(reduced / 10 * 7, test_congestion.window);
    try testing.expectEqual(reduced / 20 * 17, test_congestion.w_max);
}

test "§7.2, RFC 9438 Figure 5: the window and the threshold never fall below two datagrams" {
    test_congestion.init(test_datagram_len);
    var at_ns: u64 = test_early_ns;
    for (0..16) |_| {
        at_ns += 1;
        test_congestion.on_congestion_event(at_ns, at_ns);
    }
    try testing.expectEqual(test_minimum_window, test_congestion.window);
    try testing.expectEqual(test_minimum_window, test_congestion.slow_start_threshold);
}

test "B.5: the window does not grow inside a recovery period" {
    test_congestion.init(test_datagram_len);
    test_congestion.on_congestion_event(test_early_ns, test_late_ns);
    const held = test_congestion.window;
    // A packet sent before the period began carries no news about the path since.
    acknowledge(test_early_ns, test_late_ns + 1);
    try testing.expectEqual(held, test_congestion.window);
    try testing.expectEqual(null, test_congestion.epoch_ns);
}

test "RFC 9438 §4.3: right after a decrease the window follows the Reno-friendly estimate" {
    test_congestion.init(test_datagram_len);
    test_congestion.on_congestion_event(test_early_ns, test_late_ns);
    const held = test_congestion.window;
    // The curve starts back at the window and rises slowly, so W_est leads: a window of octets
    // acknowledged adds α = 9/17 of a datagram, where NewReno would add one.
    var acknowledged_len: u64 = 0;
    // Bounded: one window of datagrams.
    while (acknowledged_len < held) : (acknowledged_len += test_datagram_len) acknowledge(test_late_ns + 1, test_late_ns + 1);
    // α = 9/17 of a datagram, about 630 octets here; the curve alone adds under half a datagram.
    try testing.expect(test_congestion.window >= held + test_datagram_len / 2);
    try testing.expect(test_congestion.window < held + test_datagram_len);
    try testing.expectEqual(test_late_ns + 1, test_congestion.epoch_ns);
}

test "RFC 9438 §4.4, §4.5: the window climbs back to W_max by K, and probes past it" {
    test_congestion.init(test_datagram_len);
    test_congestion.on_congestion_event(test_early_ns, test_late_ns);
    const w_max = test_congestion.w_max;
    const start_ns = test_late_ns + 1;
    acknowledge(start_ns, start_ns);
    const k_ns = test_congestion.curve.k_us * constants.nanoseconds_per_microsecond;
    // Bounded: acknowledgments one round trip apart, up to K and a little past it.
    var now_ns = start_ns;
    while (now_ns < start_ns + k_ns + 2 * test_rtt_ns) : (now_ns += test_rtt_ns) {
        for (0..test_congestion.window / test_datagram_len) |_| acknowledge(start_ns + 1, now_ns);
    }
    try testing.expect(test_congestion.window >= w_max);
}

test "RFC 9438 §4.2: time the sender was limited does not count toward the curve" {
    test_congestion.init(test_datagram_len);
    test_congestion.on_congestion_event(test_early_ns, test_late_ns);
    acknowledge(test_late_ns + 1, test_late_ns + 1);
    const epoch_ns = test_congestion.epoch_ns.?;
    const limited_ns: u64 = test_rtt_ns * test_limited_round_trips;
    test_congestion.on_ack(test_late_ns + 1, test_datagram_len, .limited, epoch_ns + 1, test_rtt_ns);
    acknowledge(test_late_ns + 1, epoch_ns + 1 + limited_ns);
    try testing.expectEqual(epoch_ns + limited_ns, test_congestion.epoch_ns.?);
}

test "§7.6, RFC 9438 §4.8: persistent congestion puts the window back to the minimum, with K = 0" {
    test_congestion.init(test_datagram_len);
    test_congestion.on_congestion_event(test_early_ns, test_late_ns);
    test_congestion.on_persistent_congestion();
    try testing.expectEqual(test_minimum_window, test_congestion.window);
    // The recovery period ends with it, so the next acknowledgment grows the window again
    // rather than being held by a period that is no longer meaningful.
    try testing.expectEqual(null, test_congestion.recovery_started_at_ns);
    try testing.expect(!test_congestion.in_recovery(0));
    // Slow start runs back up to the threshold; the stage after it starts with K = 0.
    test_congestion.window = test_congestion.slow_start_threshold;
    acknowledge(test_late_ns + 1, test_late_ns + 1);
    try testing.expectEqual(0, test_congestion.curve.k_us);
}

test "§7.2: a smaller datagram puts the window back to the initial one" {
    test_congestion.init(test_datagram_len);
    for (0..4) |_| acknowledge(test_early_ns, test_late_ns);
    try testing.expect(test_congestion.window > test_initial_window);
    // §7.2 names the decrease that completing the handshake forces, and the window follows it.
    const larger: u64 = 1_500;
    test_congestion.set_max_datagram_len(larger);
    try testing.expect(test_congestion.window > test_initial_window);
    try testing.expectEqual(larger, test_congestion.max_datagram_len);
    test_congestion.set_max_datagram_len(test_datagram_len);
    try testing.expectEqual(test_initial_window, test_congestion.window);
}
