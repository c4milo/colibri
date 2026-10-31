//! The congestion window of RFC 9002 §7, under CUBIC (RFC 9438, decision 133) or BBRv3
//! (draft-ietf-ccwg-bbr-06, decision 134). Part of design §8 steps 10, 27 and 29b.4.
//!
//! One number decides how much may be outstanding: the window. RFC 9002 gives the parts both
//! controllers share: the initial and minimum windows, the recovery period and persistent
//! congestion. `recovery_congestion_cubic.zig` grows the window along RFC 9438's curve, and
//! `recovery_bbr/` sets it from its model of the path. A connection holds the state of one of
//! the two, which `Choice` names (decision 136, the owner's ruling of 2026-10-31).
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
const recovery_congestion_cubic = @import("recovery_congestion_cubic.zig");
const recovery_bbr = @import("recovery_bbr/recovery_bbr.zig");

/// What §7.8 calls underutilizing the window: the sender had less to send than the window
/// allowed, so an acknowledgment says nothing about what the path can carry and the window
/// SHOULD NOT grow on it. Whether that happened is the caller's to say.
pub const Utilization = enum {
    /// The window bounded what was sent, so the acknowledgment measures the path.
    full,
    /// The application or flow control bounded it, so the acknowledgment does not.
    limited,
};

/// The congestion controller a connection runs: `quic.CongestionController` (decision 136).
pub const Controller = enum {
    /// RFC 9438, with HyStart++ in its first slow start. The default.
    cubic,
    /// BBRv3, from draft-ietf-ccwg-bbr-06 (decision 134).
    bbr,
};

/// What a connection chose: the controller, and the value BBRv3 draws its probe waits from
/// (decision 136), which CUBIC does not read.
pub const Choice = struct {
    controller: Controller = .cubic,
    bandwidth_probe_waits: u64 = 0,
};

/// The state of the controller a connection runs.
pub const State = union(Controller) {
    cubic: recovery_congestion_cubic.Cubic,
    bbr: recovery_bbr.Bbr,
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
    /// What the connection chose, which a reset of the path keeps (RFC 9000 §9.4).
    choice: Choice,
    /// The latest instant the controller was given, from which BBRv3 starts again after a reset
    /// of the path: RFC 9000 §9.4's reset comes with no instant of its own.
    latest_ns: u64,
    state: State,

    /// RFC 9002 Appendix B.3's initial values, under CUBIC.
    pub fn init(congestion: *Congestion, max_datagram_len: u64) void {
        congestion.start(max_datagram_len, .{}, 0);
    }

    /// The controller the connection chose (decision 136), at `now_ns`, which BBRv3's clocks
    /// start from.
    pub fn select(congestion: *Congestion, choice: Choice, now_ns: u64) void {
        congestion.start(congestion.max_datagram_len, choice, now_ns);
    }

    /// RFC 9000 §9.4: the controller starts again at its initial values, under the same choice.
    pub fn reset(congestion: *Congestion) void {
        congestion.start(congestion.max_datagram_len, congestion.choice, congestion.latest_ns);
    }

    fn start(congestion: *Congestion, max_datagram_len: u64, choice: Choice, now_ns: u64) void {
        assert(max_datagram_len >= constants.protocol.datagram_len_min);
        congestion.* = .{
            .max_datagram_len = max_datagram_len,
            .window = initial_window(max_datagram_len),
            .slow_start_threshold = std.math.maxInt(u64),
            .recovery_started_at_ns = null,
            .past_window_allowed = false,
            .choice = choice,
            .latest_ns = now_ns,
            .state = undefined,
        };
        switch (choice.controller) {
            .cubic => {
                congestion.state = .{ .cubic = undefined };
                congestion.state.cubic.init(max_datagram_len);
            },
            .bbr => {
                congestion.state = .{ .bbr = undefined };
                congestion.state.bbr.init(now_ns, max_datagram_len, congestion.window, choice.bandwidth_probe_waits);
            },
        }
    }

    /// RFC 9002 §7.2: the window is recalculated when the path's maximum datagram changes, and
    /// a decrease made to complete the handshake sets the window back to the initial one.
    pub fn set_max_datagram_len(congestion: *Congestion, max_datagram_len: u64) void {
        assert(max_datagram_len >= constants.protocol.datagram_len_min);
        // §7.2 names one case: a decrease, which is what completing the handshake can force.
        // It says nothing about an increase, so an increase leaves the window where it is and
        // changes only what the initial and minimum windows would be.
        const smaller = max_datagram_len < congestion.max_datagram_len;
        congestion.max_datagram_len = max_datagram_len;
        switch (congestion.state) {
            // RFC 9438 counts in segments, so a new segment starts the stage again.
            .cubic => |*cubic| cubic.epoch_ns = null,
            .bbr => {},
        }
        if (smaller) congestion.set_window(initial_window(max_datagram_len));
    }

    /// Sets the window, which BBRv3 keeps a copy of as `C.cwnd`.
    pub fn set_window(congestion: *Congestion, window: u64) void {
        congestion.window = window;
        switch (congestion.state) {
            .cubic => {},
            .bbr => |*bbr| bbr.window_len = window,
        }
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

    /// RFC 9002 Appendix B.5's `OnPacketAcked` under CUBIC. BBRv3 takes its acknowledgments
    /// through `recovery_congestion_bbr.zig`.
    pub fn on_ack(congestion: *Congestion, sent_at_ns: u64, sent_len: u64, used: Utilization, now_ns: u64, smoothed_rtt_ns: u64, latest_rtt_ns: ?u64) void {
        congestion.latest_ns = @max(congestion.latest_ns, now_ns);
        switch (congestion.state) {
            .cubic => |*cubic| recovery_congestion_cubic.on_ack(congestion, cubic, sent_at_ns, sent_len, used, now_ns, smoothed_rtt_ns, latest_rtt_ns),
            .bbr => unreachable,
        }
    }

    /// Starts a recovery period (RFC 9002 Appendix B.6's `OnCongestionEvent`), which is what a
    /// loss and an increase in the peer's ECN-CE count both lead to. `sent_at_ns` is when the
    /// packet that signalled it was sent, and `now_ns` the instant the period starts. True when
    /// it started a new period.
    pub fn on_congestion_event(congestion: *Congestion, sent_at_ns: u64, now_ns: u64) bool {
        // RFC 9002 Appendix B.6: a packet sent inside the period this endpoint is already in
        // does not start a second one, which is what keeps one round trip of loss to one decrease.
        if (congestion.in_recovery(sent_at_ns)) return false;
        congestion.recovery_started_at_ns = now_ns;
        congestion.latest_ns = @max(congestion.latest_ns, now_ns);
        switch (congestion.state) {
            .cubic => |*cubic| recovery_congestion_cubic.on_congestion_event(congestion, cubic),
            // BBRv3 does not cut the window on loss: its model takes each lost packet, and the
            // period starts its `OnEnterFastRecovery` (`recovery_congestion_bbr.zig`).
            .bbr => {},
        }
        return true;
    }

    /// RFC 9002 §7.6 and Appendix B.8: on persistent congestion the window MUST fall to the
    /// minimum, and the recovery period ends, because every packet over a long span was lost and
    /// what the window held is no longer evidence of anything. RFC 9438 §4.8 then starts the
    /// next stage with K = 0 and W_max at the window it starts from. BBRv3 saves its state
    /// before, as §5.6.4.4's `OnEnterRTO` does (the owner's ruling of 2026-10-31).
    pub fn on_persistent_congestion(congestion: *Congestion) void {
        switch (congestion.state) {
            .cubic => |*cubic| recovery_congestion_cubic.on_persistent_congestion(cubic),
            .bbr => {},
        }
        congestion.set_window(congestion.minimum_window());
        congestion.recovery_started_at_ns = null;
    }

    /// RFC 9002 §7.2: the smallest the window falls to.
    pub fn minimum_window(congestion: *const Congestion) u64 {
        return minimum_window_of(congestion.max_datagram_len);
    }
};

/// RFC 9002 §7.2: ten maximum datagrams, held to the larger of 14,720 octets and two of them.
pub fn initial_window(max_datagram_len: u64) u64 {
    assert(max_datagram_len >= constants.protocol.datagram_len_min);
    const ten = max_datagram_len *| constants.recovery.congestion_window_initial_datagrams;
    const floor = @max(constants.recovery.congestion_window_initial_len_max, minimum_window_of(max_datagram_len));
    return @min(ten, floor);
}

fn minimum_window_of(max_datagram_len: u64) u64 {
    return max_datagram_len *| constants.recovery.congestion_window_minimum_datagrams;
}

const testing = std.testing;

/// The controller the tests drive. Test-only.
threadlocal var test_congestion: Congestion align(@alignOf(Congestion)) = undefined;
/// The path's maximum datagram in these tests, which is RFC 9000 §14.1's floor, and the window
/// ten of them come to.
const test_datagram_len: u64 = constants.protocol.datagram_len_min;
const test_initial_window: u64 = test_datagram_len * constants.recovery.congestion_window_initial_datagrams;
const test_minimum_window: u64 = test_datagram_len * constants.recovery.congestion_window_minimum_datagrams;
/// Instants the tests order by eye, and the round trip they pass.
const test_early_ns: u64 = 1_000;
const test_late_ns: u64 = 2_000;
const test_rtt_ns: u64 = 50_000_000;
/// Round trips a test's sender stays limited. Test-only.
const test_limited_round_trips: u64 = 20;

/// Acknowledges one full datagram sent at `sent_at_ns`, at `now_ns`. Test-only.
fn acknowledge(sent_at_ns: u64, now_ns: u64) void {
    test_congestion.on_ack(sent_at_ns, test_datagram_len, .full, now_ns, test_rtt_ns, null);
}

test "§7.2: the initial window is ten datagrams, held to a floor and a ceiling" {
    // At RFC 9000 §14.1's smallest datagram, ten of them are below 14,720, so ten is the window.
    try testing.expectEqual(test_initial_window, initial_window(test_datagram_len));
    // A larger datagram reaches the ceiling, and the window stops at it.
    try testing.expectEqual(constants.recovery.congestion_window_initial_len_max, initial_window(1_500));
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
    test_congestion.on_ack(test_early_ns, test_datagram_len, .limited, test_late_ns, test_rtt_ns, null);
    try testing.expectEqual(test_initial_window, test_congestion.window);
}

test "RFC 9438 §4.6: a congestion event scales the window to 0.7 and starts a recovery period" {
    test_congestion.init(test_datagram_len);
    _ = test_congestion.on_congestion_event(test_early_ns, test_late_ns);
    const reduced = test_initial_window / 10 * 7;
    try testing.expectEqual(reduced, test_congestion.slow_start_threshold);
    try testing.expectEqual(reduced, test_congestion.window);
    try testing.expectEqual(test_initial_window, test_congestion.state.cubic.w_max);
    try testing.expectEqual(test_initial_window, test_congestion.state.cubic.prior_len);
    try testing.expectEqual(test_late_ns, test_congestion.recovery_started_at_ns);
    // RFC 9002 §7.3.2: "a single packet can be sent prior to reduction".
    try testing.expect(test_congestion.past_window_allowed);
    test_congestion.past_window_allowed = false;
    // A packet sent at or before the period began is inside it; one sent after is not.
    try testing.expect(test_congestion.in_recovery(test_late_ns));
    try testing.expect(!test_congestion.in_recovery(test_late_ns + 1));
    // A second event over a packet from inside the period does not reduce it again.
    _ = test_congestion.on_congestion_event(test_early_ns, test_late_ns + 1);
    try testing.expectEqual(reduced, test_congestion.window);
    try testing.expect(!test_congestion.past_window_allowed);
    // An event over a packet sent after the period starts a new one. The window fell short of
    // W_max, so fast convergence (§4.7) lowers W_max to (1 + β) / 2 of the window.
    _ = test_congestion.on_congestion_event(test_late_ns + 1, test_late_ns + 2);
    try testing.expectEqual(reduced / 10 * 7, test_congestion.window);
    try testing.expectEqual(reduced / 20 * 17, test_congestion.state.cubic.w_max);
}

test "§7.2, RFC 9438 Figure 5: the window and the threshold never fall below two datagrams" {
    test_congestion.init(test_datagram_len);
    var at_ns: u64 = test_early_ns;
    for (0..16) |_| {
        at_ns += 1;
        _ = test_congestion.on_congestion_event(at_ns, at_ns);
    }
    try testing.expectEqual(test_minimum_window, test_congestion.window);
    try testing.expectEqual(test_minimum_window, test_congestion.slow_start_threshold);
}

test "B.5: the window does not grow inside a recovery period" {
    test_congestion.init(test_datagram_len);
    _ = test_congestion.on_congestion_event(test_early_ns, test_late_ns);
    const held = test_congestion.window;
    // A packet sent before the period began carries no news about the path since.
    acknowledge(test_early_ns, test_late_ns + 1);
    try testing.expectEqual(held, test_congestion.window);
    try testing.expectEqual(null, test_congestion.state.cubic.epoch_ns);
}

test "RFC 9438 §4.3: right after a decrease the window follows the Reno-friendly estimate" {
    test_congestion.init(test_datagram_len);
    _ = test_congestion.on_congestion_event(test_early_ns, test_late_ns);
    const held = test_congestion.window;
    // The curve starts back at the window and rises slowly, so W_est leads: a window of octets
    // acknowledged adds α = 9/17 of a datagram, where NewReno would add one.
    var acknowledged_len: u64 = 0;
    // Bounded: one window of datagrams.
    while (acknowledged_len < held) : (acknowledged_len += test_datagram_len) acknowledge(test_late_ns + 1, test_late_ns + 1);
    // α = 9/17 of a datagram, about 630 octets here; the curve alone adds under half a datagram.
    try testing.expect(test_congestion.window >= held + test_datagram_len / 2);
    try testing.expect(test_congestion.window < held + test_datagram_len);
    try testing.expectEqual(test_late_ns + 1, test_congestion.state.cubic.epoch_ns);
}

test "RFC 9438 §4.4, §4.5: the window climbs back to W_max by K, and probes past it" {
    test_congestion.init(test_datagram_len);
    _ = test_congestion.on_congestion_event(test_early_ns, test_late_ns);
    const w_max = test_congestion.state.cubic.w_max;
    const start_ns = test_late_ns + 1;
    acknowledge(start_ns, start_ns);
    const k_ns = test_congestion.state.cubic.curve.k_us * constants.nanoseconds_per_microsecond;
    // Bounded: acknowledgments one round trip apart, up to K and a little past it.
    var now_ns = start_ns;
    while (now_ns < start_ns + k_ns + 2 * test_rtt_ns) : (now_ns += test_rtt_ns) {
        for (0..test_congestion.window / test_datagram_len) |_| acknowledge(start_ns + 1, now_ns);
    }
    try testing.expect(test_congestion.window >= w_max);
}

test "RFC 9438 §4.2: time the sender was limited does not count toward the curve" {
    test_congestion.init(test_datagram_len);
    _ = test_congestion.on_congestion_event(test_early_ns, test_late_ns);
    acknowledge(test_late_ns + 1, test_late_ns + 1);
    const epoch_ns = test_congestion.state.cubic.epoch_ns.?;
    const limited_ns: u64 = test_rtt_ns * test_limited_round_trips;
    test_congestion.on_ack(test_late_ns + 1, test_datagram_len, .limited, epoch_ns + 1, test_rtt_ns, null);
    acknowledge(test_late_ns + 1, epoch_ns + 1 + limited_ns);
    try testing.expectEqual(epoch_ns + limited_ns, test_congestion.state.cubic.epoch_ns.?);
}

test "§7.6, RFC 9438 §4.8: persistent congestion puts the window back to the minimum, with K = 0" {
    test_congestion.init(test_datagram_len);
    _ = test_congestion.on_congestion_event(test_early_ns, test_late_ns);
    test_congestion.on_persistent_congestion();
    try testing.expectEqual(test_minimum_window, test_congestion.window);
    // The recovery period ends with it, so the next acknowledgment grows the window again
    // rather than being held by a period that is no longer meaningful.
    try testing.expectEqual(null, test_congestion.recovery_started_at_ns);
    try testing.expect(!test_congestion.in_recovery(0));
    // Slow start runs back up to the threshold; the stage after it starts with K = 0.
    test_congestion.window = test_congestion.slow_start_threshold;
    acknowledge(test_late_ns + 1, test_late_ns + 1);
    try testing.expectEqual(0, test_congestion.state.cubic.curve.k_us);
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

/// Acknowledges `count` full datagrams of one round of HyStart++ at `now_ns`, each with
/// `rtt_ns` as its sample: the first one sent at `now_ns`, so it ends the round before it.
fn hystart_round(now_ns: u64, rtt_ns: u64, count: u8) void {
    for (0..count) |index| {
        const sent_at_ns = if (index == 0) now_ns else now_ns - 1;
        test_congestion.on_ack(sent_at_ns, test_datagram_len, .full, now_ns, test_rtt_ns, rtt_ns);
    }
}

test "RFC 9406 §4.2, RFC 9438 §4.10: HyStart++ grows by a quarter in CSS, then hands over" {
    test_congestion.init(test_datagram_len);
    const samples = constants.recovery.hystart.rtt_samples;
    hystart_round(test_rtt_ns, test_rtt_ns, samples);
    // The round trip grows by 6.25 ms, past 50 ms over 8: CSS starts after the round's window grew.
    hystart_round(2 * test_rtt_ns, test_rtt_ns + 6_250_000, samples);
    try testing.expectEqual(.conservative, test_congestion.state.cubic.hystart.stage);
    const before = test_congestion.window;
    acknowledge(test_early_ns, 2 * test_rtt_ns);
    try testing.expectEqual(before + test_datagram_len / constants.recovery.hystart.css_growth_divisor, test_congestion.window);
    // The rounds of CSS, then the round that ends the last: ssthresh is the window, and the
    // same acknowledgment grows it along a curve that starts there.
    for (2..constants.recovery.hystart.css_rounds + 2) |index| hystart_round(index * 2 * test_rtt_ns, 2 * test_rtt_ns, 1);
    const handed = test_congestion.slow_start_threshold;
    try testing.expect(handed < std.math.maxInt(u64));
    try testing.expect(test_congestion.window > handed);
    try testing.expectEqual(handed, test_congestion.state.cubic.prior_len);
    try testing.expectEqual(handed, test_congestion.state.cubic.curve.w_max);
    try testing.expectEqual(0, test_congestion.state.cubic.curve.k_us);
}

test "RFC 9406 §4.2: a loss in slow start ends HyStart++ for the connection" {
    test_congestion.init(test_datagram_len);
    _ = test_congestion.on_congestion_event(test_early_ns, test_late_ns);
    try testing.expectEqual(.done, test_congestion.state.cubic.hystart.stage);
}
