//! CUBIC's own state and its growth (RFC 9438, decision 133), with HyStart++ in its first slow
//! start (RFC 9406, decision 135). Part of design §8 steps 27 and 28, split out of
//! `recovery_congestion.zig` in step 29b.4, which keeps RFC 9002's state the controllers share.
//!
//! It reads no clock: every instant is a parameter (non-negotiable 3).
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const recovery_congestion = @import("recovery_congestion.zig");
const recovery_cubic = @import("recovery_cubic.zig");
const recovery_hystart = @import("recovery_hystart.zig");

const Congestion = recovery_congestion.Congestion;
const Utilization = recovery_congestion.Utilization;

pub const Cubic = struct {
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
    /// HyStart++, which runs the first slow start (RFC 9438 §4.10, decision 135).
    hystart: recovery_hystart.HyStart,

    pub fn init(cubic: *Cubic, max_datagram_len: u64) void {
        cubic.* = .{
            .w_max = 0,
            .prior_len = 0,
            .epoch_ns = null,
            .curve = .{ .w_max = 0, .k_us = 0, .datagram_len = max_datagram_len },
            .estimate_len = 0,
            .growth_numerator = 0,
            .limited_since_ns = null,
            .hystart = undefined,
        };
        cubic.hystart.init();
    }
};

/// Takes the acknowledgment of `sent_len` octets, the largest of them sent at `sent_at_ns`
/// (RFC 9002 Appendix B.5's `OnPacketAcked`), at `now_ns`, with the connection's smoothed
/// round trip, which RFC 9438 §4.2 reads, and the sample the ACK gave, if any, which RFC 9406
/// §4.2 reads.
pub fn on_ack(congestion: *Congestion, cubic: *Cubic, sent_at_ns: u64, sent_len: u64, used: Utilization, now_ns: u64, smoothed_rtt_ns: u64, latest_rtt_ns: ?u64) void {
    // RFC 9406 §4.2 counts rounds and samples over every ACK in slow start, and an exit from
    // CSS needs no growth to happen.
    const growth: recovery_hystart.Growth = if (congestion.window < congestion.slow_start_threshold)
        cubic.hystart.on_ack(sent_at_ns, latest_rtt_ns, now_ns)
    else
        .full;
    if (growth == .avoidance) leave_slow_start(congestion, cubic);
    // RFC 9002 §7.8: an acknowledgment of a packet sent while the sender had less to send
    // than the window allowed says nothing about the path, so the window does not grow.
    // RFC 9438 §4.2: "The elapsed time t ... MUST NOT include periods during which cwnd has
    // not been updated due to application-limited behavior".
    if (used == .limited) {
        if (cubic.limited_since_ns == null) cubic.limited_since_ns = now_ns;
        return;
    }
    end_limited(cubic, now_ns);
    // RFC 9002 Appendix B.5: the window does not grow inside a recovery period either.
    if (congestion.in_recovery(sent_at_ns)) return;
    if (congestion.window < congestion.slow_start_threshold) {
        // RFC 9002 §7.3.1: in slow start the window grows by what was acknowledged, and RFC
        // 9406 §4.2 divides that by CSS_GROWTH_DIVISOR in CSS.
        if (growth == .conservative) return grow_conservatively(congestion, cubic, sent_len);
        congestion.window +|= sent_len;
        return;
    }
    grow_in_avoidance(congestion, cubic, sent_len, now_ns, smoothed_rtt_ns);
}

/// RFC 9406 §4.2: "enter congestion avoidance by setting the ssthresh to the current cwnd".
/// RFC 9438 §4.10: with no loss W_max is undefined, so cwnd_prior is the window, and the
/// stage's curve starts at the window with K = 0, which `start_epoch` gives when W_max is 0.
fn leave_slow_start(congestion: *Congestion, cubic: *Cubic) void {
    congestion.slow_start_threshold = congestion.window;
    cubic.prior_len = congestion.window;
    cubic.w_max = 0;
    cubic.epoch_ns = null;
    assert(cubic.hystart.stage == .done);
}

/// RFC 9406 §4.2: `cwnd + (min(N, L * SMSS) / CSS_GROWTH_DIVISOR)`, with what each division
/// leaves carried to the next, as §4.4's increase carries it.
fn grow_conservatively(congestion: *Congestion, cubic: *Cubic, sent_len: u64) void {
    cubic.growth_numerator +|= sent_len;
    congestion.window +|= cubic.growth_numerator / constants.recovery.hystart.css_growth_divisor;
    cubic.growth_numerator %= constants.recovery.hystart.css_growth_divisor;
}

/// Moves the stage's start later by the span the sender was limited, which §4.2 leaves out.
fn end_limited(cubic: *Cubic, now_ns: u64) void {
    const since_ns = cubic.limited_since_ns orelse return;
    cubic.limited_since_ns = null;
    assert(now_ns >= since_ns);
    if (cubic.epoch_ns) |epoch_ns| cubic.epoch_ns = epoch_ns +| (now_ns - since_ns);
}

/// RFC 9438 §4.2 to §4.5: the larger of the cubic curve's target and the Reno-friendly
/// estimate.
fn grow_in_avoidance(congestion: *Congestion, cubic: *Cubic, sent_len: u64, now_ns: u64, smoothed_rtt_ns: u64) void {
    const epoch_ns = cubic.epoch_ns orelse start_epoch(congestion, cubic, now_ns);
    const t_us = (now_ns -| epoch_ns) / constants.nanoseconds_per_microsecond;
    const rtt_us = smoothed_rtt_ns / constants.nanoseconds_per_microsecond;
    const window = congestion.window;
    // §4.3, Figure 4: W_est grows by α per window acknowledged, and by 1 once it reaches
    // cwnd_prior.
    cubic.estimate_len +|= recovery_cubic.estimate_gain(sent_len, window, congestion.max_datagram_len, cubic.estimate_len >= cubic.prior_len);
    // §4.3: "If [W_cubic(t) is less than W_est], CUBIC is in the Reno-friendly region and
    // cwnd SHOULD be set to W_est".
    if (cubic.curve.window_at(t_us) < cubic.estimate_len) {
        congestion.window = @max(window, cubic.estimate_len);
        return;
    }
    // §4.4, §4.5: in the concave and convex regions the window grows by
    // (target − cwnd) / cwnd per segment acknowledged.
    const target = cubic.curve.target(t_us, rtt_us, window);
    cubic.growth_numerator +|= (target - window) *| sent_len;
    congestion.window += cubic.growth_numerator / window;
    cubic.growth_numerator %= window;
}

/// Starts a congestion avoidance stage at `now_ns` (§4.1.2's t_epoch, cwnd_epoch and K).
fn start_epoch(congestion: *Congestion, cubic: *Cubic, now_ns: u64) u64 {
    cubic.curve = .of(cubic.w_max, congestion.window, congestion.max_datagram_len);
    cubic.w_max = cubic.curve.w_max;
    cubic.estimate_len = congestion.window;
    cubic.growth_numerator = 0;
    cubic.epoch_ns = now_ns;
    return now_ns;
}

/// RFC 9438's part of a congestion event, once RFC 9002 has started a recovery period: the
/// decrease of §4.6.
pub fn on_congestion_event(congestion: *Congestion, cubic: *Cubic) void {
    // RFC 9406 §4.2 and §4.3: a loss or an ECN mark ends HyStart++ for good, and the decrease
    // below sets ssthresh.
    cubic.hystart.finish();
    // RFC 9438 §4.7, §4.6: W_max and cwnd_prior first, then the decrease of Figure 5, which
    // RFC 9002 §7.2's minimum holds up.
    cubic.w_max = recovery_cubic.w_max_after(congestion.window, cubic.w_max);
    cubic.prior_len = congestion.window;
    congestion.slow_start_threshold = @max(recovery_cubic.reduced(congestion.window), congestion.minimum_window());
    congestion.window = congestion.slow_start_threshold;
    cubic.epoch_ns = null;
    // RFC 9002 §7.3.2: "This speeds up loss recovery if the data in the lost packet is
    // retransmitted."
    congestion.past_window_allowed = true;
}

/// RFC 9438 §4.8's part of persistent congestion: the next stage starts with K = 0 and W_max at
/// the window it starts from.
pub fn on_persistent_congestion(cubic: *Cubic) void {
    cubic.w_max = 0;
    cubic.epoch_ns = null;
}
