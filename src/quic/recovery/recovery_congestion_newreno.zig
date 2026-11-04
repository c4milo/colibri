//! NewReno's own state and its growth (RFC 9002 §7.3 and Appendix B, decision 133 as amended).
//! Part of design §8 step 34. `recovery_congestion.zig` keeps RFC 9002's state the controllers
//! share: the window, the slow start threshold and the recovery period.
//!
//! It reads no clock: every instant is a parameter (non-negotiable 3).
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../constants.zig");
const recovery_congestion = @import("recovery_congestion.zig");

const Congestion = recovery_congestion.Congestion;
const Utilization = recovery_congestion.Utilization;
const newreno = constants.recovery.newreno;

pub const NewReno = struct {
    /// The octets of Appendix B.5's congestion avoidance increase that have not yet made a whole
    /// octet of window: the increase is `max_datagram_size × acknowledged / window`.
    growth_numerator: u64,

    pub fn init(state: *NewReno) void {
        state.* = .{ .growth_numerator = 0 };
    }
};

/// Appendix B.5's `OnPacketAcked`: takes the acknowledgment of `sent_len` octets, the largest of
/// them sent at `sent_at_ns`.
pub fn on_ack(congestion: *Congestion, state: *NewReno, sent_at_ns: u64, sent_len: u64, used: Utilization) void {
    // RFC 9002 §7.8 and Appendix B.5: "Do not increase congestion_window if application limited
    // or flow control limited."
    if (used == .limited) return;
    // Appendix B.5: "Do not increase congestion window in recovery period."
    if (congestion.in_recovery(sent_at_ns)) return;
    if (congestion.window < congestion.slow_start_threshold) {
        // RFC 9002 §7.3.1: in slow start the window grows by what was acknowledged.
        congestion.window +|= sent_len;
        return;
    }
    grow_in_avoidance(congestion, state, sent_len);
}

/// RFC 9002 §7.3.3: the increase "MUST limit the increase to the congestion window to at most one
/// maximum datagram size for each congestion window that is acknowledged". Appendix B.5 adds
/// `max_datagram_size × sent_bytes / congestion_window`, and what each division leaves is carried
/// to the next, so a window of acknowledgments adds one datagram whatever their sizes.
fn grow_in_avoidance(congestion: *Congestion, state: *NewReno, sent_len: u64) void {
    const window = congestion.window;
    assert(window > 0);
    state.growth_numerator +|= congestion.max_datagram_len *| sent_len;
    congestion.window +|= state.growth_numerator / window;
    state.growth_numerator %= window;
}

/// Appendix B.6's part of a congestion event, once RFC 9002 has started a recovery period.
pub fn on_congestion_event(congestion: *Congestion, state: *NewReno) void {
    // Appendix B.6: `ssthresh = congestion_window * kLossReductionFactor` and
    // `congestion_window = max(ssthresh, kMinimumWindow)`.
    congestion.slow_start_threshold = congestion.window / newreno.loss_reduction_denominator * newreno.loss_reduction_numerator;
    congestion.window = @max(congestion.slow_start_threshold, congestion.minimum_window());
    state.growth_numerator = 0;
    // RFC 9002 §7.3.2 and Appendix B.6: "A packet can be sent to speed up loss recovery."
    congestion.past_window_allowed = true;
}

/// RFC 9002 §7.6.2 and Appendix B.8: the shared state falls to the minimum window, and what the
/// increase carried goes with the window it was carried against.
pub fn on_persistent_congestion(state: *NewReno) void {
    state.growth_numerator = 0;
}

test {
    _ = @import("recovery_congestion_newreno_test.zig");
}
