//! What a connection observed of its path for Careful Resume (RFC 9959 §3.1, decision 149): the
//! set a program saves for a later connection to the same remote endpoint. Part of design §8
//! step 35a.
//!
//! It reads no clock: the instant is a parameter (non-negotiable 3).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("../constants.zig");
const connection_module = @import("connection.zig");
const recovery_resume = @import("../recovery/recovery_resume.zig");
const recovery_congestion = @import("../recovery/recovery_congestion.zig");
const recovery_bbr_model = @import("../recovery/recovery_bbr/recovery_bbr_model.zig");

const Connection = connection_module.Connection;
const ResumeState = recovery_resume.ResumeState;

/// RFC 9959 §3.1's observation at `now_ns`: the capacity the connection used over one round
/// trip and its minimum round trip, or null when there is nothing worth saving. A program stores
/// the set and passes it to a later connection's `resumed_from` option.
pub fn observe(connection: *const Connection, now_ns: u64) ?ResumeState {
    const recovery = &connection.recovery;
    // RFC 9959 §3.1: "The minimum RTT at the time of observation is saved as the saved_rtt", and
    // a connection with no sample has none.
    if (!recovery.rtt.has_sample()) return null;
    const window_len = capacity_len(&recovery.congestion) orelse return null;
    // RFC 9959 §3.1: "If the measured CWND is less than four times the IW, the sender can choose
    // to not save the CC parameters".
    const floor = recovery_congestion.initial_window(recovery.congestion.max_datagram_len) * constants.policy.resume_observed_windows_min;
    if (window_len < floor) return null;
    const state: ResumeState = .{ .window_len = window_len, .rtt_ns = recovery.rtt.min_ns, .saved_at_ns = now_ns };
    assert(state.version == recovery_resume.state_version);
    return state;
}

/// RFC 9959 §4.1: the capacity a controller's state says the connection used over one round trip.
fn capacity_len(congestion: *const recovery_congestion.Congestion) ?u64 {
    switch (congestion.state) {
        .cubic, .newreno => {
            // RFC 9959 §4.1: "At the end of Slow Start, the CWND can be significantly larger than
            // needed", and "One mitigation when a connection is in Slow Start could be to set the
            // saved_cwnd based on the validated pipe size (i.e., CWND / 2)".
            if (congestion.window < congestion.slow_start_threshold) return congestion.window / constants.policy.resume_slow_start_window_divisor;
            return congestion.window;
        },
        .bbr => |*bbr| {
            // RFC 9959 §4.1: a rate-based controller such as BBR estimates the capacity from its
            // model, here draft-ietf-ccwg-bbr-06's BBR.bw over BBR.min_rtt, its BDP (§5.6.4.2).
            if (bbr.model.min_rtt_ns == recovery_bbr_model.rtt_unknown_ns) return null;
            const product = @as(u128, bbr.bw) * bbr.model.min_rtt_ns / core.constants.nanoseconds_per_second;
            return @intCast(@min(product, std.math.maxInt(u64)));
        },
    }
}

test {
    _ = @import("connection_resume_test.zig");
}
