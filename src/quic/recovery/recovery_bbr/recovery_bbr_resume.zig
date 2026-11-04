//! Careful Resume under BBRv3 (RFC 9959 Appendix C, decision 149): the "carefully-resuming" flag
//! and what it changes in Startup and Drain. Part of design §8 step 35c. `recovery_resume_phases.zig`
//! decides when the path is confirmed and calls `start`; this file runs the flag's rounds.
//!
//! It reads no clock: every instant is a parameter (non-negotiable 3).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("../../constants.zig");
const recovery_bbr = @import("recovery_bbr.zig");
const recovery_bbr_inflight = @import("recovery_bbr_inflight.zig");
const recovery_bbr_startup = @import("recovery_bbr_startup.zig");

const Bbr = recovery_bbr.Bbr;
const Path = recovery_bbr.Path;

/// Appendix C's state: whether the flag is set, or waits for the next round to be, the probing
/// rate in octets a second, and the round at which the flag clears.
pub const Resuming = struct {
    /// Appendix C: "The flag 'carefully-resuming' is added to the BBR state".
    active: bool = false,
    /// C.1: "The sender starts the Unvalidated Phase at the beginning of a BBR round".
    pending: bool = false,
    /// C.1: "The probing rate is configured to 1/2 of the bottleneck bandwidth, derived from the
    /// CWND calculation specified in the saved CC parameters".
    rate: u64 = 0,
    /// C.1: the flag "is reset to False two rounds after it is set".
    end_round: u64 = 0,
};

/// C.1: the probing rate of a jump of `jump_len` octets over the saved round trip.
pub fn probing_rate(jump_len: u64, saved_rtt_ns: u64) u64 {
    assert(saved_rtt_ns > 0);
    const product = @as(u128, jump_len) * core.constants.nanoseconds_per_second / saved_rtt_ns;
    return @intCast(@min(product, std.math.maxInt(u64)));
}

/// C.1: "Careful Resume is allowed to transmit unvalidated packets only when the BBR flow is in
/// the Startup state." Answers whether the flag will be set at the next round.
pub fn start(state: *Bbr, rate: u64) bool {
    if (state.state != .startup) return false;
    state.resuming = .{ .pending = true, .rate = rate };
    return true;
}

/// On each ACK frame, once `UpdateRound` has run: the flag is set at a round's start, and clears
/// two rounds later while Startup lasts.
pub fn on_round(state: *Bbr) void {
    const held = &state.resuming;
    if (!state.model.round_start) return;
    if (held.pending) {
        held.pending = false;
        held.active = true;
        held.end_round = state.model.round_count + constants.recovery.bbr.resume_rounds;
        return;
    }
    // C.1: "The 'carefully-resuming' flag is reset to False two rounds after it is set".
    if (held.active and state.state == .startup and state.model.round_count >= held.end_round) held.active = false;
}

/// C.3: "any delivery rates measured in the Drain state MUST be discarded if the
/// 'carefully-resuming' flag is set to True."
pub fn discards_rates(state: *const Bbr) bool {
    return state.resuming.active and state.state == .drain;
}

/// C.1: with the flag set, the pacing rate is "the larger of the nominal pacing rate ... or the
/// calculated probing rate".
pub fn raise_pacing_rate(state: *Bbr) void {
    if (!state.resuming.active or state.state != .startup) return;
    state.pacing_rate = @max(state.pacing_rate, state.resuming.rate);
}

/// C.1: with the flag set, "the CWND is set to the larger of BBR.bw and the probing rate,
/// multiplied by BBR.rtt_min times BBRStartupCwndGain".
pub fn raise_window(state: *Bbr, path: Path) void {
    if (!state.resuming.active or state.state != .startup) return;
    const bw = @max(state.bw, state.resuming.rate);
    state.window_len = @max(state.window_len, recovery_bbr_inflight.bdp_multiple(state, path, bw, state.cwnd_gain));
}

/// C.1 and C.2: "If congestion is detected while the 'carefully-resuming' flag is True, BBR exits
/// the Startup state and enters the Drain state". Answers whether it did, which is the Safe
/// Retreat Phase (C.3). A flag that waits for its round is dropped.
pub fn on_congestion(state: *Bbr) bool {
    const held = &state.resuming;
    held.pending = false;
    if (!held.active) return false;
    if (state.state == .startup) recovery_bbr_startup.enter_drain(state);
    return state.state == .drain;
}

/// C.3: "This flag is cleared upon exiting the Drain state."
pub fn on_drain_exit(state: *Bbr) void {
    state.resuming.active = false;
}

test {
    _ = @import("recovery_bbr_resume_test.zig");
}
