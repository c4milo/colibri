//! BBRv3's Startup and Drain (draft-ietf-ccwg-bbr-06 §5.3.1, §5.3.2). Part of design §8 step
//! 29b.2.
//!
//! Startup doubles the sending rate each round trip until three rounds in a row fail to raise
//! the delivery rate by a quarter. The pipe is then full, and Drain paces at half the rate until
//! the queue that Startup built is gone. 29b.3 adds Startup's exit on high loss (§5.3.1.3).
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../../constants.zig");
const recovery_delivery = @import("../recovery_delivery.zig");
const recovery_bbr = @import("recovery_bbr.zig");
const recovery_bbr_inflight = @import("recovery_bbr_inflight.zig");
const recovery_bbr_probe_bw = @import("recovery_bbr_probe_bw.zig");

const Bbr = recovery_bbr.Bbr;
const Path = recovery_bbr.Path;
const Sample = recovery_delivery.Sample;
const bbr = constants.recovery.bbr;

/// §5.3.1.1's `EnterStartup`.
pub fn enter_startup(state: *Bbr) void {
    state.state = .startup;
    state.pacing_gain = bbr.startup_pacing_gain;
    state.cwnd_gain = bbr.default_cwnd_gain;
}

/// §5.3.1.2's `ResetFullBW`.
pub fn reset_full_bw(state: *Bbr) void {
    state.full_bw = 0;
    state.full_bw_count = 0;
    state.full_bw_now = false;
}

/// §5.3.1.2's `CheckFullBWReached`, once a round, from a sample the application did not limit.
pub fn check_full_bw_reached(state: *Bbr, sample: Sample) void {
    if (state.full_bw_now or !state.model.round_start or sample.application_limited) return;
    // "if (RS.delivery_rate >= BBR.full_bw * 1.25)": the rate still grows, so the round starts a
    // new baseline. Both sides are in hundredths, in 128 bits.
    const grown = @as(u128, sample.rate) * bbr.gain_denominator >= @as(u128, state.full_bw) * bbr.full_bw_growth;
    if (grown) {
        reset_full_bw(state);
        state.full_bw = sample.rate;
        return;
    }
    state.full_bw_count += 1;
    state.full_bw_now = state.full_bw_count >= bbr.full_bw_rounds;
    if (state.full_bw_now) state.full_bw_reached = true;
    assert(state.full_bw_count <= bbr.full_bw_rounds);
}

/// §5.3.1.1's `CheckStartupDone`. 29b.3 adds `CheckStartupHighLoss` before it.
pub fn check_startup_done(state: *Bbr) void {
    if (state.state == .startup and state.full_bw_reached) enter_drain(state);
}

/// §5.3.2's `EnterDrain`.
fn enter_drain(state: *Bbr) void {
    state.state = .drain;
    state.pacing_gain = bbr.drain_pacing_gain;
    state.cwnd_gain = bbr.default_cwnd_gain;
    state.drain_start_round = state.model.round_count;
}

/// §5.3.2's `CheckDrainDone`: Drain ends once the octets in flight fit one BDP, or 3 rounds on.
pub fn check_drain_done(state: *Bbr, path: Path) void {
    if (state.state != .drain) return;
    const drained = path.in_flight_len <= recovery_bbr_inflight.inflight(state, path, state.bw, bbr.gain_denominator);
    if (drained or state.model.round_count > state.drain_start_round + bbr.drain_rounds) {
        recovery_bbr_probe_bw.enter(state, path);
    }
    assert(state.state != .drain or state.model.round_count <= state.drain_start_round + bbr.drain_rounds);
}
