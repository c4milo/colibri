//! BBRv3's ProbeBW (draft-ietf-ccwg-bbr-06 §5.3.3). Part of design §8 step 29b.2.
//!
//! Once the pipe is full, BBR cycles through four phases. DOWN paces below the estimate to empty
//! the queue, and CRUISE paces at the estimate. Once a probe wait passes, REFILL sends at the
//! estimate for one round, and UP paces above it to find more bandwidth. `AdaptLongTermModel`
//! raises `BBR.inflight_longterm` while the loss rate stays at or below 2%.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../../constants.zig");
const recovery_delivery = @import("../recovery_delivery.zig");
const recovery_bbr = @import("recovery_bbr.zig");
const recovery_bbr_inflight = @import("recovery_bbr_inflight.zig");
const recovery_bbr_startup = @import("recovery_bbr_startup.zig");
const recovery_bbr_wait = @import("recovery_bbr_wait.zig");

const Bbr = recovery_bbr.Bbr;
const Path = recovery_bbr.Path;
const Sample = recovery_delivery.Sample;
const bbr = constants.recovery.bbr;
const unbounded_len = recovery_bbr.unbounded_len;

/// §5.3.3.9's `EnterProbeBW`.
pub fn enter(state: *Bbr, path: Path) void {
    state.cwnd_gain = bbr.default_cwnd_gain;
    start_down(state, path);
}

/// §5.3.3.9's `StartProbeBW_DOWN`. 29b.3 adds `ResetCongestionSignals`.
pub fn start_down(state: *Bbr, path: Path) void {
    state.probe_up_acked_per_increase_len = unbounded_len;
    pick_probe_wait(state);
    state.cycle_start_ns = path.now_ns;
    state.ack_phase = .probe_stopping;
    state.model.start_round(path.delivered_len);
    state.state = .probe_bw_down;
    state.pacing_gain = bbr.probe_bw_down_pacing_gain;
    state.cwnd_gain = bbr.default_cwnd_gain;
}

/// §5.3.3.9's `StartProbeBW_CRUISE`.
pub fn start_cruise(state: *Bbr) void {
    state.state = .probe_bw_cruise;
    state.pacing_gain = bbr.probe_bw_steady_pacing_gain;
    state.cwnd_gain = bbr.default_cwnd_gain;
}

/// §5.3.3.9's `StartProbeBW_REFILL`. 29b.3 adds `ResetShortTermModel`.
pub fn start_refill(state: *Bbr, path: Path) void {
    state.bw_probe_up_rounds = 0;
    state.bw_probe_up_acked_len = 0;
    state.prev_probe_precautionary = false;
    state.ack_phase = .refilling;
    state.model.start_round(path.delivered_len);
    state.state = .probe_bw_refill;
    state.pacing_gain = bbr.probe_bw_steady_pacing_gain;
    state.cwnd_gain = bbr.default_cwnd_gain;
}

/// §5.3.3.9's `StartProbeBW_UP`.
fn start_up(state: *Bbr, sample: Sample, path: Path) void {
    state.ack_phase = .probe_starting;
    state.model.start_round(path.delivered_len);
    recovery_bbr_startup.reset_full_bw(state);
    state.full_bw = sample.rate;
    state.state = .probe_bw_up;
    state.pacing_gain = bbr.probe_bw_up_pacing_gain;
    state.cwnd_gain = bbr.probe_bw_up_cwnd_gain;
    raise_inflight_longterm_slope(state, path);
}

/// §5.3.3.8.2's `PickProbeWait`, from the caller's draw (decision 136).
fn pick_probe_wait(state: *Bbr) void {
    const drawn = recovery_bbr_wait.draw(state.bandwidth_probe_waits, state.probe_waits_drawn);
    state.probe_waits_drawn +%= 1;
    state.rounds_since_probe_up = drawn.rounds_start;
    state.bw_probe_wait_ns = drawn.wait_ns;
}

/// §5.3.3.9's `UpdateProbeBWCyclePhase`, on each ACK frame.
pub fn update_cycle_phase(state: *Bbr, sample: Sample, path: Path) void {
    if (!state.full_bw_reached) return;
    if (adapt_long_term_model(state, sample, path)) return;
    switch (state.state) {
        .probe_bw_down => {
            if (is_time_to_probe(state, path)) return;
            if (is_time_to_cruise(state, path)) start_cruise(state);
        },
        .probe_bw_cruise => _ = is_time_to_probe(state, path),
        .probe_bw_refill => {
            // "After one round of REFILL, start UP".
            if (state.model.round_start) {
                state.is_bw_probe_sample = true;
                start_up(state, sample, path);
            }
        },
        .probe_bw_up => {
            if (is_time_to_go_down(state, sample, path)) {
                state.prev_probe_too_high = false;
                start_down(state, path);
            }
        },
        .startup, .drain, .probe_rtt => {},
    }
}

/// §5.3.3.8.2's `IsTimeToProbeBW`: the wall clock wait has passed, or the round trips a Reno flow
/// needs to fill its share have.
fn is_time_to_probe(state: *Bbr, path: Path) bool {
    // §5.3.3.9's `HasElapsedInPhase`.
    const waited = path.now_ns > state.cycle_start_ns +| state.bw_probe_wait_ns;
    if (waited or is_reno_coexistence_probe_time(state, path)) {
        start_refill(state, path);
        return true;
    }
    return false;
}

/// §5.3.3.8.2's `IsRenoCoexistenceProbeTime`. `TargetInflight` is a volume, and a Reno flow
/// grows by one datagram a round trip, so the rounds are that volume in datagrams, at most 63.
fn is_reno_coexistence_probe_time(state: *const Bbr, path: Path) bool {
    const reno_rounds = recovery_bbr_inflight.target_inflight(state, path) / path.datagram_len;
    return state.rounds_since_probe_up >= @min(reno_rounds, bbr.reno_rounds_max);
}

/// §5.3.3.9's `IsTimeToCruise`.
fn is_time_to_cruise(state: *const Bbr, path: Path) bool {
    if (path.in_flight_len > recovery_bbr_inflight.inflight_with_headroom(state, path)) return false;
    return path.in_flight_len <= recovery_bbr_inflight.inflight(state, path, state.model.max_bw, bbr.gain_denominator);
}

/// §5.3.3.9's `IsTimeToGoDown`.
fn is_time_to_go_down(state: *Bbr, sample: Sample, path: Path) bool {
    // §5.3.3.6: precautionary deceleration.
    if (state.prev_probe_too_high and path.in_flight_len >= state.inflight_longterm_len) {
        state.prev_probe_precautionary = true;
        return true;
    }
    if (path.window_limited and state.window_len >= state.inflight_longterm_len) {
        // "bw is limited by BBR.inflight_longterm".
        recovery_bbr_startup.reset_full_bw(state);
        state.full_bw = sample.rate;
        return false;
    }
    return state.full_bw_now;
}

/// §5.3.3.9's `RaiseInflightLongtermSlope`: each round of UP doubles the growth of
/// `BBR.inflight_longterm`.
fn raise_inflight_longterm_slope(state: *Bbr, path: Path) void {
    const growth_this_round = @as(u64, 1) << state.bw_probe_up_rounds;
    state.bw_probe_up_rounds = @min(state.bw_probe_up_rounds + 1, bbr.bw_probe_up_rounds_max);
    state.probe_up_acked_per_increase_len = @max(state.window_len / growth_this_round, path.datagram_len);
    assert(state.probe_up_acked_per_increase_len > 0);
}

/// §5.3.3.9's `ProbeInflightLongtermUpward`: one datagram more for each
/// `probe_up_acked_per_increase_len` octets acknowledged while the window is full.
fn probe_inflight_longterm_upward(state: *Bbr, sample: Sample, path: Path) void {
    if (!path.window_limited or state.window_len < state.inflight_longterm_len) return;
    state.bw_probe_up_acked_len +|= sample.acknowledged_len;
    if (state.bw_probe_up_acked_len >= state.probe_up_acked_per_increase_len) {
        const delta = state.bw_probe_up_acked_len / state.probe_up_acked_per_increase_len;
        state.bw_probe_up_acked_len -= delta * state.probe_up_acked_per_increase_len;
        state.inflight_longterm_len +|= delta *| path.datagram_len;
    }
    // The remainder is below one step until the slope rises, which halves the step.
    assert(state.bw_probe_up_acked_len < state.probe_up_acked_per_increase_len);
    if (state.model.round_start) raise_inflight_longterm_slope(state, path);
}

/// §5.3.3.9's `AdaptLongTermModel`: true when it moved the state.
fn adapt_long_term_model(state: *Bbr, sample: Sample, path: Path) bool {
    if (state.ack_phase == .probe_starting and state.model.round_start) {
        // "starting to get bw probing samples".
        state.ack_phase = .probe_feedback;
    }
    if (state.ack_phase == .probe_stopping and state.model.round_start) {
        // "end of samples from bw probing phase".
        state.is_bw_probe_sample = false;
        state.ack_phase = .init;
        if (state.is_in_probe_bw() and !sample.application_limited) state.model.advance_max_bw_filter();
        // §5.3.3.6: precautionary acceleration.
        if (state.is_in_probe_bw() and state.prev_probe_precautionary and !state.prev_probe_too_high) {
            start_refill(state, path);
            return true;
        }
    }
    if (recovery_bbr_inflight.is_inflight_too_high(sample)) return false;
    // "Loss rate is safe. Adjust upper bounds upward."
    if (state.inflight_longterm_len == unbounded_len) return false;
    if (sample.tx_in_flight_len > state.inflight_longterm_len) state.inflight_longterm_len = sample.tx_in_flight_len;
    if (state.state == .probe_bw_up) probe_inflight_longterm_upward(state, sample, path);
    return false;
}
