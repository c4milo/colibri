//! BBRv3's response to loss (draft-ietf-ccwg-bbr-06 §5.3.1.3, §5.5.10, §5.5.11, §5.6.4.4). Part
//! of design §8 step 29b.3.
//!
//! A probe that lost more than 2% of what it had in flight lowers `BBR.inflight_longterm` to
//! where the loss began (§5.5.10.2). Outside a probe, each round with loss scales the short-term
//! model down by `BBR.Beta` toward what the round delivered (§5.5.10.3). Startup ends on high
//! loss (§5.3.1.3). A loss episode found spurious later restores what the loss took (§5.5.11).
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../../constants.zig");
const recovery_delivery = @import("../recovery_delivery.zig");
const recovery_sent = @import("../recovery_sent.zig");
const recovery_bbr = @import("recovery_bbr.zig");
const recovery_bbr_inflight = @import("recovery_bbr_inflight.zig");
const recovery_bbr_probe_bw = @import("recovery_bbr_probe_bw.zig");
const recovery_bbr_startup = @import("recovery_bbr_startup.zig");

const Bbr = recovery_bbr.Bbr;
const Path = recovery_bbr.Path;
const Sample = recovery_delivery.Sample;
const bbr = constants.recovery.bbr;
const unbounded_len = recovery_bbr.unbounded_len;

/// `value` times `BBR.Beta`, in 128 bits, held at the largest `u64`.
fn times_beta(value: u64) u64 {
    return @intCast(@min(@as(u128, value) * bbr.beta / bbr.gain_denominator, std.math.maxInt(u64)));
}

/// §5.5.10.3's `LossLowerBounds` for one bound: the larger of the round's delivery and
/// `BBR.Beta` of the bound.
pub fn lower(latest: u64, bound: u64) u64 {
    const lowered = @max(latest, times_beta(bound));
    assert(lowered >= latest);
    return lowered;
}

/// §5.5.10.3's `ResetCongestionSignals`.
pub fn reset_congestion_signals(state: *Bbr) void {
    state.is_loss_in_round = false;
    state.bw_latest = 0;
    state.inflight_latest_len = 0;
}

/// §5.5.10.3's `ResetShortTermModel`.
pub fn reset_short_term_model(state: *Bbr) void {
    state.bw_shortterm = unbounded_len;
    state.inflight_shortterm_len = unbounded_len;
}

/// §5.5.10.3's `UpdateLatestDeliverySignals`, near the start of an ACK frame. A loss round
/// ends when a packet sent after it began is acknowledged.
pub fn update_latest_delivery_signals(state: *Bbr, sample: Sample) void {
    state.loss_round_start = false;
    state.bw_latest = @max(state.bw_latest, sample.rate);
    state.inflight_latest_len = @max(state.inflight_latest_len, sample.delivered_len);
    if (sample.prior_delivered_len >= state.loss_round_delivered_len) {
        state.loss_round_delivered_len = sample.prior_delivered_len + sample.delivered_len;
        state.loss_round_start = true;
    }
}

/// §5.5.10.3's `AdvanceLatestDeliverySignals`, near the end of an ACK frame. §5.3.1.3's counts
/// of the round start again with it.
pub fn advance_latest_delivery_signals(state: *Bbr, sample: Sample) void {
    if (!state.loss_round_start) return;
    state.bw_latest = sample.rate;
    state.inflight_latest_len = sample.delivered_len;
    state.round_lost_len = 0;
    state.round_acknowledged_len = 0;
    state.round_lost_ranges = 0;
}

/// The rest of §5.5.10.3's `UpdateCongestionSignals`, after `UpdateMaxBw`: once a round,
/// `AdaptLowerBoundsFromCongestion`.
pub fn update_congestion_signals(state: *Bbr) void {
    if (!state.loss_round_start) return;
    const probing = switch (state.state) {
        .startup, .probe_bw_refill, .probe_bw_up => true,
        .drain, .probe_bw_down, .probe_bw_cruise, .probe_rtt => false,
    };
    if (!probing and state.is_loss_in_round) {
        // `InitLowerBounds`: "Handle the first congestion episode in this cycle".
        if (state.bw_shortterm == unbounded_len) state.bw_shortterm = state.model.max_bw;
        if (state.inflight_shortterm_len == unbounded_len) state.inflight_shortterm_len = state.window_len;
        // `LossLowerBounds`.
        state.bw_shortterm = lower(state.bw_latest, state.bw_shortterm);
        state.inflight_shortterm_len = lower(state.inflight_latest_len, state.inflight_shortterm_len);
    }
    state.is_loss_in_round = false;
}

/// §5.6.4.4's `SaveCwnd`. In recovery or in ProbeRTT the window is already reduced, so the
/// larger of the two is kept.
pub fn save_window(state: *Bbr, path: Path) void {
    if (!path.in_recovery and state.state != .probe_rtt) {
        state.prior_window_len = state.window_len;
    } else {
        state.prior_window_len = @max(state.prior_window_len, state.window_len);
    }
}

/// §5.6.4.4's `RestoreCwnd`.
pub fn restore_window(state: *Bbr) void {
    state.window_len = @max(state.window_len, state.prior_window_len);
}

/// §5.5.11.1's `SaveStateUponLoss`.
fn save_state_upon_loss(state: *Bbr, path: Path) void {
    save_window(state, path);
    state.undo_state = null;
    state.undo_bw_shortterm = state.bw_shortterm;
    state.undo_inflight_shortterm_len = state.inflight_shortterm_len;
    state.undo_inflight_longterm_len = state.inflight_longterm_len;
}

/// §5.6.4.4's `OnEnterFastRecovery`: RFC 9002's recovery period starts (§7.3.2).
pub fn on_enter_recovery(state: *Bbr, path: Path) void {
    save_state_upon_loss(state, path);
    state.recovery_start_round = state.model.round_count;
}

/// §5.5.10.2's `NoteLoss`.
fn note_loss(state: *Bbr, path: Path) void {
    if (!state.is_loss_in_round) {
        // "first loss in this round trip?"
        state.loss_round_delivered_len = path.delivered_len;
        save_state_upon_loss(state, path);
    }
    state.is_loss_in_round = true;
}

/// §5.5.10.2's `HandleLostPacket`, for one packet RFC 9002 §6.1 declared lost. `lost_len` is
/// `C.lost`, which counts it, and `application` says the packet was in the application space.
pub fn on_packet_lost(state: *Bbr, lost: recovery_sent.Record, lost_len: u64, application: bool, path: Path) void {
    assert(lost_len >= lost.lost_len);
    note_loss(state, path);
    count_round_loss(state, lost, application);
    // "not a packet sent while probing bandwidth".
    if (!state.is_bw_probe_sample) return;
    var sample = std.mem.zeroes(Sample);
    sample.tx_in_flight_len = lost.tx_in_flight_len;
    sample.lost_len = lost_len - lost.lost_len;
    sample.application_limited = lost.application_limited;
    if (!recovery_bbr_inflight.is_inflight_too_high(sample)) return;
    sample.tx_in_flight_len = inflight_at_loss(sample, lost.sent_len);
    handle_inflight_too_high(state, sample, path);
}

/// §5.3.1.3's counts for one lost packet: its octets, and a new range unless it follows the last
/// lost packet of the application space (the owner's ruling of 2026-10-31).
fn count_round_loss(state: *Bbr, lost: recovery_sent.Record, application: bool) void {
    if (lost.in_flight) state.round_lost_len +|= lost.sent_len;
    const follows = application and state.last_lost_number != null and lost.number == state.last_lost_number.? + 1;
    if (!follows) state.round_lost_ranges +|= 1;
    state.last_lost_number = if (application) lost.number else null;
}

/// §5.5.10.2's `InflightAtLoss`: the octets in flight at which the losses crossed 2%, inside the
/// lost packet of `size_len` octets. `lost_prefix` may be negative, when the losses before the
/// packet already crossed it, so the arithmetic is signed, and the answer is at least 0.
pub fn inflight_at_loss(sample: Sample, size_len: u64) u64 {
    const inflight_prev: i128 = @as(i128, sample.tx_in_flight_len) - size_len;
    const lost_prev: i128 = @as(i128, sample.lost_len) - size_len;
    // "(BBR.LossThresh * inflight_prev - lost_prev) / (1 - BBR.LossThresh)", in hundredths.
    const lost_prefix = @divFloor(
        @as(i128, bbr.loss_threshold) * inflight_prev - @as(i128, bbr.gain_denominator) * lost_prev,
        @as(i128, bbr.gain_denominator - bbr.loss_threshold),
    );
    const at_loss = @max(inflight_prev + lost_prefix, 0);
    return @intCast(@min(at_loss, std.math.maxInt(u64)));
}

/// §5.5.10.2's `HandleInflightTooHigh`.
fn handle_inflight_too_high(state: *Bbr, sample: Sample, path: Path) void {
    state.prev_probe_too_high = true;
    // "only react once per bw probe".
    state.is_bw_probe_sample = false;
    if (!sample.application_limited) {
        const target_len = times_beta(recovery_bbr_inflight.target_inflight(state, path));
        state.inflight_longterm_len = @max(sample.tx_in_flight_len, target_len);
    }
    if (state.state == .probe_bw_up) {
        state.undo_state = .probe_bw_up;
        recovery_bbr_probe_bw.start_down(state, path);
    }
}

/// §5.3.1.3's `CheckStartupHighLoss`, at the end of a round: Startup ends once a full round of
/// loss recovery passed, the round lost more than 2% of what it delivered and lost, and its
/// losses fell in at least 6 ranges.
pub fn check_startup_high_loss(state: *Bbr, path: Path) void {
    if (state.state != .startup or !state.loss_round_start or !path.in_recovery) return;
    const started = state.recovery_start_round orelse return;
    if (state.model.round_count < started + bbr.startup_recovery_rounds) return;
    const seen_len = @as(u128, state.round_acknowledged_len) + state.round_lost_len;
    if (@as(u128, state.round_lost_len) * bbr.gain_denominator <= seen_len * bbr.loss_threshold) return;
    if (state.round_lost_ranges < bbr.startup_full_loss_ranges) return;
    state.undo_state = .startup;
    state.full_bw_reached = true;
    const bdp_len = recovery_bbr_inflight.bdp_multiple(state, path, state.bw, bbr.gain_denominator);
    state.inflight_longterm_len = @max(bdp_len, state.inflight_latest_len);
    recovery_bbr_startup.enter_drain(state);
    assert(state.state == .drain);
}

/// §5.5.11.2's `HandleSpuriousLossDetection`: the loss episode was spurious, so BBR takes back
/// what it did for it.
pub fn on_spurious_loss(state: *Bbr, path: Path) void {
    restore_window(state);
    state.is_loss_in_round = false;
    recovery_bbr_startup.reset_full_bw(state);
    state.bw_shortterm = @max(state.bw_shortterm, state.undo_bw_shortterm);
    state.inflight_shortterm_len = @max(state.inflight_shortterm_len, state.undo_inflight_shortterm_len);
    state.inflight_longterm_len = @max(state.inflight_longterm_len, state.undo_inflight_longterm_len);
    // "If flow was probing bandwidth, return to that state".
    const undo = state.undo_state orelse return;
    state.undo_state = null;
    if (undo == .startup and state.state != .startup) {
        state.full_bw_reached = false;
        if (state.state != .probe_rtt) recovery_bbr_startup.enter_startup(state);
    } else if (undo == .probe_bw_up and state.state != .probe_bw_up) {
        if (state.state != .probe_rtt) recovery_bbr_probe_bw.start_refill(state, path);
    }
}
