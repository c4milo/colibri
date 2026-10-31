//! BBRv3's ProbeRTT and its restart after an idle period (draft-ietf-ccwg-bbr-06 §5.3.4, §5.4).
//! Part of design §8 step 29b.2.
//!
//! When BBR.probe_rtt_min_delay has not fallen for 5 s, BBR halves its window for at least 200 ms
//! and one round trip, so the queue at the bottleneck empties and the round trip it measures is
//! the path's own. An idle period empties the queue too, so after one BBR does not enter
//! ProbeRTT, and ends one that is in progress.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../../constants.zig");
const recovery_delivery = @import("../recovery_delivery.zig");
const recovery_bbr = @import("recovery_bbr.zig");
const recovery_bbr_inflight = @import("recovery_bbr_inflight.zig");
const recovery_bbr_loss = @import("recovery_bbr_loss.zig");
const recovery_bbr_probe_bw = @import("recovery_bbr_probe_bw.zig");
const recovery_bbr_startup = @import("recovery_bbr_startup.zig");

const Bbr = recovery_bbr.Bbr;
const Path = recovery_bbr.Path;
const Sample = recovery_delivery.Sample;
const bbr = constants.recovery.bbr;

/// §5.3.4.3's `CheckProbeRTT`, on each ACK frame after `UpdateMinRTT`.
pub fn check(state: *Bbr, sample: Sample, path: Path, delivery: *recovery_delivery.Delivery) void {
    if (state.state != .probe_rtt and state.model.probe_rtt_expired and !state.idle_restart) {
        enter(state);
        recovery_bbr_loss.save_window(state, path);
        state.probe_rtt_done_at_ns = 0;
        state.ack_phase = .probe_stopping;
        state.model.start_round(path.delivered_len);
    }
    if (state.state == .probe_rtt) handle(state, path, delivery);
    if (sample.delivered_len > 0) state.idle_restart = false;
}

/// §5.3.4.3's `EnterProbeRTT`.
fn enter(state: *Bbr) void {
    state.state = .probe_rtt;
    state.pacing_gain = bbr.probe_rtt_pacing_gain;
    state.cwnd_gain = bbr.probe_rtt_cwnd_gain;
}

/// §5.3.4.3's `HandleProbeRTT`.
fn handle(state: *Bbr, path: Path, delivery: *recovery_delivery.Delivery) void {
    // "Ignore low rate samples during ProbeRTT".
    delivery.mark_application_limited(path.in_flight_len);
    if (state.probe_rtt_done_at_ns == 0 and path.in_flight_len <= recovery_bbr_inflight.probe_rtt_window_len(state, path)) {
        // "Wait for at least BBR.ProbeRTTDuration to elapse", and for one round.
        state.probe_rtt_done_at_ns = path.now_ns + bbr.probe_rtt_duration_ns;
        state.probe_rtt_round_done = false;
        state.model.start_round(path.delivered_len);
    } else if (state.probe_rtt_done_at_ns != 0) {
        if (state.model.round_start) state.probe_rtt_round_done = true;
        if (state.probe_rtt_round_done) check_done(state, path);
    }
}

/// §5.3.4.3's `CheckProbeRTTDone`.
fn check_done(state: *Bbr, path: Path) void {
    if (state.probe_rtt_done_at_ns == 0 or path.now_ns <= state.probe_rtt_done_at_ns) return;
    // "schedule next ProbeRTT".
    state.model.probe_rtt_min_at_ns = path.now_ns;
    recovery_bbr_loss.restore_window(state);
    exit(state, path);
    assert(state.state != .probe_rtt);
}

/// §5.3.4.4's `ExitProbeRTT`.
fn exit(state: *Bbr, path: Path) void {
    recovery_bbr_loss.reset_short_term_model(state);
    if (state.full_bw_reached) {
        recovery_bbr_probe_bw.start_down(state, path);
        recovery_bbr_probe_bw.start_cruise(state);
    } else {
        recovery_bbr_startup.enter_startup(state);
    }
}

/// §5.4.1's `HandleRestartFromIdle`, before a packet goes out. `application_limited` is
/// `C.app_limited` (§4.1.2.4). In ProbeBW the draft also paces at the estimate, which 29b.4 does.
pub fn handle_restart_from_idle(state: *Bbr, path: Path, application_limited: bool) void {
    if (path.in_flight_len != 0 or !application_limited) return;
    state.idle_restart = true;
    state.model.extra_acked_interval_start_ns = path.now_ns;
    if (state.state == .probe_rtt) check_done(state, path);
}
