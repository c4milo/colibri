//! BBRv3's states (draft-ietf-ccwg-bbr-06 §5.3, §5.4). Part of design §8 step 29b.2.
//!
//! BBR moves through Startup, Drain, the four phases of ProbeBW and ProbeRTT on each ACK frame,
//! from the model of `recovery_bbr_model.zig`. Each state sets a pacing gain and a cwnd gain,
//! which 29b.4 applies to the pacing rate and the window. The moves of each state are in a file
//! of their own:
//! - `recovery_bbr_startup.zig`: Startup and Drain (§5.3.1, §5.3.2).
//! - `recovery_bbr_probe_bw.zig`: ProbeBW (§5.3.3).
//! - `recovery_bbr_probe_rtt.zig`: ProbeRTT and the restart after an idle period (§5.3.4, §5.4).
//! - `recovery_bbr_inflight.zig`: the volumes they compare with the octets in flight (§5.6.4).
//! - `recovery_bbr_wait.zig`: the draws of each bandwidth probe wait (decision 136).
//! - `recovery_bbr_loss.zig`: the short-term model and the response to loss (§5.5.10, §5.5.11).
//!
//! 29b.4 adds the pacing rate, the send quantum and the window. Every instant is a parameter (non-negotiable 3), and
//! every gain is a count of hundredths (invariant 5).
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../../constants.zig");
const recovery_delivery = @import("../recovery_delivery.zig");
const recovery_bbr_model = @import("recovery_bbr_model.zig");
const recovery_bbr_startup = @import("recovery_bbr_startup.zig");
const recovery_bbr_probe_bw = @import("recovery_bbr_probe_bw.zig");
const recovery_bbr_probe_rtt = @import("recovery_bbr_probe_rtt.zig");
const recovery_bbr_loss = @import("recovery_bbr_loss.zig");
const recovery_sent = @import("../recovery_sent.zig");

const bbr = constants.recovery.bbr;
const Sample = recovery_delivery.Sample;

/// The draft's "Infinity" for a volume: `BBR.inflight_longterm` before any loss bounds it.
pub const unbounded_len: u64 = std.math.maxInt(u64);

/// §5.1's states.
pub const State = enum(u8) {
    startup,
    drain,
    probe_bw_down,
    probe_bw_cruise,
    probe_bw_refill,
    probe_bw_up,
    probe_rtt,
};

/// §2.14's `BBR.ack_phase`: where the ACK frames are in a bandwidth probe.
pub const AckPhase = enum(u8) {
    init,
    refilling,
    probe_starting,
    probe_feedback,
    probe_stopping,
};

/// What the connection knows when BBR runs: the draft's `C.*` values.
pub const Path = struct {
    now_ns: u64,
    /// `C.inflight`: the octets in flight (RFC 9002 §7.2's `bytes_in_flight`).
    in_flight_len: u64,
    /// `C.delivered`: the octets the peer has acknowledged (§4.1.2.1.1).
    delivered_len: u64,
    /// `C.is_cwnd_limited`: whether the window, and not the application, bounded what went out
    /// (RFC 9002 §7.8).
    window_limited: bool,
    /// `InLossRecovery()`: whether RFC 9002's recovery period holds (§7.3.2).
    in_recovery: bool,
    /// `C.SMSS`: the maximum datagram size.
    datagram_len: u64,
    /// `C.InitialCwnd` (RFC 9002 §7.2).
    initial_window_len: u64,
    /// `C.send_quantum` (§5.6.3), which 29b.4 computes.
    send_quantum_len: u64,
};

pub const Bbr = struct {
    model: recovery_bbr_model.Model,
    state: State,
    /// §2.5's `BBR.pacing_gain` and §2.6's `BBR.cwnd_gain`, in hundredths.
    pacing_gain: u64,
    cwnd_gain: u64,
    /// §5.5.10.3's `BBR.bw`, octets a second: `BBR.max_bw`, bounded by the short-term model.
    bw: u64,
    /// §2.10 and §5.5.10.3: the short-term model, which loss outside a probe lowers, and the
    /// latest round's delivery it lowers toward.
    bw_shortterm: u64,
    inflight_shortterm_len: u64,
    bw_latest: u64,
    inflight_latest_len: u64,
    loss_round_delivered_len: u64,
    loss_round_start: bool,
    is_loss_in_round: bool,
    /// §2.15: what §5.5.11 restores after a spurious loss episode. Null is the draft's None.
    undo_state: ?State,
    undo_bw_shortterm: u64,
    undo_inflight_shortterm_len: u64,
    undo_inflight_longterm_len: u64,
    /// §5.3.1.3's counts of the round in progress: octets acknowledged and lost, lost ranges and
    /// the last lost packet number, and the round RFC 9002's recovery period started in.
    round_acknowledged_len: u64,
    round_lost_len: u64,
    round_lost_ranges: u8,
    last_lost_number: ?u64,
    recovery_start_round: ?u64,
    /// `C.cwnd`, which ProbeRTT saves and restores (§5.6.4.4) and 29b.4 sets.
    window_len: u64,
    /// §5.6.4.4's `BBR.prior_cwnd`.
    prior_window_len: u64,
    /// §2.13 and §5.3.1.2: the estimate of a full pipe.
    full_bw: u64,
    full_bw_count: u8,
    full_bw_now: bool,
    full_bw_reached: bool,
    /// §5.3.2's `BBR.drain_start_round`.
    drain_start_round: u64,
    /// §2.14: the state of a bandwidth probe.
    ack_phase: AckPhase,
    cycle_start_ns: u64,
    bw_probe_wait_ns: u64,
    rounds_since_probe_up: u64,
    bw_probe_up_rounds: u6,
    bw_probe_up_acked_len: u64,
    probe_up_acked_per_increase_len: u64,
    prev_probe_too_high: bool,
    prev_probe_precautionary: bool,
    is_bw_probe_sample: bool,
    /// §2.10's `BBR.inflight_longterm`.
    inflight_longterm_len: u64,
    /// Decision 136: the value the caller drew, and the count of waits drawn from it.
    bandwidth_probe_waits: u64,
    probe_waits_drawn: u64,
    /// §2.16.2: `BBR.probe_rtt_done_stamp`, 0 when unset, and `BBR.probe_rtt_round_done`.
    probe_rtt_done_at_ns: u64,
    probe_rtt_round_done: bool,
    /// §5.4's `BBR.idle_restart`.
    idle_restart: bool,

    /// §5.2.1's `OnInit`, for the states. `bandwidth_probe_waits` is the caller's draw
    /// (decision 136).
    pub fn init(state: *Bbr, now_ns: u64, initial_window_len: u64, bandwidth_probe_waits: u64) void {
        assert(initial_window_len > 0);
        state.* = .{
            .model = undefined,
            .state = .startup,
            .pacing_gain = bbr.startup_pacing_gain,
            .cwnd_gain = bbr.default_cwnd_gain,
            .bw = 0,
            .bw_shortterm = unbounded_len,
            .inflight_shortterm_len = unbounded_len,
            .bw_latest = 0,
            .inflight_latest_len = 0,
            .loss_round_delivered_len = 0,
            .loss_round_start = false,
            .is_loss_in_round = false,
            .undo_state = null,
            .undo_bw_shortterm = 0,
            .undo_inflight_shortterm_len = 0,
            .undo_inflight_longterm_len = 0,
            .round_acknowledged_len = 0,
            .round_lost_len = 0,
            .round_lost_ranges = 0,
            .last_lost_number = null,
            .recovery_start_round = null,
            .window_len = initial_window_len,
            .prior_window_len = 0,
            .full_bw = 0,
            .full_bw_count = 0,
            .full_bw_now = false,
            .full_bw_reached = false,
            .drain_start_round = 0,
            .ack_phase = .init,
            .cycle_start_ns = 0,
            .bw_probe_wait_ns = 0,
            .rounds_since_probe_up = 0,
            .bw_probe_up_rounds = 0,
            .bw_probe_up_acked_len = 0,
            .probe_up_acked_per_increase_len = unbounded_len,
            .prev_probe_too_high = false,
            .prev_probe_precautionary = false,
            .is_bw_probe_sample = false,
            .inflight_longterm_len = unbounded_len,
            .bandwidth_probe_waits = bandwidth_probe_waits,
            .probe_waits_drawn = 0,
            .probe_rtt_done_at_ns = 0,
            .probe_rtt_round_done = false,
            .idle_restart = false,
        };
        state.model.init(now_ns);
        recovery_bbr_startup.enter_startup(state);
    }

    /// §5.2.3's `UpdateModelAndState`, on an ACK frame that took packets out of flight.
    /// `delivery` is the connection's, which ProbeRTT marks.
    pub fn on_ack(state: *Bbr, sample: Sample, path: Path, delivery: *recovery_delivery.Delivery) void {
        assert(path.datagram_len > 0);
        recovery_bbr_loss.update_latest_delivery_signals(state, sample);
        state.round_acknowledged_len +|= sample.acknowledged_len;
        // §5.5.10.3's `UpdateCongestionSignals` starts with `UpdateMaxBw`, which runs `UpdateRound`.
        state.model.update_max_bw(sample);
        // §5.5.1: "BBR.rounds_since_probe_up++" when a round starts.
        if (state.model.round_start) state.rounds_since_probe_up +|= 1;
        recovery_bbr_loss.update_congestion_signals(state);
        state.model.update_ack_aggregation(sample, path.now_ns, state.bw, state.window_len, state.full_bw_reached);
        recovery_bbr_startup.check_full_bw_reached(state, sample);
        recovery_bbr_loss.check_startup_high_loss(state, path);
        recovery_bbr_startup.check_startup_done(state);
        recovery_bbr_startup.check_drain_done(state, path);
        recovery_bbr_probe_bw.update_cycle_phase(state, sample, path);
        state.model.update_min_rtt(sample.rtt_ns, path.now_ns);
        recovery_bbr_probe_rtt.check(state, sample, path, delivery);
        recovery_bbr_loss.advance_latest_delivery_signals(state, sample);
        // §5.5.10.3's `BoundBWForModel`.
        state.bw = @min(state.model.max_bw, state.bw_shortterm);
        assert(state.bw <= state.model.max_bw);
    }

    /// §5.2.4: RFC 9002 §6.1 declared `lost` lost. `lost_len` is `C.lost`, which counts it.
    pub fn on_packet_lost(state: *Bbr, lost: recovery_sent.Record, lost_len: u64, application: bool, path: Path) void {
        recovery_bbr_loss.on_packet_lost(state, lost, lost_len, application, path);
    }

    /// §5.6.4.4's `OnEnterFastRecovery`: RFC 9002's recovery period started.
    pub fn on_enter_recovery(state: *Bbr, path: Path) void {
        recovery_bbr_loss.on_enter_recovery(state, path);
    }

    /// §5.2.5: `recovery_spurious.zig` found the loss episode spurious.
    pub fn on_spurious_loss(state: *Bbr, path: Path) void {
        recovery_bbr_loss.on_spurious_loss(state, path);
    }

    /// §5.2.2's `OnTransmit`: §5.4's `HandleRestartFromIdle`, before a packet goes out.
    pub fn on_transmit(state: *Bbr, path: Path, delivery: *const recovery_delivery.Delivery) void {
        recovery_bbr_probe_rtt.handle_restart_from_idle(state, path, delivery.application_limited_until != 0);
    }

    /// §5.3.3.9's `IsInAProbeBWState`.
    pub fn is_in_probe_bw(state: *const Bbr) bool {
        return switch (state.state) {
            .probe_bw_down, .probe_bw_cruise, .probe_bw_refill, .probe_bw_up => true,
            .startup, .drain, .probe_rtt => false,
        };
    }
};

test {
    _ = @import("recovery_bbr_test.zig");
    _ = @import("recovery_bbr_vectors_test.zig");
    _ = @import("recovery_bbr_probe_test.zig");
    _ = @import("recovery_bbr_loss_test.zig");
}
