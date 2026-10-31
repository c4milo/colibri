//! BBRv3's control parameters (draft-ietf-ccwg-bbr-06 §5.6). Part of design §8 step 29b.4.
//!
//! On each ACK frame, after the model and the states, BBR sets the three values a sender acts
//! on: the pacing rate (§5.6.2), the send quantum, which is the largest burst the pacer lets out
//! (§5.6.3), and the congestion window (§5.6.4). Every rate is in octets a second, and the
//! arithmetic is integer throughout (invariant 5).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("../../constants.zig");
const recovery_delivery = @import("../recovery_delivery.zig");
const recovery_bbr = @import("recovery_bbr.zig");
const recovery_bbr_inflight = @import("recovery_bbr_inflight.zig");

const Bbr = recovery_bbr.Bbr;
const Path = recovery_bbr.Path;
const Sample = recovery_delivery.Sample;
const bbr = constants.recovery.bbr;
const unbounded_len = recovery_bbr.unbounded_len;

/// `a * b / c` in 128 bits, held at the largest `u64`.
fn scale(a: u64, b: u64, c: u64) u64 {
    assert(c > 0);
    return @intCast(@min(@as(u128, a) * b / c, std.math.maxInt(u64)));
}

/// §5.6.2's `InitPacingRate`: the initial window over the smoothed round trip, or over 1 ms
/// before any sample, at Startup's gain.
pub fn init_pacing_rate(state: *Bbr, initial_window_len: u64, smoothed_rtt_ns: ?u64) void {
    const period_ns = smoothed_rtt_ns orelse bbr.initial_pacing_period_ns;
    assert(period_ns > 0);
    const nominal = scale(initial_window_len, core.constants.nanoseconds_per_second, period_ns);
    state.pacing_rate = scale(nominal, bbr.startup_pacing_gain, bbr.gain_denominator);
}

/// §5.6.2's `SetPacingRateWithGain`: `gain` hundredths of `BBR.bw`, 1% below it. Before the
/// pipe is full the rate only rises, so samples the application limited cannot lower it.
pub fn set_pacing_rate_with_gain(state: *Bbr, gain: u64) void {
    const margin = bbr.gain_denominator - bbr.pacing_margin;
    const rate = scale(scale(state.bw, gain, bbr.gain_denominator), margin, bbr.gain_denominator);
    if (state.full_bw_reached or rate > state.pacing_rate) state.pacing_rate = rate;
}

/// §5.6.3's `SetSendQuantum`: what the pacing rate sends in 1 ms, held between 2 maximum
/// datagrams and 64 KB.
pub fn set_send_quantum(state: *Bbr, datagram_len: u64) void {
    const quantum = scale(state.pacing_rate, bbr.send_quantum_period_ns, core.constants.nanoseconds_per_second);
    state.send_quantum_len = @max(@min(quantum, bbr.send_quantum_max_len), bbr.send_quantum_min_datagrams * datagram_len);
    assert(state.send_quantum_len >= bbr.send_quantum_min_datagrams * datagram_len);
}

/// §5.6.4.6's `SetCwnd`, with §5.6.4.2's `UpdateMaxInflight` first and §5.6.4.5's and §5.6.4.7's
/// bounds last.
pub fn set_window(state: *Bbr, sample: Sample, path: Path) void {
    // `UpdateMaxInflight`: the BDP at the cwnd gain, with the aggregation it absorbs.
    const cap_len = recovery_bbr_inflight.bdp_multiple(state, path, state.bw, state.cwnd_gain) +| state.model.extra_acked_len;
    state.max_inflight_len = recovery_bbr_inflight.quantization_budget(state, path, cap_len);
    const probe_rtt_cap_len = if (state.state == .probe_rtt) recovery_bbr_inflight.probe_rtt_window_len(state, path) else unbounded_len;
    state.window_len = next_window(.{
        .full_bw_reached = state.full_bw_reached,
        .window_len = state.window_len,
        .acknowledged_len = sample.acknowledged_len,
        .max_inflight_len = state.max_inflight_len,
        .delivered_len = path.delivered_len,
        .initial_window_len = path.initial_window_len,
        .min_pipe_len = recovery_bbr_inflight.min_pipe_len(path),
        .probe_rtt_cap_len = probe_rtt_cap_len,
        .model_cap_len = model_cap_len(state, path),
    });
}

/// What `SetCwnd` reads, apart from BBR's state.
pub const WindowInputs = struct {
    full_bw_reached: bool,
    window_len: u64,
    acknowledged_len: u64,
    max_inflight_len: u64,
    delivered_len: u64,
    initial_window_len: u64,
    min_pipe_len: u64,
    /// `ProbeRTTCwnd` in ProbeRTT, and unbounded otherwise. At least `min_pipe_len`.
    probe_rtt_cap_len: u64,
    /// `BoundCwndForModel`'s cap. At least `min_pipe_len`.
    model_cap_len: u64,
};

/// §5.6.4.6's `SetCwnd` as a function of what it reads: the window grows by what was
/// acknowledged toward `BBR.max_inflight`, and never falls below `BBR.MinPipeCwnd`.
pub fn next_window(in: WindowInputs) u64 {
    assert(in.probe_rtt_cap_len >= in.min_pipe_len and in.model_cap_len >= in.min_pipe_len);
    var window_len = in.window_len;
    if (in.full_bw_reached) {
        window_len = @min(window_len +| in.acknowledged_len, in.max_inflight_len);
    } else if (window_len < in.max_inflight_len or in.delivered_len < in.initial_window_len) {
        window_len +|= in.acknowledged_len;
    }
    window_len = @max(window_len, in.min_pipe_len);
    // §5.6.4.5's `BoundCwndForProbeRTT`, then §5.6.4.7's `BoundCwndForModel`.
    window_len = @min(window_len, in.probe_rtt_cap_len, in.model_cap_len);
    assert(window_len >= in.min_pipe_len);
    return window_len;
}

/// §5.6.4.7's `BoundCwndForModel`: the bound of the state, and the short-term model's.
fn model_cap_len(state: *const Bbr, path: Path) u64 {
    var cap = unbounded_len;
    if (state.is_in_probe_bw() and state.state != .probe_bw_cruise) {
        cap = state.inflight_longterm_len;
    } else if (state.state == .probe_rtt or state.state == .probe_bw_cruise) {
        cap = recovery_bbr_inflight.inflight_with_headroom(state, path);
    }
    cap = @min(cap, state.inflight_shortterm_len);
    return @max(cap, recovery_bbr_inflight.min_pipe_len(path));
}

/// §5.2.3's `UpdateControlParameters`, after `UpdateModelAndState`. `smoothed_rtt_ns` is RFC
/// 9002's estimate once it has a sample: §5.6.2 starts the pacing rate again from the first one.
pub fn update(state: *Bbr, sample: Sample, path: Path, smoothed_rtt_ns: ?u64) void {
    if (!state.has_seen_rtt and smoothed_rtt_ns != null) {
        state.has_seen_rtt = true;
        init_pacing_rate(state, path.initial_window_len, smoothed_rtt_ns);
    }
    set_pacing_rate_with_gain(state, state.pacing_gain);
    set_send_quantum(state, path.datagram_len);
    set_window(state, sample, path);
}

/// §5.4.1: after an idle period in ProbeBW, BBR paces at its estimate, with a gain of 1.
pub fn on_restart_from_idle(state: *Bbr) void {
    if (state.is_in_probe_bw()) set_pacing_rate_with_gain(state, bbr.gain_denominator);
}
