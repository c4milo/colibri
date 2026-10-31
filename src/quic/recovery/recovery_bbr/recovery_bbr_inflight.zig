//! The volumes BBRv3's states compare with the octets in flight (draft-ietf-ccwg-bbr-06
//! §5.6.4.2, §5.3.3.9, §5.5.10.2). Part of design §8 step 29b.2.
//!
//! Each volume is in octets, from BBR's model of the path and the gains of the state. Every
//! product is taken in 128 bits and saturates at the largest `u64`, which is also the draft's
//! "Infinity" for a volume that nothing bounds.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("../../constants.zig");
const recovery_delivery = @import("../recovery_delivery.zig");
const recovery_bbr = @import("recovery_bbr.zig");
const recovery_bbr_model = @import("recovery_bbr_model.zig");

const Bbr = recovery_bbr.Bbr;
const Path = recovery_bbr.Path;
const Sample = recovery_delivery.Sample;
const bbr = constants.recovery.bbr;
const unbounded_len = recovery_bbr.unbounded_len;

/// `a * b / c` in 128 bits, held at the largest `u64`.
fn scale(a: u64, b: u64, c: u64) u64 {
    assert(c > 0);
    const product = @as(u128, a) * b / c;
    return @intCast(@min(product, std.math.maxInt(u64)));
}

/// §2.8's `BBR.MinPipeCwnd`: 4 maximum datagrams.
pub fn min_pipe_len(path: Path) u64 {
    return bbr.min_pipe_cwnd_datagrams * path.datagram_len;
}

/// §5.6.4.2's `BBRBDPMultiple`: `gain` hundredths of the BDP of `bw` over BBR.min_rtt, or
/// `C.InitialCwnd` before any round trip sample.
pub fn bdp_multiple(state: *const Bbr, path: Path, bw: u64, gain: u64) u64 {
    if (state.model.min_rtt_ns == recovery_bbr_model.rtt_unknown_ns) return path.initial_window_len;
    const bdp_len = scale(bw, state.model.min_rtt_ns, core.constants.nanoseconds_per_second);
    return scale(bdp_len, gain, bbr.gain_denominator);
}

/// §5.6.4.2's `BBRQuantizationBudget`: at least the offload budget and `BBR.MinPipeCwnd`, and 2
/// datagrams more in ProbeBW_UP.
pub fn quantization_budget(state: *const Bbr, path: Path, inflight_cap_len: u64) u64 {
    var cap = @max(inflight_cap_len, recovery_bbr_model.offload_budget_len(path.send_quantum_len));
    cap = @max(cap, min_pipe_len(path));
    if (state.state == .probe_bw_up) cap +|= bbr.probe_bw_up_quantization_datagrams * path.datagram_len;
    assert(cap >= min_pipe_len(path));
    return cap;
}

/// §5.6.4.2's `BBRInflight`, with the rate the caller names: `BBRInflight(gain)` uses `BBR.bw`,
/// and §5.3.3.9's `IsTimeToCruise` uses `BBR.max_bw`.
pub fn inflight(state: *const Bbr, path: Path, bw: u64, gain: u64) u64 {
    return quantization_budget(state, path, bdp_multiple(state, path, bw, gain));
}

/// §5.3.3.9's `InflightWithHeadroom`: BBR.inflight_longterm less 15% of it, and at least one
/// datagram less, but never below `BBR.MinPipeCwnd`.
pub fn inflight_with_headroom(state: *const Bbr, path: Path) u64 {
    if (state.inflight_longterm_len == unbounded_len) return unbounded_len;
    const headroom_len = @max(path.datagram_len, scale(state.inflight_longterm_len, bbr.headroom, bbr.gain_denominator));
    return @max(state.inflight_longterm_len -| headroom_len, min_pipe_len(path));
}

/// §5.3.3.8.2's `TargetInflight`: the BDP, unless the window is smaller.
pub fn target_inflight(state: *const Bbr, path: Path) u64 {
    return @min(bdp_multiple(state, path, state.bw, bbr.gain_denominator), state.window_len);
}

/// §5.6.4.5's `ProbeRTTCwnd`: half the BDP, and at least `BBR.MinPipeCwnd`.
pub fn probe_rtt_window_len(state: *const Bbr, path: Path) u64 {
    return @max(bdp_multiple(state, path, state.bw, bbr.probe_rtt_cwnd_gain), min_pipe_len(path));
}

/// §5.5.10.2's `IsInflightTooHigh`: the packets lost since the newest acknowledged packet went
/// out are above 2% of what was then in flight. Its second clause, a loss without selective
/// acknowledgments, never holds: every QUIC ACK frame is selective (RFC 9000 §19.3).
pub fn is_inflight_too_high(sample: Sample) bool {
    return @as(u128, sample.lost_len) * bbr.gain_denominator > @as(u128, sample.tx_in_flight_len) * bbr.loss_threshold;
}
