//! BBRv3's constants (draft-ietf-ccwg-bbr-06, decision 134), which `constants_recovery.zig`
//! exports as `bbr`. Each fraction of the draft is a numerator and a denominator, because
//! colibri's arithmetic is integer (non-negotiable 5).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");

/// §2.11: `BBR.MaxBwFilterLen`, the bandwidth probe cycles BBR.max_bw remembers: the current
/// cycle and the previous one.
pub const max_bw_filter_cycles: u64 = 2;

/// §2.12: `BBR.ExtraAckedFilterLen`, the round trips BBR.extra_acked remembers once Startup has
/// ended. In Startup it remembers 1 (§5.5.9).
pub const extra_acked_filter_rounds: u64 = 10;

/// §2.16.1: `BBR.MinRTTFilterLen`, how long a BBR.min_rtt sample stays valid.
pub const min_rtt_filter_len_ns: u64 = 10_000_000_000;

/// §2.16.2: `BBR.ProbeRTTInterval`, how long a BBR.probe_rtt_min_delay sample stays valid.
pub const probe_rtt_interval_ns: u64 = 5_000_000_000;

/// The denominator of every gain and factor below: each is a count of hundredths, so 2.77 is 277
/// (the owner's ruling of 2026-10-30, design §8 step 29b).
pub const gain_denominator: u64 = 100;

/// §2.5: `BBR.StartupPacingGain`, 4 × ln(2) ≈ 2.77, and `BBR.DrainPacingGain`, 0.5.
pub const startup_pacing_gain: u64 = 277;
pub const drain_pacing_gain: u64 = 50;
/// §2.6: `BBR.DefaultCwndGain`, 2.
pub const default_cwnd_gain: u64 = 200;
/// §5.6.1's table: the pacing gains of ProbeBW_DOWN, of ProbeBW_CRUISE and ProbeBW_REFILL, and
/// of ProbeBW_UP, and ProbeBW_UP's cwnd gain.
pub const probe_bw_down_pacing_gain: u64 = 90;
pub const probe_bw_steady_pacing_gain: u64 = 100;
pub const probe_bw_up_pacing_gain: u64 = 125;
pub const probe_bw_up_cwnd_gain: u64 = 225;
/// §2.16.2: `BBR.ProbeRTTCwndGain`, 0.5. ProbeRTT paces at a gain of 1 (§5.3.4.3).
pub const probe_rtt_cwnd_gain: u64 = 50;
pub const probe_rtt_pacing_gain: u64 = 100;

/// §5.3.1.2: a round whose rate grows by less than 1.25 times counts toward a full pipe, and
/// three such rounds fill it.
pub const full_bw_growth: u64 = 125;
pub const full_bw_rounds: u8 = 3;

/// §5.3.2: Drain ends at the latest 3 rounds after it starts.
pub const drain_rounds: u64 = 3;

/// §2.8: `BBR.LossThresh`, 2%, and `BBR.Headroom`, 0.15.
pub const loss_threshold: u64 = 2;
pub const headroom: u64 = 15;

/// §2.8: `BBR.Beta`, 0.7: what each round with loss scales the short-term model by.
pub const beta: u64 = 70;

/// §5.3.1.3: `BBRStartupFullLossCnt`, the lost ranges a round must hold before Startup ends on
/// loss, and the rounds of loss recovery it waits first: the round the recovery started in, and
/// one full round after it.
pub const startup_full_loss_ranges: u8 = 6;
pub const startup_recovery_rounds: u64 = 2;

/// §2.8: `BBR.MinPipeCwnd`, in maximum datagrams.
pub const min_pipe_cwnd_datagrams: u64 = 4;

/// §5.6.4.2: ProbeBW_UP adds 2 maximum datagrams to the quantization budget.
pub const probe_bw_up_quantization_datagrams: u64 = 2;

/// §5.3.3.9: `BBR.bw_probe_up_rounds` stops at 30, so the growth of BBR.inflight_longterm in one
/// round stays below 2^31 datagrams.
pub const bw_probe_up_rounds_max: u6 = 30;

/// §2.16.2: `BBR.ProbeRTTDuration`, 200 ms.
pub const probe_rtt_duration_ns: u64 = 200_000_000;

/// §5.3.3.8.2: a bandwidth probe waits 2 s plus a draw below 1 s, or at most 63 round trips, less
/// a draw of 0 or 1.
pub const probe_wait_min_ns: u64 = 2_000_000_000;
pub const probe_wait_spread_ns: u64 = 1_000_000_000;
pub const reno_rounds_max: u64 = 63;

/// The SplitMix64 increment, 2^64 divided by the golden ratio, rounded to odd: the count of
/// waits times it, added to `bandwidth_probe_waits`, is what each wait mixes (decision 136, the
/// owner's ruling of 2026-10-31).
pub const probe_wait_increment: u64 = 0x9e3779b97f4a7c15;

/// The SplitMix64 finalizer's two multipliers and three shifts, which mix each wait's input so
/// each bit of the output depends on each bit of the input.
pub const splitmix_first_multiplier: u64 = 0xbf58476d1ce4e5b9;
pub const splitmix_second_multiplier: u64 = 0x94d049bb133111eb;
pub const splitmix_first_shift: u6 = 30;
pub const splitmix_second_shift: u6 = 27;
pub const splitmix_third_shift: u6 = 31;

comptime {
    // §5.5.7.2: the min_rtt filter covers an entire ProbeRTT cycle.
    assert(min_rtt_filter_len_ns > probe_rtt_interval_ns);
    assert(max_bw_filter_cycles == 2 and extra_acked_filter_rounds > 1);
    assert(min_rtt_filter_len_ns == 10 * core.constants.nanoseconds_per_second);
    assert(probe_rtt_interval_ns == 5 * core.constants.nanoseconds_per_second);
    assert(probe_rtt_duration_ns < probe_rtt_interval_ns);
    // §2.5: "any value at or below 1 / BBRStartupCwndGain" drains the queue.
    assert(drain_pacing_gain * default_cwnd_gain <= gain_denominator * gain_denominator);
    assert(probe_wait_min_ns + probe_wait_spread_ns < min_rtt_filter_len_ns);
    assert(loss_threshold < gain_denominator and headroom < gain_denominator and beta < gain_denominator);
}
