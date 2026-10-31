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

comptime {
    // §5.5.7.2: the min_rtt filter covers an entire ProbeRTT cycle.
    assert(min_rtt_filter_len_ns > probe_rtt_interval_ns);
    assert(max_bw_filter_cycles == 2 and extra_acked_filter_rounds > 1);
    assert(min_rtt_filter_len_ns == 10 * core.constants.nanoseconds_per_second);
    assert(probe_rtt_interval_ns == 5 * core.constants.nanoseconds_per_second);
}
