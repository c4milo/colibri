//! BBRv3's model of the path (draft-ietf-ccwg-bbr-06 §5.5.1 to §5.5.9). Part of design §8 step
//! 29b.1.
//!
//! BBR estimates the bottleneck rate and the round-trip propagation delay of the path from the
//! rate samples of `recovery_delivery.zig`. This file holds the estimates and the counts they
//! are kept over:
//! - BBR.round_count, the packet-timed round trips (§5.5.1).
//! - BBR.max_bw, the largest rate sample over the last 2 bandwidth probe cycles (§5.5.2 to
//!   §5.5.6).
//! - BBR.min_rtt, the smallest round trip over the last 10 s (§5.5.7, §5.3.4.3).
//! - BBR.extra_acked, the octets that come back acknowledged in a burst (§5.5.9).
//!
//! The states of §5.3 call these functions, and decide when a probe cycle ends. Every instant is
//! a parameter (non-negotiable 3), and the arithmetic is integer throughout (invariant 5).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("../constants.zig");
const recovery_bbr_filter = @import("recovery_bbr_filter.zig");
const recovery_delivery = @import("recovery_delivery.zig");

const Sample = recovery_delivery.Sample;
const bbr = constants.recovery.bbr;

/// The draft's "Infinity", for BBR.min_rtt before any sample.
pub const rtt_unknown_ns: u64 = std.math.maxInt(u64);

pub const Model = struct {
    /// §5.5.1: `BBR.next_round_delivered`, `BBR.round_start` and `BBR.round_count`.
    next_round_delivered_len: u64,
    round_start: bool,
    round_count: u64,
    /// §5.5.5: `BBR.max_bw` in octets a second, its filter, and §5.5.6's `BBR.cycle_count`.
    max_bw: u64,
    max_bw_filter: recovery_bbr_filter.MaxFilter(bbr.max_bw_filter_cycles),
    cycle_count: u64,
    /// §5.3.4.3: `BBR.min_rtt` and `BBR.min_rtt_stamp`.
    min_rtt_ns: u64,
    min_rtt_at_ns: u64,
    /// §5.3.4.3: `BBR.probe_rtt_min_delay`, `BBR.probe_rtt_min_stamp` and
    /// `BBR.probe_rtt_expired`.
    probe_rtt_min_delay_ns: u64,
    probe_rtt_min_at_ns: u64,
    probe_rtt_expired: bool,
    /// §5.5.9: `BBR.extra_acked`, `BBR.extra_acked_interval_start`, `BBR.extra_acked_delivered`
    /// and `BBR.extra_acked_filter`.
    extra_acked_len: u64,
    extra_acked_interval_start_ns: u64,
    extra_acked_delivered_len: u64,
    extra_acked_filter: recovery_bbr_filter.MaxFilter(bbr.extra_acked_filter_rounds),

    /// §5.2.1's `OnInit` for the model, and §5.5.1's `InitRoundCounting`. A connection starts
    /// with no round trip sample, so BBR.min_rtt starts at the draft's "Infinity".
    pub fn init(model: *Model, now_ns: u64) void {
        model.* = .{
            .next_round_delivered_len = 0,
            .round_start = false,
            .round_count = 0,
            .max_bw = 0,
            .max_bw_filter = undefined,
            .cycle_count = 0,
            .min_rtt_ns = rtt_unknown_ns,
            .min_rtt_at_ns = now_ns,
            .probe_rtt_min_delay_ns = rtt_unknown_ns,
            .probe_rtt_min_at_ns = now_ns,
            .probe_rtt_expired = false,
            .extra_acked_len = 0,
            .extra_acked_interval_start_ns = now_ns,
            .extra_acked_delivered_len = 0,
            .extra_acked_filter = undefined,
        };
        model.max_bw_filter.init();
        model.extra_acked_filter.init();
    }

    /// §5.5.1's `UpdateRound`: a round trip ends when the peer acknowledges a packet sent after
    /// the round began. §5.3's states count `BBR.rounds_since_probe_up` from `round_start`.
    pub fn update_round(model: *Model, sample: Sample) void {
        if (sample.prior_delivered_len >= model.next_round_delivered_len) {
            // §5.5.1's `StartRound`: "BBR.next_round_delivered = C.delivered".
            model.next_round_delivered_len = sample.prior_delivered_len + sample.delivered_len;
            model.round_count += 1;
            model.round_start = true;
        } else {
            model.round_start = false;
        }
        assert(model.next_round_delivered_len >= sample.prior_delivered_len);
    }

    /// §5.5.5's `UpdateMaxBw`, which runs `UpdateRound` first.
    pub fn update_max_bw(model: *Model, sample: Sample) void {
        model.update_round(sample);
        // §5.5.4: an application-limited sample counts only when it is above the estimate.
        if (sample.rate > 0 and (sample.rate >= model.max_bw or !sample.application_limited)) {
            model.max_bw = model.max_bw_filter.update(sample.rate, model.cycle_count, bbr.max_bw_filter_cycles);
        }
        assert(model.max_bw >= sample.rate);
    }

    /// §5.5.6's `AdvanceMaxBwFilter`: one bandwidth probe cycle has ended.
    pub fn advance_max_bw_filter(model: *Model) void {
        model.cycle_count += 1;
    }

    /// §5.3.4.3's `UpdateMinRTT`, on every ACK frame. `rtt_ns` is the sample's `RS.rtt`, or null
    /// when the frame took nothing out of flight, which the draft writes as `RS.rtt = -1`.
    pub fn update_min_rtt(model: *Model, rtt_ns: ?u64, now_ns: u64) void {
        assert(now_ns >= model.probe_rtt_min_at_ns and now_ns >= model.min_rtt_at_ns);
        model.probe_rtt_expired = now_ns > model.probe_rtt_min_at_ns +| bbr.probe_rtt_interval_ns;
        if (rtt_ns) |rtt| {
            if (rtt < model.probe_rtt_min_delay_ns or model.probe_rtt_expired) {
                model.probe_rtt_min_delay_ns = rtt;
                model.probe_rtt_min_at_ns = now_ns;
            }
        }
        const min_rtt_expired = now_ns > model.min_rtt_at_ns +| bbr.min_rtt_filter_len_ns;
        if (model.probe_rtt_min_delay_ns < model.min_rtt_ns or min_rtt_expired) {
            model.min_rtt_ns = model.probe_rtt_min_delay_ns;
            model.min_rtt_at_ns = model.probe_rtt_min_at_ns;
        }
        assert(model.min_rtt_ns <= model.probe_rtt_min_delay_ns);
    }

    /// §5.5.9's `UpdateACKAggregation`. `bw` is `BBR.bw` in octets a second, `window_len` is
    /// `C.cwnd`, and `full_bw_reached` says whether Startup has ended (§5.3.1).
    pub fn update_ack_aggregation(model: *Model, sample: Sample, now_ns: u64, bw: u64, window_len: u64, full_bw_reached: bool) void {
        assert(now_ns >= model.extra_acked_interval_start_ns);
        // "Find excess ACKed beyond expected amount over this interval".
        var expected_len = expected_delivered_len(bw, now_ns - model.extra_acked_interval_start_ns);
        // "Reset interval if ACK rate is below expected rate".
        if (model.extra_acked_delivered_len <= expected_len) {
            model.extra_acked_delivered_len = 0;
            model.extra_acked_interval_start_ns = now_ns;
            expected_len = 0;
        }
        model.extra_acked_delivered_len +|= sample.acknowledged_len;
        const extra_len = @min(model.extra_acked_delivered_len -| expected_len, window_len);
        // "in Startup, just remember 1 round".
        const window: u64 = if (full_bw_reached) bbr.extra_acked_filter_rounds else 1;
        model.extra_acked_len = model.extra_acked_filter.update(extra_len, model.round_count, window);
        assert(extra_len <= window_len);
    }
};

/// §5.5.9's `expected_delivered`: the octets `bw` octets a second deliver in `interval_ns`. The
/// product is taken in 128 bits, and the quotient saturates at the largest `u64`.
pub fn expected_delivered_len(bw: u64, interval_ns: u64) u64 {
    const expected = @as(u128, bw) * interval_ns / core.constants.nanoseconds_per_second;
    return @intCast(@min(expected, std.math.maxInt(u64)));
}

/// §5.5.8.2's `UpdateOffloadBudget` for QUIC: the send quantum. colibri owns no socket, so it
/// cannot know whether the caller's sends offload pacing, and adds nothing for it (the owner's
/// ruling of 2026-10-30, design §8 step 29b.1).
pub fn offload_budget_len(send_quantum_len: u64) u64 {
    return send_quantum_len;
}

test {
    _ = @import("recovery_bbr_model_test.zig");
}
