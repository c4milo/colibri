//! The round trip estimator of RFC 9002 §5, and the Probe Timeout §6.2.1 computes from it.
//! Part of design §8 step 10.
//!
//! Four numbers: the latest sample, the smallest ever seen, an exponentially weighted moving
//! average, and a mean variation of that average. RFC 9002 §5 defines all four and §6.2.1 turns
//! the last two into the timeout that drives loss recovery.
//!
//! Every instant is a parameter. RFC 9002's pseudocode reads `now()` at nine sites and colibri
//! reads no clock (non-negotiable 3), so a sample arrives already measured: the caller knows
//! when it sent the packet and when the acknowledgment came, and hands over the difference.
//!
//! **RFC 9002 disagrees with itself here, and the disagreement is decided rather than hidden.**
//! §5.3 updates `smoothed_rtt` and then computes the variation against the new value; Appendix
//! A.7 computes the variation against the old value and then updates. They give different
//! numbers on every sample after the first. `update` follows Appendix A.7, and
//! [decision 50](../../docs/decisions.md) records why.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");

/// Everything a sample needs beyond its own measurement (RFC 9002 §5.3).
pub const Sample = struct {
    /// The round trip as the caller measured it: the instant the acknowledgment was processed
    /// less the instant the largest newly acknowledged packet was sent (RFC 9002 §5.1).
    rtt_ns: u64,
    /// The ACK Delay the peer reported, already decoded by its `ack_delay_exponent`
    /// (RFC 9000 §19.3). RFC 9002 §5.3 permits ignoring it for Initial packets, which the
    /// caller does by passing 0.
    ack_delay_ns: u64,
    /// RFC 9002 §5.3: until the handshake is confirmed the peer's `max_ack_delay` is not
    /// applied, because a delay larger than it is expected then and is not repeating.
    handshake_confirmed: bool,
    /// The instant the acknowledgment was processed, which is the instant `rtt_ns` was measured
    /// from. RFC 9002 Appendix A.3 keeps it as `first_rtt_sample` for the first sample alone,
    /// because §7.6.2 counts a packet toward persistent congestion only if it was sent after it.
    taken_at_ns: u64,
};

pub const Rtt = struct {
    /// RFC 9002 §5.1: the most recent sample, before any adjustment.
    latest_ns: u64,
    /// RFC 9002 §5.2: the smallest sample seen on this path, which ignores acknowledgment
    /// delay entirely, so it is the floor an adjusted sample may not go below.
    min_ns: u64,
    /// RFC 9002 §5.3: the exponentially weighted moving average, and the mean variation of it.
    smoothed_ns: u64,
    variation_ns: u64,
    /// RFC 9002 Appendix A.3's `first_rtt_sample`: when the first sample since the estimator was
    /// initialized or reset arrived, or null when none has.
    first_sample_at_ns: ?u64,
    /// The peer's `max_ack_delay` (RFC 9000 §18.2), in nanoseconds. It is the peer's advertised
    /// value and not a limit of colibri's, so it arrives with the transport parameters; absent,
    /// §18.2 assumes 25 milliseconds, which `init` uses until the caller knows better.
    peer_max_ack_delay_ns: u64,

    /// RFC 9002 §5.3: before any sample the estimator holds the initial round trip, and the
    /// variation is half of it.
    pub fn init(rtt: *Rtt) void {
        rtt.* = .{
            .latest_ns = 0,
            .min_ns = 0,
            .smoothed_ns = constants.rtt_initial_ns,
            .variation_ns = constants.rtt_initial_ns / constants.rtt_initial_variation_divisor,
            .first_sample_at_ns = null,
            .peer_max_ack_delay_ns = constants.max_ack_delay_default_ns,
        };
    }

    /// RFC 9002 §5.3, RFC 9000 §9.4: the estimator is reset when the connection migrates, so it
    /// keeps no history of a path it has left. What the peer advertised is not path history and
    /// stays.
    pub fn reset(rtt: *Rtt) void {
        const advertised_ns = rtt.peer_max_ack_delay_ns;
        rtt.init();
        rtt.peer_max_ack_delay_ns = advertised_ns;
    }

    /// Whether any sample has arrived since the estimator was initialized or reset.
    pub fn has_sample(rtt: *const Rtt) bool {
        return rtt.first_sample_at_ns != null;
    }

    /// Takes the peer's `max_ack_delay` from its transport parameters (RFC 9000 §18.2), in
    /// milliseconds as the parameter carries it.
    pub fn set_peer_max_ack_delay(rtt: *Rtt, milliseconds: u64) void {
        // RFC 9000 §18.2: values of 2^14 or greater are invalid, which the caller has refused.
        assert(milliseconds < constants.max_ack_delay_invalid_at);
        rtt.peer_max_ack_delay_ns = milliseconds *| constants.nanoseconds_per_millisecond;
    }

    /// Takes one round trip sample (RFC 9002 §5.3, Appendix A.7).
    pub fn update(rtt: *Rtt, sample: Sample) void {
        rtt.latest_ns = sample.rtt_ns;
        // RFC 9002 §5.3: on the first sample after initialization the estimator is reset to it,
        // so no part of the initial value survives into a measured path.
        if (rtt.first_sample_at_ns == null) {
            rtt.first_sample_at_ns = sample.taken_at_ns;
            rtt.min_ns = sample.rtt_ns;
            rtt.smoothed_ns = sample.rtt_ns;
            rtt.variation_ns = sample.rtt_ns / constants.rtt_initial_variation_divisor;
            return;
        }
        // RFC 9002 §5.2: min_rtt ignores acknowledgment delay, so it takes the sample as it came.
        // Appendix A.7 updates it before computing the adjusted sample, and this follows that
        // order. Neither the order nor the choice of sample changes an answer: `adjusted` returns
        // either the sample itself or a value at or above min_rtt, so both give the same minimum.
        rtt.min_ns = @min(rtt.min_ns, sample.rtt_ns);
        const adjusted_ns = rtt.adjusted(sample);
        // RFC 9002 Appendix A.7: the variation is computed against the smoothed value as it
        // stands, before this sample moves it. §5.3's prose does it the other way; decision 50
        // records the choice.
        const difference_ns = if (rtt.smoothed_ns > adjusted_ns)
            rtt.smoothed_ns - adjusted_ns
        else
            adjusted_ns - rtt.smoothed_ns;
        rtt.variation_ns = weighted(rtt.variation_ns, difference_ns, constants.rtt_variation_weight);
        rtt.smoothed_ns = weighted(rtt.smoothed_ns, adjusted_ns, constants.rtt_smoothed_weight);
    }

    /// The sample less the acknowledgment delay, where RFC 9002 §5.3 permits subtracting it.
    fn adjusted(rtt: *const Rtt, sample: Sample) u64 {
        var ack_delay_ns = sample.ack_delay_ns;
        // RFC 9002 §5.3: after the handshake is confirmed an endpoint MUST use the lesser of the
        // reported delay and the peer's max_ack_delay.
        if (sample.handshake_confirmed) ack_delay_ns = @min(ack_delay_ns, rtt.peer_max_ack_delay_ns);
        // RFC 9002 §5.3: an endpoint MUST NOT subtract the delay if the result would be below
        // min_rtt, which is what limits how far a misreporting peer can pull the estimate down.
        if (sample.rtt_ns < rtt.min_ns +| ack_delay_ns) return sample.rtt_ns;
        return sample.rtt_ns - ack_delay_ns;
    }

    /// The Probe Timeout of RFC 9002 §6.2.1: the estimate, four times its variation, and the
    /// delay a receiver may add. `include_max_ack_delay` is false for the Initial and Handshake
    /// spaces, where §6.2.1 sets that term to 0 because a peer does not delay those on purpose.
    pub fn probe_timeout_ns(rtt: *const Rtt, include_max_ack_delay: bool) u64 {
        const variation_ns = @max(constants.rtt_variation_factor *| rtt.variation_ns, constants.rtt_granularity_ns);
        const delay_ns = if (include_max_ack_delay) rtt.peer_max_ack_delay_ns else 0;
        const period_ns = rtt.smoothed_ns +| variation_ns +| delay_ns;
        // RFC 9002 §6.2.1: the period MUST be at least the timer granularity, so it cannot
        // expire the instant it is armed.
        return @max(period_ns, constants.rtt_granularity_ns);
    }

    /// RFC 9002 §7.6.1: how long every packet over a span must be lost before the span counts as
    /// persistent congestion. It is the Probe Timeout times a threshold, and §7.6.1 states that
    /// unlike §6.2's timeout this one carries `max_ack_delay` whatever space the losses are in.
    pub fn persistent_congestion_ns(rtt: *const Rtt) u64 {
        return rtt.probe_timeout_ns(true) *| constants.persistent_congestion_threshold;
    }

    /// The instant past which a packet is lost by the time threshold of RFC 9002 §6.1.2: nine
    /// eighths of the larger of the latest and smoothed estimates, never below the granularity.
    pub fn loss_delay_ns(rtt: *const Rtt) u64 {
        const estimate_ns = @max(rtt.latest_ns, rtt.smoothed_ns);
        const scaled_ns = (estimate_ns *| constants.loss_time_threshold_numerator) /
            constants.loss_time_threshold_denominator;
        // RFC 9002 §6.1.2: the delay is at least the granularity, so a timer cannot expire early.
        return @max(scaled_ns, constants.rtt_granularity_ns);
    }
};

/// One step of an exponentially weighted moving average: `weight - 1` parts of what is held to
/// one part of what arrived (RFC 9002 §5.3). Done in this order so the division truncates once,
/// which keeps one host's answer every host's (invariant 5).
fn weighted(held_ns: u64, sample_ns: u64, weight: u64) u64 {
    assert(weight > 1);
    const kept = held_ns *| (weight - 1);
    return (kept +| sample_ns) / weight;
}

const testing = std.testing;

/// The estimator the tests drive, and the instants they measure in. Test-only.
var test_rtt: Rtt = undefined;
const millisecond = constants.nanoseconds_per_millisecond;

/// A sample with no reported delay, which is what an Initial packet's acknowledgment gives.
fn plain(rtt_ns: u64) Sample {
    return .{
        .rtt_ns = rtt_ns,
        .ack_delay_ns = 0,
        .handshake_confirmed = false,
        .taken_at_ns = test_taken_at_ns,
    };
}

/// The instant every test sample was measured at. Test-only.
const test_taken_at_ns: u64 = constants.rtt_initial_ns;

test "§5.3: the first sample replaces the initial estimate entirely" {
    test_rtt.init();
    // Before any sample the estimator holds §6.2.2's recommended initial round trip.
    try testing.expectEqual(constants.rtt_initial_ns, test_rtt.smoothed_ns);
    try testing.expectEqual(constants.rtt_initial_ns / 2, test_rtt.variation_ns);
    try testing.expect(!test_rtt.has_sample());
    // The first sample is taken whole: no part of 333 ms survives into a measured path.
    test_rtt.update(plain(40 * millisecond));
    try testing.expectEqual(40 * millisecond, test_rtt.latest_ns);
    try testing.expectEqual(40 * millisecond, test_rtt.min_ns);
    try testing.expectEqual(40 * millisecond, test_rtt.smoothed_ns);
    try testing.expectEqual(20 * millisecond, test_rtt.variation_ns);
    try testing.expect(test_rtt.has_sample());
}

test "§5.3: a later sample moves the estimate an eighth and the variation a quarter" {
    test_rtt.init();
    test_rtt.update(plain(100 * millisecond));
    try testing.expectEqual(50 * millisecond, test_rtt.variation_ns);
    // smoothed = 7/8 * 100 + 1/8 * 140 = 105; variation = 3/4 * 50 + 1/4 * |100 - 140| = 47.5.
    test_rtt.update(plain(140 * millisecond));
    try testing.expectEqual(105 * millisecond, test_rtt.smoothed_ns);
    try testing.expectEqual(47 * millisecond + 500_000, test_rtt.variation_ns);
    // The latest sample is held unadjusted, and min_rtt keeps the smaller of the two.
    try testing.expectEqual(140 * millisecond, test_rtt.latest_ns);
    try testing.expectEqual(100 * millisecond, test_rtt.min_ns);
}

test "decision 50: the variation is measured before the sample moves the estimate" {
    // Design §12 question 4. §5.3 and Appendix A.7 order the two assignments differently, and
    // this pins which one colibri computes. The numbers are decision 50's worked example.
    test_rtt.init();
    test_rtt.update(plain(100 * millisecond));
    test_rtt.variation_ns = 25 * millisecond;
    test_rtt.update(plain(140 * millisecond));
    // Appendix A.7: 3/4 * 25 + 1/4 * |100 - 140| = 28.75.
    const appendix_ns = 28 * millisecond + 750_000;
    try testing.expectEqual(appendix_ns, test_rtt.variation_ns);
    // §5.3 would have measured against the updated 105 ms: 3/4 * 25 + 1/4 * 35 = 27.5.
    const prose_ns = 27 * millisecond + 500_000;
    try testing.expect(appendix_ns > prose_ns);
    // The two differ by an exact factor: §5.3's term is seven eighths of the appendix's, because
    // 7/8 S + 1/8 A - A is 7/8 (S - A). The difference is a quarter of an eighth of |S - A|.
    const quarter_of_eighth_ns = (40 * millisecond) / 32;
    try testing.expectEqual(prose_ns + quarter_of_eighth_ns, appendix_ns);
    // §6.2.1 carries four times the variation, so the choice is worth 5 ms of timeout here.
    try testing.expectEqual(105 * millisecond + 4 * appendix_ns, test_rtt.probe_timeout_ns(false));
}

test "§5.3: the reported delay is subtracted only where it may be" {
    // min_rtt is 30 ms here, so both adjusted samples below stay above it and the floor of the
    // test that follows this one does not decide the answer.
    test_rtt.init();
    test_rtt.update(plain(30 * millisecond));
    // Before the handshake is confirmed the peer's max_ack_delay does not bound the report, so
    // all 60 ms comes off: 7/8 * 30 + 1/8 * 40 = 31.25.
    test_rtt.update(.{
        .rtt_ns = 100 * millisecond,
        .ack_delay_ns = 60 * millisecond,
        .handshake_confirmed = false,
        .taken_at_ns = test_taken_at_ns,
    });
    try testing.expectEqual(31 * millisecond + 250_000, test_rtt.smoothed_ns);
    // After it is confirmed the same report is clamped to the peer's 25 ms, so the adjusted
    // sample is 75 ms rather than 40 ms: 7/8 * 30 + 1/8 * 75 = 35.625.
    test_rtt.init();
    test_rtt.update(plain(30 * millisecond));
    test_rtt.update(.{
        .rtt_ns = 100 * millisecond,
        .ack_delay_ns = 60 * millisecond,
        .handshake_confirmed = true,
        .taken_at_ns = test_taken_at_ns,
    });
    try testing.expectEqual(35 * millisecond + 625_000, test_rtt.smoothed_ns);
}

test "§5.3: subtracting the delay may not take the sample below min_rtt" {
    test_rtt.init();
    test_rtt.update(plain(100 * millisecond));
    // A peer reporting a delay that would put the sample under the smallest ever seen is
    // ignored: the sample is taken whole, which is what bounds how far it can pull the estimate.
    test_rtt.update(.{
        .rtt_ns = 110 * millisecond,
        .ack_delay_ns = 90 * millisecond,
        .handshake_confirmed = false,
        .taken_at_ns = test_taken_at_ns,
    });
    try testing.expectEqual(101 * millisecond + 250_000, test_rtt.smoothed_ns);
    // Exactly at min_rtt the subtraction stands: 110 - 10 = 100.
    test_rtt.init();
    test_rtt.update(plain(100 * millisecond));
    test_rtt.update(.{
        .rtt_ns = 110 * millisecond,
        .ack_delay_ns = 10 * millisecond,
        .handshake_confirmed = false,
        .taken_at_ns = test_taken_at_ns,
    });
    try testing.expectEqual(100 * millisecond, test_rtt.smoothed_ns);
}

test "§5.2: min_rtt is of the sample as it came, and only ever falls" {
    test_rtt.init();
    test_rtt.update(plain(100 * millisecond));
    // A larger sample with a large reported delay would adjust below min_rtt, but §5.2 has
    // min_rtt ignore the delay, so it does not move.
    test_rtt.update(.{
        .rtt_ns = 120 * millisecond,
        .ack_delay_ns = 40 * millisecond,
        .handshake_confirmed = false,
        .taken_at_ns = test_taken_at_ns,
    });
    try testing.expectEqual(100 * millisecond, test_rtt.min_ns);
    test_rtt.update(plain(70 * millisecond));
    try testing.expectEqual(70 * millisecond, test_rtt.min_ns);
    test_rtt.update(plain(200 * millisecond));
    try testing.expectEqual(70 * millisecond, test_rtt.min_ns);
}

test "§6.2.1: the probe timeout carries the delay only where a peer may add one" {
    test_rtt.init();
    test_rtt.update(plain(100 * millisecond));
    // smoothed 100, variation 50: 100 + 4 * 50 = 300, and the peer's 25 ms on top in the
    // Application Data space alone.
    try testing.expectEqual(300 * millisecond, test_rtt.probe_timeout_ns(false));
    try testing.expectEqual(325 * millisecond, test_rtt.probe_timeout_ns(true));
    // §6.2.1: the variation term is at least the granularity, so a run of identical samples
    // driving the variation to zero still leaves a timeout longer than the estimate.
    for (0..64) |_| test_rtt.update(plain(100 * millisecond));
    try testing.expectEqual(0, test_rtt.variation_ns);
    try testing.expectEqual(100 * millisecond + constants.rtt_granularity_ns, test_rtt.probe_timeout_ns(false));
}

test "§6.1.2: the loss delay is nine eighths of the larger estimate" {
    test_rtt.init();
    test_rtt.update(plain(80 * millisecond));
    // Both are 80 ms after the first sample: 9/8 * 80 = 90.
    try testing.expectEqual(90 * millisecond, test_rtt.loss_delay_ns());
    // A sample above the average makes the latest the larger, and the delay follows it rather
    // than the slower-moving average: 9/8 * 160 = 180.
    test_rtt.update(plain(160 * millisecond));
    try testing.expectEqual(180 * millisecond, test_rtt.loss_delay_ns());
    // A sample below it leaves the average larger: smoothed is 7/8 * 90 + 1/8 * 10 = 80, and
    // 9/8 * 80 = 90.
    test_rtt.update(plain(10 * millisecond));
    try testing.expectEqual(90 * millisecond, test_rtt.loss_delay_ns());
    // §6.1.2: never below the granularity, whatever the estimates hold.
    test_rtt.latest_ns = 0;
    test_rtt.smoothed_ns = 0;
    try testing.expectEqual(constants.rtt_granularity_ns, test_rtt.loss_delay_ns());
}

test "§9.4: a reset forgets the path and keeps what the peer advertised" {
    test_rtt.init();
    // RFC 9000 §18.2: the parameter is milliseconds, and 2^14 - 1 is the largest valid one.
    test_rtt.set_peer_max_ack_delay(40);
    test_rtt.update(plain(100 * millisecond));
    // 100 + 4 * 50 + the 40 ms the peer advertised.
    try testing.expectEqual(340 * millisecond, test_rtt.probe_timeout_ns(true));
    // RFC 9000 §9.4: migrating to a new path discards what was measured on the old one.
    test_rtt.reset();
    try testing.expect(!test_rtt.has_sample());
    try testing.expectEqual(null, test_rtt.first_sample_at_ns);
    try testing.expectEqual(constants.rtt_initial_ns, test_rtt.smoothed_ns);
    try testing.expectEqual(0, test_rtt.min_ns);
    // What the peer advertised is not a property of the path, so it survives the reset.
    try testing.expectEqual(40 * millisecond, test_rtt.peer_max_ack_delay_ns);
    test_rtt.update(plain(100 * millisecond));
    try testing.expectEqual(340 * millisecond, test_rtt.probe_timeout_ns(true));
    // Absent the parameter, §18.2 assumes 25 ms.
    test_rtt.init();
    try testing.expectEqual(constants.max_ack_delay_default_ns, test_rtt.peer_max_ack_delay_ns);
}
