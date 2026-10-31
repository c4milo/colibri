//! The draws of each bandwidth probe wait (draft-ietf-ccwg-bbr-06 §5.3.3.8.2, decision 136).
//! Part of design §8 step 29b.2.
//!
//! §5.3.3.8.2's `PickProbeWait` draws two random values each time BBR waits to probe: a wall
//! clock wait between 2 and 3 s, and a start of 0 or 1 for the count of round trips, so the
//! bound is 63 or 62 rounds. colibri holds no generator (invariant 5). The caller draws one
//! `u64` at start, and each wait mixes it with the count of waits so far through the SplitMix64
//! finalizer, so no pattern repeats and one seed replays (the owner's ruling of 2026-10-31).
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("../../constants.zig");

const bbr = constants.recovery.bbr;

/// The two draws of one wait.
pub const Wait = struct {
    /// `BBR.rounds_since_probe_up` at the start of the wait: 0 or 1.
    rounds_start: u64,
    /// `BBR.bw_probe_wait`: 2 s and a draw below 1 s.
    wait_ns: u64,
};

/// The SplitMix64 finalizer: each bit of the output depends on each bit of the input.
pub fn mix(input: u64) u64 {
    var mixed = input;
    mixed = (mixed ^ (mixed >> bbr.splitmix_first_shift)) *% bbr.splitmix_first_multiplier;
    mixed = (mixed ^ (mixed >> bbr.splitmix_second_shift)) *% bbr.splitmix_second_multiplier;
    return mixed ^ (mixed >> bbr.splitmix_third_shift);
}

/// The draws of wait number `count` from the caller's `bandwidth_probe_waits`.
pub fn draw(bandwidth_probe_waits: u64, count: u64) Wait {
    const mixed = mix(bandwidth_probe_waits +% count *% bbr.probe_wait_increment);
    const drawn: Wait = .{
        .rounds_start = mixed & 1,
        .wait_ns = bbr.probe_wait_min_ns + (mixed >> 1) % bbr.probe_wait_spread_ns,
    };
    assert(drawn.rounds_start <= 1);
    assert(drawn.wait_ns >= bbr.probe_wait_min_ns and drawn.wait_ns < bbr.probe_wait_min_ns + bbr.probe_wait_spread_ns);
    return drawn;
}

const testing = std.testing;

test "SplitMix64's finalizer gives its published first output" {
    // SplitMix64 seeded with 0 returns mix(0x9e3779b97f4a7c15) first.
    try testing.expectEqual(0xe220a8397b1dcdaf, mix(bbr.probe_wait_increment));
}

test "decision 136: two connections with near values do not wait alike" {
    const first = draw(1, 0);
    const second = draw(2, 0);
    try testing.expect(first.wait_ns != second.wait_ns);
    // Each wait of one connection differs from the one before it.
    try testing.expect(draw(1, 1).wait_ns != first.wait_ns);
}
