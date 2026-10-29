//! CUBIC's constants (RFC 9438, decision 133), which `constants.zig` exports as `cubic`. Each
//! fraction of RFC 9438 is a numerator and a denominator, because colibri's arithmetic is integer
//! (non-negotiable 5).
const std = @import("std");
const assert = std.debug.assert;

/// §4.6: β_cubic, what the window is scaled by on a congestion event, which "SHOULD be set to 0.7".
pub const beta_numerator: u64 = 7;
pub const beta_denominator: u64 = 10;

/// §5.1: C, the aggressiveness of the cubic increase in segments per second cubed, which "SHOULD
/// be set to 0.4".
pub const c_numerator: u64 = 4;
pub const c_denominator: u64 = 10;

/// §4.3: α_cubic, the Reno-friendly estimate's increase per round trip, 3 × (1 − β) / (1 + β),
/// which gives the average window of Reno.
pub const alpha_numerator: u64 = 9;
pub const alpha_denominator: u64 = 17;

/// §4.7: fast convergence lowers W_max to the window × (1 + β) / 2 when the window fell short of it.
pub const convergence_numerator: u64 = 17;
pub const convergence_denominator: u64 = 20;

/// §4.2: the target after the next round trip is at most 1.5 times the window.
pub const target_numerator: u64 = 3;
pub const target_denominator: u64 = 2;

/// Microseconds in a second, the unit colibri counts CUBIC's time in: §4.2's cube of `t − K`
/// stays inside 128 bits for a span of `elapsed_us_max`.
pub const microseconds_per_second: u64 = 1_000_000;

/// The longest `t − K` the cubic increase counts, about 4.8 hours. Past it the window has long
/// reached any bound the sent table sets, so the increase holds at its value there.
pub const elapsed_us_max: u64 = 17_179_869_184;

/// The bits a cube root of a 128-bit value needs: 2^128 is below (2^43)^3.
pub const cube_root_bits: u7 = 43;

comptime {
    assert(beta_numerator < beta_denominator);
    assert(elapsed_us_max == 1 << 34);
    // §4.3: α = 3 × (1 − β) / (1 + β), and §4.7's factor is (1 + β) / 2.
    assert(alpha_numerator * (beta_denominator + beta_numerator) == 3 * (beta_denominator - beta_numerator) * alpha_denominator);
    assert(convergence_numerator * 2 * beta_denominator == (beta_denominator + beta_numerator) * convergence_denominator);
    // The cube of the longest span, times C's numerator and the largest datagram, fits in 128 bits.
    assert(std.math.log2_int(u128, elapsed_us_max) * 3 + std.math.log2_int(u64, c_numerator) + 17 < 127);
    assert(3 * @as(u16, cube_root_bits) >= 128);
}
