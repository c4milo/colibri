//! NewReno's constants (RFC 9002 §7 and Appendix B, decision 133 as amended), which
//! `constants_recovery.zig` exports as `newreno`. The fraction is a numerator and a denominator,
//! because colibri's arithmetic is integer (non-negotiable 5).
const std = @import("std");
const assert = std.debug.assert;

/// Appendix B.1's `kLossReductionFactor`: what the window is scaled by on a new congestion event,
/// which "Section 7 recommends a value of 0.5".
pub const loss_reduction_numerator: u64 = 1;
pub const loss_reduction_denominator: u64 = 2;

comptime {
    assert(loss_reduction_numerator < loss_reduction_denominator);
}

test "RFC 9002 Appendix B.1: kLossReductionFactor is 0.5" {
    try std.testing.expectEqual(1, loss_reduction_numerator);
    try std.testing.expectEqual(2, loss_reduction_denominator);
}
