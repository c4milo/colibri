//! The constants of `core` (docs/design.md §7), never written inline (CLAUDE.md
//! non-negotiable 4). Decision 137 puts each in a file by who sets it, and this file exports
//! the files:
//! - `protocol`: the values the RFCs fix, which no one may change.
//! - `limits`: the bounds colibri chose, which size memory or bound a loop or a queue. Ask
//!   the owner before changing one (CLAUDE.md).
//! This file holds the units.
//!
//! These are the constants two or more modules share. Several of the limits exist because an
//! RFC declines to bound something and leaves the job to the implementation. Each such limit
//! names the section that declines, so a reader can tell a limit colibri chose from a limit a
//! protocol fixed.
const std = @import("std");
const assert = std.debug.assert;

pub const protocol = @import("constants_protocol.zig");
pub const limits = @import("constants_limits.zig");

/// Nanoseconds in a second. QUIC gives a delivery rate in octets a second
/// (draft-ietf-ccwg-bbr-06 §4.1).
pub const nanoseconds_per_second: u64 = 1_000_000_000;

comptime {
    // A field section that could not hold one maximal field line would make the two limits
    // disagree, and the peer would see the disagreement as a refusal it cannot diagnose.
    assert(limits.field_section_size_max >= limits.field_name_len_max + limits.field_value_len_max + protocol.field_line_overhead);
    // The per-line limits must fit the accounting type the size formula uses.
    assert(@as(u64, limits.field_name_len_max) + limits.field_value_len_max + protocol.field_line_overhead <= std.math.maxInt(u32));
}

test "field_section_size_max admits one maximal field line" {
    const line_size: u64 = @as(u64, limits.field_name_len_max) + limits.field_value_len_max + protocol.field_line_overhead;
    try std.testing.expect(line_size <= limits.field_section_size_max);
}
