//! The constants of `qlog` (docs/design.md §7), never written inline (CLAUDE.md
//! non-negotiable 4). Decision 137 puts each in a file by who sets it, and this file exports
//! the files:
//! - `protocol`: the values the RFCs fix, which no one may change.
//! - `limits`: the bounds colibri chose, which size memory or bound a loop or a queue. Ask
//!   the owner before changing one (CLAUDE.md).
//! This file holds the units.
const std = @import("std");
const assert = std.debug.assert;

pub const protocol = @import("constants_protocol.zig");
pub const limits = @import("constants_limits.zig");

/// A qlog time is milliseconds with a fraction (main schema §1.2, §7.1). colibri's instants are
/// nanoseconds, and it writes microseconds as the fraction.
pub const nanoseconds_per_millisecond: u64 = 1_000_000;
pub const nanoseconds_per_microsecond: u64 = 1_000;

comptime {
    assert(nanoseconds_per_millisecond % nanoseconds_per_microsecond == 0);
    assert(std.math.pow(u64, 10, protocol.millisecond_fraction_digits) == nanoseconds_per_millisecond / nanoseconds_per_microsecond);
}
