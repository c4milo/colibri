//! The constants of `qpack` (docs/design.md §7), never written inline (CLAUDE.md
//! non-negotiable 4). Decision 137 puts each in a file by who sets it, and this file exports
//! the files:
//! - `protocol`: the values the RFCs fix, which no one may change.
//! - `limits`: the bounds colibri chose, which size memory or bound a loop or a queue. Ask
//!   the owner before changing one (CLAUDE.md).
//! - `policy`: the values colibri chose within what the RFCs allow, which size nothing.
const std = @import("std");

pub const protocol = @import("constants_protocol.zig");
pub const limits = @import("constants_limits.zig");
pub const policy = @import("constants_policy.zig");

test "constants compile" {
    try std.testing.expect(true);
}
