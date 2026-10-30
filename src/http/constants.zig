//! The constants of `http` (docs/design.md §7), never written inline (CLAUDE.md
//! non-negotiable 4). Decision 137 puts each in a file by who sets it, and this file exports
//! the files:
//! - `protocol`: the values the RFCs fix, which no one may change.
//! - `limits`: the bounds colibri chose, which size memory or bound a loop or a queue. Ask
//!   the owner before changing one (CLAUDE.md).
//!
//! The field-length limits h2 and h3 share live in `core` and are imported from there.

pub const protocol = @import("constants_protocol.zig");
pub const limits = @import("constants_limits.zig");
