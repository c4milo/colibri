//! The constants of `colibri` (decision 150), never written inline (CLAUDE.md non-negotiable 4).
//! Decision 137 puts each in a file by who sets it, and this file exports the files:
//! - `limits`: the bounds colibri chose, which size memory or bound a loop. Ask the owner before
//!   changing one (CLAUDE.md).
pub const limits = @import("constants_limits.zig");
