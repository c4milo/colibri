//! The constants of `h11` (docs/design.md §7), never written inline (CLAUDE.md
//! non-negotiable 4). Decision 137 puts each in a file by who sets it, and this file exports
//! the files:
//! - `protocol`: the values the RFCs fix, which no one may change.
//! - `limits`: the bounds colibri chose, which size memory or bound a loop or a queue. Ask
//!   the owner before changing one (CLAUDE.md).
//!
//! A limit h11 shares with h2 or h3, such as the field limits, is in `core.constants.limits`;
//! these are the limits only HTTP/1.1's text framing needs.

pub const protocol = @import("constants_protocol.zig");
pub const limits = @import("constants_limits.zig");
