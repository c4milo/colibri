//! The constants of `hpack` (docs/design.md §7), never written inline (CLAUDE.md
//! non-negotiable 4). Decision 137 puts each in a file by who sets it, and this file exports
//! the files:
//! - `protocol`: the values the RFCs fix, which no one may change.
//! - `limits`: the bounds colibri chose, which size memory or bound a loop or a queue. Ask
//!   the owner before changing one (CLAUDE.md).
//!
//! RFC 7541 §7.4 requires an implementation to set limits on the integers and the string
//! literals it accepts. The integer limits are `wire`'s. The string limits are the field-length
//! limits of `core`, so a name or a value the decoder accepts is one the field validators can
//! measure.

pub const protocol = @import("constants_protocol.zig");
pub const limits = @import("constants_limits.zig");
