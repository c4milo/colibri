//! The constants of `dnssec` (decision 142), never written inline (CLAUDE.md non-negotiable 4).
//! Decision 137 puts each in a file by who sets it, and this file exports the files:
//! - `protocol`: the values the RFCs and IANA's registries fix, which no one may change.

pub const protocol = @import("constants_protocol.zig");
