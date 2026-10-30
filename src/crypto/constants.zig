//! The constants of `crypto` (docs/design.md §7), never written inline (CLAUDE.md
//! non-negotiable 4). Decision 137 puts each in a file by who sets it, and this file exports
//! the files:
//! - `protocol`: the values the RFCs fix, which no one may change.
//!
//! Both sides of `Suite` must agree on these. `quic` names the same values through this module,
//! so a suite and the code that frames its packets cannot disagree.

pub const protocol = @import("constants_protocol.zig");
