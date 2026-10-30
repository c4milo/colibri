//! The constants of `wire` (docs/design.md §7), never written inline (CLAUDE.md
//! non-negotiable 4). Decision 137 puts each in a file by who sets it, and this file exports
//! the files:
//! - `protocol`: the values the RFCs fix, which no one may change.
//!
//! `wire` holds two integer codecs and keeps their limits separate on purpose: the QUIC
//! variable-length integer is a framing primitive, and the prefixed integer is a field-compression
//! primitive (decision 11). They share a 62-bit maximum value and nothing else.

pub const protocol = @import("constants_protocol.zig");
