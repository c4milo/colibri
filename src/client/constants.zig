//! The constants of `client` (docs/design.md §7), never written inline (CLAUDE.md
//! non-negotiable 4). Decision 137 puts each in a file by who sets it, and this file exports
//! the files:
//! - `protocol`: the values the RFCs fix, which no one may change.
//! - `limits`: the bounds colibri chose, which size memory or bound a loop or a queue. Ask
//!   the owner before changing one (CLAUDE.md).
//! - `policy`: the values colibri chose within what the RFCs allow, which size nothing.
//! This file holds the units.
//!
//! A connection's buffers are sized from h2's frame limits and the TLS record limits, so every
//! size is a comptime constant a caller can read (decision 35).
const quic = @import("quic");

pub const protocol = @import("constants_protocol.zig");
pub const limits = @import("constants_limits.zig");
pub const policy = @import("constants_policy.zig");

/// Nanoseconds in a second, which an Alt-Svc freshness lifetime counts (RFC 7838 §3.1).
pub const nanoseconds_per_second: u64 = 1_000 * quic.constants.nanoseconds_per_millisecond;
