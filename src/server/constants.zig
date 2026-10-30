//! The constants of `server` (docs/design.md §7), never written inline (CLAUDE.md
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
const std = @import("std");
const assert = std.debug.assert;

pub const protocol = @import("constants_protocol.zig");
pub const limits = @import("constants_limits.zig");
pub const policy = @import("constants_policy.zig");

/// Nanoseconds in a second, which a connection's ticket instant is counted in.
pub const nanoseconds_per_second: u64 = 1_000_000_000;

comptime {
    assert(limits.quic_response_pieces_max > 2 and limits.quic_read_len > 0 and policy.quic_id_len >= 8);
    // Every chunk the output holds leaves room for the last one.
    assert(limits.output_len > limits.chunk_framing_len_max + protocol.last_chunk_len);
    assert(limits.bodies_max > 0 and policy.body_rate_min > 0 and policy.send_rate_min > 0);
    assert(policy.rate_grace_ns + policy.rate_window_ns <= policy.body_timeout_ns and policy.body_timeout_ns <= limits.timeout_ns_max);
}
