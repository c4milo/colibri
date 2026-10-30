//! The constants of `quic` (docs/design.md §7), never written inline (CLAUDE.md
//! non-negotiable 4). Decision 137 puts each in a file by who sets it, and this file exports
//! the files:
//! - `protocol`: the values the RFCs fix, which no one may change.
//! - `limits`: the bounds colibri chose, which size memory or bound a loop or a queue. Ask
//!   the owner before changing one (CLAUDE.md).
//! - `policy`: the values colibri chose within what the RFCs allow, which size nothing.
//! - `recovery`: the parameters of RFC 9002's loss detection, congestion control and pacing,
//!   with CUBIC's and HyStart++'s.
//! This file holds the units.
//!
//! `packet/invariant.zig` imports none of this: it reads RFC 8999 alone, and invariant 22 keeps
//! every version 1 value out of its reach.
const std = @import("std");
const assert = std.debug.assert;

pub const protocol = @import("constants_protocol.zig");
pub const limits = @import("constants_limits.zig");
pub const policy = @import("constants_policy.zig");
pub const recovery = @import("constants_recovery.zig");

/// Nanoseconds in a microsecond, which the ACK Delay field is measured in (RFC 9000 §19.3).
pub const nanoseconds_per_microsecond: u64 = 1_000;

/// Nanoseconds in a millisecond, which `max_idle_timeout` is advertised in (RFC 9000 §18.2).
pub const nanoseconds_per_millisecond: u64 = 1_000 * nanoseconds_per_microsecond;

comptime {
    // A header must fit the smallest datagram §14.1 allows, or no Initial could ever be written.
    assert(limits.packet_header_len_max < protocol.datagram_len_min);
    assert(limits.connection_ids_max >= protocol.active_connection_id_limit_min);
}
