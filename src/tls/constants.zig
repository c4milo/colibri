//! The constants of `tls` (docs/design.md §7), never written inline (CLAUDE.md
//! non-negotiable 4). Decision 137 puts each in a file by who sets it, and this file exports
//! the files:
//! - `protocol`: the values the RFCs fix, which no one may change.
//! - `limits`: the bounds colibri chose, which size memory or bound a loop or a queue. Ask
//!   the owner before changing one (CLAUDE.md).
//! This file holds the units.
//!
//! A limit chapulin names stays chapulin's, under its C name in `chapulin.c`, such as
//! `CH_ALPN_MAX`; these are the ones colibri chooses. A caller cannot reach `chapulin.c`, so the
//! few it sizes its buffers and lists by are exported where their object is known:
//! `record.alert_record_len`, `record.Client.handshake_output_len_min`, and each
//! configuration's `anchors_max` and `protocols_max`.
const std = @import("std");
const assert = std.debug.assert;

pub const protocol = @import("constants_protocol.zig");
pub const limits = @import("constants_limits.zig");

/// Nanoseconds in a second: colibri passes instants in nanoseconds, and chapulin counts a Retry
/// token's lifetime in seconds.
pub const nanoseconds_per_second: u64 = 1_000_000_000;

comptime {
    assert(limits.ticket_psk_len_max >= protocol.sha256_len);
}
