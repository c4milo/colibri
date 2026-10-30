//! The constants of `h3` (docs/design.md §7), never written inline (CLAUDE.md
//! non-negotiable 4). Decision 137 puts each in a file by who sets it, and this file exports
//! the files:
//! - `protocol`: the values the RFCs fix, which no one may change.
//! - `limits`: the bounds colibri chose, which size memory or bound a loop or a queue. Ask
//!   the owner before changing one (CLAUDE.md).
//! - `policy`: the values colibri chose within what the RFCs allow, which size nothing.
const core = @import("core");
const std = @import("std");
const assert = std.debug.assert;

pub const protocol = @import("constants_protocol.zig");
pub const limits = @import("constants_limits.zig");
pub const policy = @import("constants_policy.zig");

comptime {
    // The three streams the connection opens, the peer's unidirectional ones and every request
    // stream fit the QUIC stream table together.
    assert(protocol.critical_streams + limits.uni_streams_max + limits.request_streams_max <= core.constants.limits.streams_per_connection_max);
    // The critical streams, and at least one more, fit the peer's slots.
    assert(limits.uni_streams_max > protocol.critical_streams);
}
