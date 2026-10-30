//! The constants of `h2` (docs/design.md §7), never written inline (CLAUDE.md
//! non-negotiable 4). Decision 137 puts each in a file by who sets it, and this file exports
//! the files:
//! - `protocol`: the values the RFCs fix, which no one may change.
//! - `limits`: the bounds colibri chose, which size memory or bound a loop or a queue. Ask
//!   the owner before changing one (CLAUDE.md).
//! - `policy`: the values colibri chose within what the RFCs allow, which size nothing.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");

pub const protocol = @import("constants_protocol.zig");
pub const limits = @import("constants_limits.zig");
pub const policy = @import("constants_policy.zig");

comptime {
    assert(limits.frame_size_max >= protocol.max_frame_size_min and limits.frame_size_max <= protocol.max_frame_size_max);
    assert(policy.window_initial <= protocol.window_max and protocol.initial_window_size_initial <= protocol.window_max);
    // A line's own octets: the first octet, its name's length and its value's length, all of which
    // the 32 octets §6.5.2 charges per line cover, so a section colibri accepts encodes within its
    // own size plus the size updates that may open the block.
    assert(core.constants.protocol.field_line_overhead >= @sizeOf(u8) + 2 * wire.constants.protocol.integer_len_max);
    assert(limits.settings_per_frame_max > 0 and limits.settings_per_frame_max * protocol.setting_len <= limits.frame_size_max);
}
