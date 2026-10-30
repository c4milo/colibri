//! The values the RFCs fix for core, which no one may change.
//! Decision 137 groups them, and `constants.zig` exports this file as `protocol`.
const std = @import("std");
const assert = std.debug.assert;

/// Octets added to a field line's name and value lengths wherever both protocols measure lines:
/// a field section against `SETTINGS_MAX_HEADER_LIST_SIZE` (RFC 9113 §6.5.2) and
/// `SETTINGS_MAX_FIELD_SECTION_SIZE` (RFC 9114 §4.2.2), and a dynamic table entry (RFC 7541 §4.1,
/// RFC 9204 §3.2.1). The four give the same formula, and this is its one constant.
pub const field_line_overhead: u32 = 32;

comptime {
    assert(field_line_overhead == 32);
}
