//! The bounds colibri chose for qlog, which size memory or bound a loop or a queue. Ask the
//! owner before changing one (CLAUDE.md): the test at the end pins each value.
//! Decision 137 groups them, and `constants.zig` exports this file as `limits`.
const std = @import("std");
const assert = std.debug.assert;

/// Decimal digits of the largest tuple number, a `u32`, which a TupleID holds as text (main
/// schema §7.2, quic-events §4.7).
pub const tuple_id_len_max: usize = 10;

/// The tokens a record's writer gathers before it hands them to stdx's `write_items` (decision
/// 102 as amended), and the octets of their names, strings and hex strings it holds copies of.
/// Policy: a packet event with a few frames fits, and a longer record is written in several calls.
pub const batch_items_max: usize = 64;
pub const batch_octets_len: usize = 1024;

/// Smallest buffer a log may be given, in octets: the header record fits with room for events.
/// Policy.
pub const log_len_min: usize = 1024;

comptime {
    assert(log_len_min > 0);
    assert(batch_items_max > 0 and batch_octets_len > 0);
    assert(std.fmt.count("{d}", .{std.math.maxInt(u32)}) == tuple_id_len_max);
}

test "decision 137: each limit holds the value the owner ruled" {
    // A failure here is a changed limit, which the owner rules on before this test changes.
    const expectEqual = @import("std").testing.expectEqual;
    try expectEqual(10, tuple_id_len_max);
    try expectEqual(64, batch_items_max);
    try expectEqual(1024, batch_octets_len);
    try expectEqual(1024, log_len_min);
}
