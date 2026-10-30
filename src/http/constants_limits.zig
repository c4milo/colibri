//! The bounds colibri chose for http, which size memory or bound a loop or a queue. Ask the
//! owner before changing one (CLAUDE.md): the test at the end pins each value.
//! Decision 137 groups them, and `constants.zig` exports this file as `limits`.
const std = @import("std");

/// The pairs one query holds at most, which sizes `QueryParameters` (decision 127, the owner's
/// ruling of 2026-10-25). `read` refuses a query of more.
pub const query_parameters_max: usize = 32;

comptime {
    std.debug.assert(query_parameters_max > 0);
}

test "decision 137: each limit holds the value the owner ruled" {
    // A failure here is a changed limit, which the owner rules on before this test changes.
    const expectEqual = @import("std").testing.expectEqual;
    try expectEqual(32, query_parameters_max);
}
