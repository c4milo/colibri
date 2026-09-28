//! The hook chapulin's objects import, defined for the module's test binary alone (decision 94): a
//! program that links colibri defines its own. Only a `test` block imports this file, so no other
//! build analyses it or exports the name.
const std = @import("std");

/// A failed chapulin assertion is a defect in chapulin or in how colibri configured it.
fn assert_fail(condition: [*:0]const u8, file: [*:0]const u8, line: c_int) callconv(.c) noreturn {
    std.debug.panic("chapulin assertion failed: {s} ({s}:{d})", .{ condition, file, line });
}

comptime {
    @export(&assert_fail, .{ .name = "ch_assert_fail", .linkage = .strong });
}
