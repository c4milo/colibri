//! The hook chapulin's objects import (decision 94), which a program that links colibri defines.
//! The simulator links chapulin for the client trace run (decision 105), so its test binary and
//! `zig build sim` define it here.
const std = @import("std");

/// A failed chapulin assertion is a defect in chapulin or in how colibri configured it.
fn assert_fail(condition: [*:0]const u8, file: [*:0]const u8, line: c_int) callconv(.c) noreturn {
    std.debug.panic("chapulin assertion failed: {s} ({s}:{d})", .{ condition, file, line });
}

comptime {
    @export(&assert_fail, .{ .name = "ch_assert_fail", .linkage = .strong });
}
