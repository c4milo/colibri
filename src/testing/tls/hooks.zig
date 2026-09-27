//! The hook chapulin's objects import, which every image of `src/testing/` defines, as every program
//! that links colibri's `tls` does (decision 94): `ch_assert_fail`. The objects are built
//! `RAND=session`, so each session draws from the source `entropy.zig` hands its `start`, and no
//! image defines `ch_rand_bytes`. The library defines no hook.
const std = @import("std");

/// chapulin routes every failed assertion here, and `ch_assert.h` leaves the handler to the
/// image: its failure domain is the caller's. colibri's panics, naming the condition and the
/// chapulin source line. A failed chapulin assertion is a defect in chapulin or in how colibri
/// configured it, and either way the endpoint must not carry on with a session built on it.
fn assert_fail(condition: [*:0]const u8, file: [*:0]const u8, line: c_int) callconv(.c) noreturn {
    std.debug.panic("chapulin assertion failed: {s} ({s}:{d})", .{ condition, file, line });
}

comptime {
    @export(&assert_fail, .{ .name = "ch_assert_fail", .linkage = .strong });
}
