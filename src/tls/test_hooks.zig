//! The two hooks chapulin's objects import, defined for the module's test binary alone (decision
//! 94): a program that links colibri defines its own. Only a `test` block imports this file, so no
//! other build analyses it or exports these names.
//!
//! The randomness is a fixed stream: chapulin draws key shares and nonces from it, and a fixed
//! stream makes every run of the tests draw the same ones. Nothing here is secret.
const std = @import("std");

/// The stream's state and the mixing of each step: SplitMix64's constants. Each thread that runs
/// tests draws its own stream.
threadlocal var stream_state: u64 align(@alignOf(u64)) = stream_seed;
const stream_seed: u64 = 0x636f_6c69_6272_6921;
const stream_increment: u64 = 0x9e37_79b9_7f4a_7c15;
const mix_multiplier_first: u64 = 0xbf58_476d_1ce4_e5b9;
const mix_multiplier_second: u64 = 0x94d0_49bb_1331_11eb;
const mix_shift_first: u6 = 30;
const mix_shift_second: u6 = 27;
const mix_shift_third: u6 = 31;

fn rand_bytes(pointer: [*]u8, len: usize) callconv(.c) void {
    for (pointer[0..len]) |*octet| {
        stream_state +%= stream_increment;
        var mixed = stream_state;
        mixed = (mixed ^ (mixed >> mix_shift_first)) *% mix_multiplier_first;
        mixed = (mixed ^ (mixed >> mix_shift_second)) *% mix_multiplier_second;
        octet.* = @truncate(mixed ^ (mixed >> mix_shift_third));
    }
}

/// A failed chapulin assertion is a defect in chapulin or in how colibri configured it.
fn assert_fail(condition: [*:0]const u8, file: [*:0]const u8, line: c_int) callconv(.c) noreturn {
    std.debug.panic("chapulin assertion failed: {s} ({s}:{d})", .{ condition, file, line });
}

comptime {
    @export(&rand_bytes, .{ .name = "ch_rand_bytes", .linkage = .strong });
    @export(&assert_fail, .{ .name = "ch_assert_fail", .linkage = .strong });
}
