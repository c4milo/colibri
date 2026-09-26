//! The random octets chapulin draws, which the program that links it supplies: chapulin is built
//! `RAND=extern`, and its `rand.h` has the image define `ch_rand_bytes` once (decision 94, design
//! §8 step 16a). This file defines it for every image of `src/testing/`, and the library defines
//! none: randomness is the consumer's.
//!
//! The octets come from the operating system's `getentropy`, which keeps no state here, so the hook
//! is safe to call from several threads at once, as chapulin's `rand.h` requires. A test that must
//! stage the same octets twice, such as one ClientHello compared with another, switches to a fixed
//! stream with `use_fixed` and back with `use_system`.
const std = @import("std");
const assert = std.debug.assert;

/// The most octets one `getentropy` call fills (POSIX).
const getentropy_len_max = 256;

/// macOS and glibc Linux declare `getentropy` in `unistd.h`. Zig's `std.c` exposes it on neither,
/// so it is declared here.
extern "c" fn getentropy(buffer: [*]u8, len: usize) c_int;

/// The fixed stream a test switched to, or null for the operating system's. Only a test sets it,
/// and a test runs on one thread.
var fixed_state: ?u64 = null;

/// Makes every draw after this one come from a fixed stream that starts at `seed`, so two runs
/// that draw the same lengths draw the same octets. Test-only.
pub fn use_fixed(seed: u64) void {
    fixed_state = seed;
}

/// Makes every draw after this one come from the operating system again.
pub fn use_system() void {
    fixed_state = null;
}

/// Fills `octets` from the operating system, or halts: a program with no entropy has no business
/// starting a handshake (chapulin's `rand.h`).
pub fn fill(octets: []u8) void {
    var filled: usize = 0;
    // Each turn fills `getentropy_len_max` octets, or the rest.
    for (0..octets.len / getentropy_len_max + 1) |_| {
        if (filled == octets.len) return;
        const len = @min(octets.len - filled, getentropy_len_max);
        if (getentropy(octets[filled..].ptr, len) != 0) @panic("getentropy failed");
        filled += len;
    }
    assert(filled == octets.len);
}

/// SplitMix64's increment, multipliers and shifts, which the fixed stream uses.
const mix_increment: u64 = 0x9e3779b97f4a7c15;
const mix_multiplier_first: u64 = 0xbf58476d1ce4e5b9;
const mix_multiplier_second: u64 = 0x94d049bb133111eb;
const mix_shift_first: u6 = 30;
const mix_shift_second: u6 = 27;
const mix_shift_third: u6 = 31;

fn fill_fixed(state: *u64, octets: []u8) void {
    for (octets) |*octet| {
        state.* +%= mix_increment;
        var mixed = state.*;
        mixed = (mixed ^ (mixed >> mix_shift_first)) *% mix_multiplier_first;
        mixed = (mixed ^ (mixed >> mix_shift_second)) *% mix_multiplier_second;
        octet.* = @truncate(mixed ^ (mixed >> mix_shift_third));
    }
}

fn rand_bytes(pointer: [*]u8, len: usize) callconv(.c) void {
    const octets = pointer[0..len];
    if (fixed_state) |*state| return fill_fixed(state, octets);
    fill(octets);
}

comptime {
    @export(&rand_bytes, .{ .name = "ch_rand_bytes", .linkage = .strong });
}

const testing = std.testing;

/// Octets the tests draw. Test-only.
const test_draw_len = 300;

test "the operating system's octets fill the whole buffer, past one getentropy call" {
    var octets: [test_draw_len]u8 = @splat(0);
    fill(&octets);
    // 300 zero octets from a working source would be a one-in-2^2400 draw.
    try testing.expect(!std.mem.allEqual(u8, &octets, 0));
}

test "the fixed stream repeats from its seed, and the system stream returns after it" {
    var first: [test_draw_len]u8 = undefined;
    var second: [test_draw_len]u8 = undefined;
    use_fixed(7);
    rand_bytes(&first, first.len);
    use_fixed(7);
    rand_bytes(&second, second.len);
    use_system();
    try testing.expectEqualSlices(u8, &first, &second);
    try testing.expect(fixed_state == null);
}
