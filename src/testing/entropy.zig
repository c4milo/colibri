//! The random octets `src/testing/`'s endpoints draw, from the operating system's `getentropy`:
//! for the keys and connection IDs they choose, and as the source each of their TLS sessions draws
//! from. chapulin is built `RAND=session`, and each session's `start` takes its source (decision 94
//! as amended on 2026-09-27). The library draws none: randomness is the consumer's.
//!
//! `getentropy` keeps no state here, so one source serves sessions on several threads at once.
const std = @import("std");
const assert = std.debug.assert;

/// The most octets one `getentropy` call fills (POSIX).
const getentropy_len_max = 256;

/// macOS and glibc Linux declare `getentropy` in `unistd.h`. Zig's `std.c` exposes it on neither,
/// so it is declared here.
extern "c" fn getentropy(buffer: [*]u8, len: usize) c_int;

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

/// The source each TLS session of `src/testing/` draws from: `fill`, which keeps no state.
pub fn random() std.Random {
    return .{ .ptr = @constCast(&source_marker), .fillFn = fill_source };
}

/// What a `std.Random` points at, which `fill_source` never reads: the source keeps no state.
const source_marker: u8 = 0;

fn fill_source(_: *anyopaque, octets: []u8) void {
    fill(octets);
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

test "the source a session draws from fills from the operating system" {
    var octets: [test_draw_len]u8 = @splat(0);
    random().bytes(&octets);
    try testing.expect(!std.mem.allEqual(u8, &octets, 0));
}
