//! What a program that links colibri's `tls` module defines once, which the examples over TLS and
//! QUIC share. It is not an example of colibri by itself.
//!
//! colibri draws no random octet and reports no failure of its own accord (non-negotiable 5):
//! - chapulin, the TLS stack behind `tls`, calls `ch_assert_fail` when one of its assertions
//!   fails, and the program defines it, because how a program reports a failure is the program's
//!   choice (decision 94);
//! - each connection draws every random value from the source the program passes it. A program
//!   passes its operating system's entropy, as here. A test passes a seeded generator, and the
//!   connection then replays octet for octet.
const std = @import("std");

/// chapulin's one hook. This program reports the failed assertion and stops.
fn assert_fail(condition: [*:0]const u8, file: [*:0]const u8, line: c_int) callconv(.c) noreturn {
    std.debug.panic("chapulin assertion failed: {s} ({s}:{d})", .{ condition, file, line });
}

comptime {
    @export(&assert_fail, .{ .name = "ch_assert_fail", .linkage = .strong });
}

/// macOS and glibc declare `getentropy` in `unistd.h`, and Zig's `std.c` exposes it on neither.
extern "c" fn getentropy(buffer: [*]u8, len: usize) c_int;

/// The most octets one `getentropy` call fills (POSIX).
const getentropy_len_max = 256;

/// Fills `octets` from the operating system, or stops: a program with no entropy starts no
/// handshake.
pub fn fill(octets: []u8) void {
    var filled: usize = 0;
    // Each turn fills `getentropy_len_max` octets, or the rest.
    for (0..octets.len / getentropy_len_max + 1) |_| {
        if (filled == octets.len) return;
        const len = @min(octets.len - filled, getentropy_len_max);
        if (getentropy(octets[filled..].ptr, len) != 0) @panic("getentropy failed");
        filled += len;
    }
}

/// The source the program passes each connection. It keeps no state, so one serves every
/// connection.
pub fn random() std.Random {
    return .{ .ptr = @constCast(&source_marker), .fillFn = fill_source };
}

/// What a `std.Random` points at, which `fill_source` never reads.
const source_marker: u8 = 0;

fn fill_source(_: *anyopaque, octets: []u8) void {
    fill(octets);
}
