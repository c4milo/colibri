//! What a program that runs TLS over colibri defines once, which the examples over TLS and QUIC
//! share. It is not an example of colibri by itself.
//!
//! colibri draws no random octet of its own accord (non-negotiable 5). Each connection draws every
//! random value from the source the program passes it. A program passes its operating system's
//! entropy, as here. A test passes a seeded generator, and the connection then replays octet for
//! octet.
const std = @import("std");

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
