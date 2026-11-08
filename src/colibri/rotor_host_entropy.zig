//! The source a `.private` server or client draws from when its program passes none (decision
//! 150 ruling 9, which decision 159 keeps for `.private` alone): the operating system's entropy,
//! with no state kept here, so one source serves every session. Linux gives it through the
//! `getrandom` system call, which needs no libc. macOS gives it through `getentropy`, in the
//! libSystem every macOS program links. It is a file of colibri's own Rotor host.
const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const tls = @import("tls");

/// The most octets one `getentropy` call fills (POSIX), and the size of each `getrandom` call.
const call_len_max = 256;

/// macOS declares `getentropy` in `unistd.h`, and Zig's `std.c` does not expose it.
extern "c" fn getentropy(buffer: [*]u8, len: usize) c_int;

comptime {
    // The two systems Rotor's backends run on (decision 58).
    assert(builtin.os.tag == .linux or builtin.os.tag.isDarwin());
}

/// Fills `octets` from the operating system, or halts: a server with no entropy must not start a
/// handshake.
fn fill(octets: []u8) void {
    var filled: usize = 0;
    // Each turn fills `call_len_max` octets, or the rest.
    for (0..octets.len / call_len_max + 1) |_| {
        if (filled == octets.len) return;
        const len = @min(octets.len - filled, call_len_max);
        fill_part(octets[filled..][0..len]);
        filled += len;
    }
    assert(filled == octets.len);
}

fn fill_part(part: []u8) void {
    assert(part.len <= call_len_max);
    if (builtin.os.tag == .linux) {
        const result = std.os.linux.getrandom(part.ptr, part.len, 0);
        // A call of at most 256 octets returns them all, or fails (getrandom(2)).
        if (std.os.linux.errno(result) != .SUCCESS or result != part.len) @panic("getrandom failed");
        return;
    }
    if (getentropy(part.ptr, part.len) != 0) @panic("getentropy failed");
}

/// The source a session draws from: `fill`, which keeps no state.
pub fn random() tls.Random {
    return .{ .ptr = @constCast(&source_marker), .fillFn = fill_source };
}

/// What the source points at, which `fill_source` never reads.
const source_marker: u8 = 0;

fn fill_source(_: *anyopaque, octets: []u8) void {
    fill(octets);
}

const testing = std.testing;

test "decision 150 ruling 9: two draws from the system differ" {
    var first: [32]u8 = undefined;
    var second: [32]u8 = undefined;
    const source = random();
    source.bytes(&first);
    source.bytes(&second);
    try testing.expect(!std.mem.eql(u8, &first, &second));
    // A draw longer than one call is filled whole.
    var long = [_]u8{0} ** (call_len_max * 2 + 1);
    source.bytes(&long);
    try testing.expect(!std.mem.allEqual(u8, long[call_len_max * 2 - 32 ..], 0));
}
