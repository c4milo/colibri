//! The `memset` of the programs colibri times: `http-server`, which `bench/run.sh` measures, and
//! `quic-udp`, which `tools/h3load.sh` loads. Each root references this file, so the export is in
//! the program; the library exports none, because its caller's program owns the symbol.
//!
//! On Linux every `memset` in a Zig 0.16 program is compiler_rt's, which writes one octet at a
//! time: the 0xAA fill of a large `undefined` local, each `@memset` whose length is known only at
//! run time, and chapulin's C code. This one writes a vector at a time, and the linker takes it in
//! place of compiler_rt's. It is pepegrillo's recipe (`docs/performance/performance_zig.md`, "Copies
//! and fills"), which `zig build guide` installs. The guard keeps it to Linux and to Zig 0.16, so it
//! stops at the upgrade, which deletes this file.
const std = @import("std");
const builtin = @import("builtin");

/// The octets one vector store writes.
const store_len = 32;

comptime {
    const zig_0_16 = builtin.zig_version.major == 0 and builtin.zig_version.minor == 16;
    if (builtin.os.tag == .linux and zig_0_16) @export(&memset, .{ .name = "memset" });
}

/// Writes `value` to the `len` octets at `destination` and returns `destination`, as C's `memset`
/// does. A fill of one store or more ends with a store over its last `store_len` octets, which may
/// write some of them twice. The barrier in each loop keeps the compiler from turning the loop into
/// a call to `memset`, which is this function.
fn memset(destination: ?[*]u8, value: u8, len: usize) callconv(.c) ?[*]u8 {
    @setRuntimeSafety(false);
    const octets = destination orelse return destination;
    const fill: @Vector(store_len, u8) = @splat(value);
    if (len < store_len) {
        for (0..len) |i| {
            octets[i] = value;
            std.mem.doNotOptimizeAway(octets);
        }
        return destination;
    }
    var i: usize = 0;
    while (i + store_len <= len) : (i += store_len) {
        octets[i..][0..store_len].* = fill;
        std.mem.doNotOptimizeAway(octets);
    }
    octets[len - store_len ..][0..store_len].* = fill;
    return destination;
}

test "memset writes each octet it is given and none around them" {
    const guard = 0x5c;
    const fill = 0xa5;
    var buffer: [4 * store_len + 16]u8 = undefined;
    for (0..4) |offset| {
        for (0..3 * store_len + 5) |len| {
            @memset(&buffer, guard);
            const start = offset + 1;
            try std.testing.expectEqual(@as(?[*]u8, buffer[start..].ptr), memset(buffer[start..].ptr, fill, len));
            for (buffer, 0..) |octet, index| {
                const inside = index >= start and index < start + len;
                try std.testing.expectEqual(@as(u8, if (inside) fill else guard), octet);
            }
        }
    }
}

test "memset returns a null destination untouched" {
    try std.testing.expectEqual(@as(?[*]u8, null), memset(null, 0, 0));
}
