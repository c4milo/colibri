//! The context colibri's TLS values take in the test-only programs (decision 175): stdx's
//! `CpuFeatures.detect()`, taken once, and one `stdx.crypto.init` over the operating system's
//! entropy (`entropy.zig`). stdx maps the features to chapulin's description of the CPU, and
//! states the timing: on every x86-64 core, and on an arm64 thread whose PSTATE.DIT is set.
//!
//! So each thread that runs TLS calls `set_timing` first, which sets PSTATE.DIT on arm64 where the
//! core has FEAT_DIT. A virtual machine may hide FEAT_DIT from its guest, as the bench runner's
//! does. There stdx states no timing, and the sessions hold TLS_CHACHA20_POLY1305_SHA256 alone.
const std = @import("std");
const builtin = @import("builtin");
const stdx = @import("stdx");
const platform = stdx.platform;
const entropy = @import("entropy.zig");

/// The context the first call made, which every later call returns.
var made: ?stdx.crypto.Context align(@alignOf(?stdx.crypto.Context)) = null;

/// The program's one context: the CPU features detected once, and the operating system's
/// entropy. It sets the calling thread's timing first. The first call makes the context, so a
/// program makes that call before it starts a second thread.
pub fn crypto() stdx.crypto.Context {
    const context = made orelse first: {
        const first = stdx.crypto.init(platform.CpuFeatures.detect(), entropy.random());
        made = first;
        break :first first;
    };
    _ = platform.set_data_independent_timing(context.features, true);
    return context;
}

/// Sets PSTATE.DIT on the calling thread where the core has FEAT_DIT, as a program does on each
/// thread that runs TLS (decision 175). Elsewhere it does nothing.
pub fn set_timing() void {
    _ = crypto();
}

/// The CPU features the program detected once, which its codecs take beside its TLS values
/// (decision 169).
pub fn features() platform.CpuFeatures {
    return crypto().features;
}

/// Prints the features `crypto` holds, which decide the suites a program's TLS sessions hold, and
/// whether the calling thread's timing is data-independent, under the program's name.
pub fn print(program: []const u8) void {
    const held = features();
    std.debug.print("{s}: cpu aes {}, pclmul {}, pmull {}, dit {}, sha256 {}, sha512 {}, sha3 {}, timing {}\n", .{ program, held.aes, held.pclmul, held.pmull, held.dit, held.sha256, held.sha512, held.sha3, platform.data_independent_timing(held) });
}

const testing = std.testing;

test "decision 175: an arm64 thread with FEAT_DIT runs with PSTATE.DIT set, and the context keeps the features" {
    const context = crypto();
    try testing.expectEqual(platform.CpuFeatures.detect(), context.features);
    if (builtin.cpu.arch == .aarch64 and context.features.dit) try testing.expect(platform.data_independent_timing(context.features));
    // Every later call returns the first context, and the codecs take its features.
    try testing.expectEqual(context.random.ptr, crypto().random.ptr);
    try testing.expectEqual(context.features, features());
}
