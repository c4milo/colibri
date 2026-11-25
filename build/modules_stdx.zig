//! The stdx package the library links (decisions 90 and 174), and the test for chapulin's host
//! object. Split from `modules.zig`, which builds the module graph over it.
const std = @import("std");

/// chapulin's `KEYLOG` value, spelled as stdx's option `crypto_keylog` takes it.
const Keylog = enum { on, off };

/// stdx, with `stdx.crypto`: chapulin's one module, which stdx alone asks chapulin for (decision
/// 174, stdx's decision 87). Its request is decision 172's: `TRANSPORT=nonblocking RAND=session
/// ROLE=both TRUST=webpki EXPORTER=on TX_RECORD=16384`, `SUITE=aesgcm` on a host target and
/// `chacha` on another, and `DNSSEC`, `JWS`, `SCRAM` and `HASH` on a host target (stdx's
/// `build/crypto.zig`). The module defines `ch_assert_fail`, so a program defines no hook.
/// - The library's stdx is `KEYLOG=off` (decision 94). Only the test-only images of `tls_keylog`
///   take a second stdx with `on`, which hands each traffic secret to `ch_keylog`.
/// - A program that names stdx beside colibri passes the same options, so that it links one
///   stdx and one chapulin (docs/usage.md).
pub fn dependency(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
    keylog: Keylog,
) *std.Build.Dependency {
    const release = optimize == .ReleaseSafe;
    // Zig keys a dependency by the options a build names, and a dependent names no
    // `crypto_keylog`. So the library's request leaves it out too, and gives the dependent's stdx.
    return switch (keylog) {
        .off => b.dependency("stdx", .{ .target = target, .release = release, .crypto = true }),
        .on => b.dependency("stdx", .{ .target = target, .release = release, .crypto = true, .crypto_keylog = true }),
    };
}

/// Decision 97 as amended for chapulin 0.2.0 (https://github.com/c4milo/colibri/issues/84): on a
/// host target, arm64 with NEON or x86-64 with SSE2, both objects are chapulin's host objects. They
/// hold every fast path beside the portable code, and each session picks among them from the CPU
/// its caller describes (chapulin's decision 89). Any other target builds chapulin's device
/// object, whose AES is the software one, so stdx asks it for `SUITE=chacha` alone. This is
/// chapulin's host test (its build's `hostTarget`), which stdx's `build/crypto.zig` repeats.
pub fn host_object(target: std.Build.ResolvedTarget) bool {
    const cpu = target.result.cpu;
    return switch (cpu.arch) {
        .aarch64 => std.Target.aarch64.featureSetHas(cpu.features, .neon),
        .x86_64 => std.Target.x86.featureSetHas(cpu.features, .sse2),
        else => false,
    };
}
