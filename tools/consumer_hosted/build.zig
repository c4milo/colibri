//! A project that depends on colibri and runs it on its own loop (decision 159): it uses a
//! protocol module and the `.hosted` kind of `colibri.Server` and `colibri.Client`, and no
//! `.private` object. It passes no `rotor` option, so its build fetches no Rotor.
//! `tools/consumer_check.sh` fetches colibri's working tree into it with a global cache that
//! starts empty, builds and runs it, and requires that no Rotor package arrived.
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    // No `.rotor = true`: this program is the host of each colibri object, so colibri's build
    // requests no Rotor for it.
    const colibri = b.dependency("colibri", .{ .target = target, .release = true });
    // Decision 97 as amended on 2026-09-30: the program probes its CPU through stdx's `platform`,
    // from the stdx colibri pins.
    const stdx = b.dependency("stdx", .{ .target = target, .release = true });

    const exe = b.addExecutable(.{ .name = "consumer-hosted", .root_module = program(b, "main.zig", target) });
    exe.root_module.addImport("colibri", colibri.module("colibri"));
    exe.root_module.addImport("tls", colibri.module("tls"));
    exe.root_module.addImport("h11", colibri.module("h11"));
    exe.root_module.addImport("platform", stdx.module("platform"));
    b.step("run", "Run the hosted consumer").dependOn(&b.addRunArtifact(exe).step);

    // Decision 159: a program that names `.private` in a build with no Rotor does not compile.
    // tools/consumer_check.sh builds this step and requires it to fail with colibri's message.
    // The step installs the program, because Zig compiles an executable only when its file is
    // used.
    const private = b.addExecutable(.{ .name = "consumer-private", .root_module = program(b, "private.zig", target) });
    private.root_module.addImport("colibri", colibri.module("colibri"));
    b.step("private", "Compile a program that names .private with no Rotor").dependOn(&b.addInstallArtifact(private, .{}).step);
}

/// One program of this project, built ReleaseSafe as colibri is.
fn program(b: *std.Build, root_source_file: []const u8, target: std.Build.ResolvedTarget) *std.Build.Module {
    return b.createModule(.{
        .root_source_file = b.path(root_source_file),
        .target = target,
        .optimize = .ReleaseSafe,
        // `getentropy`, the source each TLS session draws from.
        .link_libc = true,
    });
}
