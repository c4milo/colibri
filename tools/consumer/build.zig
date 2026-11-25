//! A project that depends on colibri as a package, the way README.md tells one to.
//! `tools/consumer_check.sh` fetches colibri's working tree into it and builds and runs it, so the
//! `build.zig` lines README.md and docs/usage.md show are lines that work: tools/doc_snippets.sh
//! finds each of them here.
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const exe = b.addExecutable(.{
        .name = "consumer",
        .root_module = b.createModule(.{
            .root_source_file = b.path("main.zig"),
            .target = target,
            .optimize = .ReleaseSafe,
        }),
    });
    // Decision 170: `colibri` is the one module of the package. Its root names each library
    // module, so the program writes `colibri.server`, `colibri.client`, `colibri.tls` and
    // `colibri.h2`, and imports no other module of colibri.
    // Decision 159: `.rotor = true` asks for Rotor, the loop of the `.private` kind of
    // `colibri.Server` and `colibri.Client`, which this program uses. A program that uses the
    // protocol modules or the `.hosted` kind alone leaves the option out, and fetches no Rotor
    // (`tools/consumer_hosted/`).
    const colibri = b.dependency("colibri", .{ .target = target, .release = true, .rotor = true });
    exe.root_module.addImport("colibri", colibri.module("colibri"));
    // Decision 97 as amended on 2026-09-30: the program probes its CPU through stdx's `platform`, from
    // the stdx colibri pins and with the options colibri gives it, so both reach one module and one
    // `platform.Cpu`, the probe colibri's `tls.Cpu` holds. stdx exports the one module `stdx`
    // (decision 171), so the program writes `@import("stdx").platform`, and codes content with
    // `@import("stdx").compress.gzip`.
    const stdx = b.dependency("stdx", .{ .target = target, .release = true });
    exe.root_module.addImport("stdx", stdx.module("stdx"));
    // Decision 170: the package exports `colibri` alone. tools/consumer_check.sh passes
    // `-Dnamed-module=h2` and requires the build to stop, because the package has no module of
    // that name.
    if (b.option([]const u8, "named-module", "Ask colibri's package for a module of this name")) |name| {
        _ = colibri.module(name);
    }

    const run = b.addRunArtifact(exe);
    b.step("run", "Run the consumer").dependOn(&run.step);

    // Design §8 step 16's check: a program that runs `colibri.tls` and defines no `ch_assert_fail`
    // does not link. tools/consumer_check.sh builds this step and requires it to fail, naming the hook.
    // The step installs the program, because Zig links an executable only when its file is used.
    const without_assert = b.addExecutable(.{
        .name = "without-assert",
        .root_module = b.createModule(.{
            .root_source_file = b.path("without_assert.zig"),
            .target = target,
            .optimize = .ReleaseSafe,
        }),
    });
    without_assert.root_module.addImport("colibri", colibri.module("colibri"));
    b.step("without-assert", "Link a program that uses tls and defines no ch_assert_fail").dependOn(&b.addInstallArtifact(without_assert, .{}).step);
}
