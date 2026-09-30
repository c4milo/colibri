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
    const colibri = b.dependency("colibri", .{ .target = target, .release = true });
    exe.root_module.addImport("h11", colibri.module("h11"));
    exe.root_module.addImport("http", colibri.module("http"));
    exe.root_module.addImport("h2", colibri.module("h2"));
    exe.root_module.addImport("tls", colibri.module("tls"));
    // Decision 101: colibri's package exports stdx's codecs.
    exe.root_module.addImport("gzip", colibri.module("gzip"));
    // Decision 97 as amended: stdx's `platform`, which answers the TLS values' `aes_instructions`.
    exe.root_module.addImport("platform", colibri.module("platform"));

    const run = b.addRunArtifact(exe);
    b.step("run", "Run the consumer").dependOn(&run.step);

    // Design §8 step 16's check: a program that links `tls` and defines no `ch_assert_fail` does
    // not link. tools/consumer_check.sh builds this step and requires it to fail, naming the hook.
    // The step installs the program, because Zig links an executable only when its file is used.
    const without_assert = b.addExecutable(.{
        .name = "without-assert",
        .root_module = b.createModule(.{
            .root_source_file = b.path("without_assert.zig"),
            .target = target,
            .optimize = .ReleaseSafe,
        }),
    });
    without_assert.root_module.addImport("tls", colibri.module("tls"));
    b.step("without-assert", "Link a program that uses tls and defines no ch_assert_fail").dependOn(&b.addInstallArtifact(without_assert, .{}).step);
}
