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
    // Decision 100: `server` and `client` put one set of calls over every version, and `tls` holds
    // the values their handshakes take. The protocol modules follow, for a program that drives one
    // version by itself.
    const colibri = b.dependency("colibri", .{ .target = target, .release = true });
    exe.root_module.addImport("server", colibri.module("server"));
    exe.root_module.addImport("client", colibri.module("client"));
    exe.root_module.addImport("tls", colibri.module("tls"));
    exe.root_module.addImport("h11", colibri.module("h11"));
    exe.root_module.addImport("http", colibri.module("http"));
    exe.root_module.addImport("h2", colibri.module("h2"));
    // Decision 101: colibri's package exports stdx's codecs.
    exe.root_module.addImport("gzip", colibri.module("gzip"));
    // Decision 97 as amended on 2026-09-30: the program probes its CPU through stdx's `platform`, from
    // the stdx colibri pins and with the options colibri gives it, so both reach one module and one
    // `platform.Cpu`, the type colibri's TLS values take.
    const stdx = b.dependency("stdx", .{ .target = target, .release = true });
    exe.root_module.addImport("platform", stdx.module("platform"));

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
