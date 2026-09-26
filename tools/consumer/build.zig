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

    const run = b.addRunArtifact(exe);
    b.step("run", "Run the consumer").dependOn(&run.step);
}
