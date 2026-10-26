//! colibri's router in the router benchmark (bench/router/competitors/run.sh). It builds from a
//! copy of this directory in the tree's `.zig-cache`, three levels below the tree, so the packages
//! that Zig fetches stay out of `bench/`.
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    // ReleaseFast, which colibri does not offer, shows what the assertions cost in this
    // benchmark alone.
    const fast = b.option(bool, "fast", "Build ReleaseFast, in place of ReleaseSafe") orelse false;
    const colibri = b.dependency("colibri", .{ .target = target, .release = true });
    const module = b.createModule(.{
        .root_source_file = b.path("main.zig"),
        .target = target,
        .optimize = if (fast) .ReleaseFast else .ReleaseSafe,
    });
    module.addImport("server", colibri.module("server"));
    module.addImport("http", colibri.module("http"));
    module.addAnonymousImport("github_routes.txt", .{ .root_source_file = b.path("github_routes.txt") });
    const bench = b.addExecutable(.{ .name = "router-bench", .root_module = module });
    b.installArtifact(bench);
}
