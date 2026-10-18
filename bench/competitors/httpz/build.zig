//! http.zig, the Zig h11 server colibri's is measured against (design §8 step 13g). It builds with
//! Zig 0.17.0, the release http.zig's master targets, which bench.yml installs for it alone:
//! colibri itself stays on Zig 0.16.
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseFast });
    const httpz = b.dependency("httpz", .{ .target = target, .optimize = optimize });
    const module = b.createModule(.{
        .root_source_file = b.path("main.zig"),
        .target = target,
        .optimize = optimize,
    });
    module.addImport("httpz", httpz.module("httpz"));
    const server = b.addExecutable(.{ .name = "colibri-bench-httpz", .root_module = module });
    b.installArtifact(server);
}
