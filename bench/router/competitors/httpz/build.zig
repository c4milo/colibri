//! http.zig's router in the router benchmark (bench/router/competitors/run.sh). It builds with Zig
//! 0.17.0, the release http.zig's master targets, at the commit bench/competitors/httpz pins.
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const httpz = b.dependency("httpz", .{ .target = target, .optimize = .ReleaseFast });
    const module = b.createModule(.{
        .root_source_file = b.path("main.zig"),
        .target = target,
        .optimize = .ReleaseFast,
    });
    module.addImport("httpz", httpz.module("httpz"));
    const bench = b.addExecutable(.{ .name = "router-bench", .root_module = module });
    b.installArtifact(bench);
}
