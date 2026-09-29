//! `zig build guide`: pepegrillo's `docs/performance.md`, the method every performance change
//! follows, installed from the commit `build.zig.zon` pins to `zig-out/docs/performance-method.md`,
//! so a reader finds it at that commit without a clone of pepegrillo beside this one (CLAUDE.md,
//! Read before changing behaviour). colibri's appendix to it is `docs/performance.md`.
const std = @import("std");

/// The installed copy's path under the install prefix.
const installed_path = "docs/performance-method.md";

pub fn add(b: *std.Build, pepegrillo: *std.Build.Dependency) void {
    const guide = b.step("guide", "Install pepegrillo's performance method, the one every change follows, to zig-out/" ++ installed_path);
    guide.dependOn(&b.addInstallFile(pepegrillo.path("docs/performance.md"), installed_path).step);
}
