//! `zig build guide`: pepegrillo's performance method, the one every performance change follows,
//! installed from the commit `build.zig.zon` pins to `zig-out/docs/performance/`, so a reader finds
//! it at that commit without a clone of pepegrillo beside this one (CLAUDE.md, Read before changing
//! behaviour). Its entry point is `performance.md`, and colibri's appendix to it is
//! `docs/performance.md`.
const std = @import("std");

/// The method's folder, in pepegrillo's tree and under the install prefix alike.
const method_path = "docs/performance";

pub fn add(b: *std.Build, pepegrillo: *std.Build.Dependency) void {
    const guide = b.step("guide", "Install pepegrillo's performance method, the one every change follows, to zig-out/" ++ method_path);
    guide.dependOn(&b.addInstallDirectory(.{
        .source_dir = pepegrillo.path(method_path),
        .install_dir = .prefix,
        .install_subdir = method_path,
    }).step);
}
