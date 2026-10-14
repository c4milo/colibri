//! The probes of the router's cost (design §8 step 21e, decision 122 as amended on 2026-10-14).
//! A project of its own that depends on the colibri tree two levels up as a path package.
//! `bench/routes/compile_time.sh` and `bench/routes/run_time.sh` run it from a copy inside that
//! tree's `.zig-cache`, so the packages that Zig fetches stay out of `bench/`.
//!   - `zig build compile -Dtable=<name> -Dstamp=<n>` compiles one table of `tables.zig` into a
//!     Debug test binary for the host and runs it. A new stamp makes the compiler build it again.
//!   - `zig build probe -Dtarget=<linux target>` installs `run_time.zig`, which matches one path
//!     against a table of literals a fixed number of times, in ReleaseSafe.
const std = @import("std");

/// The tables of `tables.zig`, by the name of each.
const Table = enum {
    one,
    literals_256_parameter,
    literals_512_parameter,
    literals_512_literal,
    routes_test_256,
    resources_50,
    mixed_338,
    named_256,
};

pub fn build(b: *std.Build) void {
    const table = b.option(Table, "table", "The table that `compile` builds") orelse .one;
    const stamp = b.option(u64, "stamp", "A value that makes `compile` build again") orelse 0;
    const host = b.graph.host;
    const colibri_debug = b.dependency("colibri", .{ .target = host, .release = false });
    const options = b.addOptions();
    options.addOption(Table, "table", table);
    options.addOption(u64, "stamp", stamp);
    const compile_module = b.createModule(.{
        .root_source_file = b.path("compile_time.zig"),
        .target = host,
        .optimize = .Debug,
    });
    compile_module.addImport("server", colibri_debug.module("server"));
    compile_module.addImport("http", colibri_debug.module("http"));
    compile_module.addOptions("options", options);
    const compile_test = b.addTest(.{ .name = "compile-time", .root_module = compile_module });
    b.step("compile", "Compile one table in a Debug test binary and run it").dependOn(&b.addRunArtifact(compile_test).step);

    const target = b.standardTargetOptions(.{});
    const colibri = b.dependency("colibri", .{ .target = target, .release = true });
    const probe_module = b.createModule(.{
        .root_source_file = b.path("run_time.zig"),
        .target = target,
        .optimize = .ReleaseSafe,
    });
    probe_module.addImport("server", colibri.module("server"));
    probe_module.addImport("http", colibri.module("http"));
    const probe = b.addExecutable(.{ .name = "probe", .root_module = probe_module });
    b.step("probe", "Install the run-time probe").dependOn(&b.addInstallArtifact(probe, .{}).step);
}
