//! `zig build line-coverage`: the tests of each library module, built in Debug with LLVM and run
//! under kcov by pepegrillo's `coverage` tool (tools/line_coverage.zig). The tool prints the share
//! of each module's lines that the tests run, with a total. kcov runs on Linux alone, and
//! `tools/line_coverage_check.sh` runs the step there, in a container when the host has no kcov 43.
//!
//! The binaries come from the roots of `zig build test-<module>`, so the tests of `tls`, `server`,
//! `client` and `colibri` import the test identity, as they do there. Zig's own x86-64 backend
//! writes an incomplete line table, so each binary uses LLVM. A line that two binaries run counts
//! once: a line of `h2` that the tests of `server` run counts for `h2`.
const std = @import("std");
const assert = std.debug.assert;

/// The tests whose binaries kcov runs, by the names of `zig build test-<name>`: one for each module
/// the package exports (decision 86), whose directory tools/line_coverage.zig names. `tls-keylog`
/// is `tls` again over the objects built `KEYLOG=on`. Its tests run lines of `src/tls/` that the
/// tests of `tls` cannot run, such as the seal of a peer's KeyUpdate.
const counted_tests = [_][]const u8{
    "core", "wire", "http", "tls-provider", "crypto",     "qlog",   "hpack",  "qpack",  "quic",
    "h2",   "h3",   "h11",  "tls",          "tls-keylog", "dnssec", "server", "client", "colibri",
};

/// Adds the step. `unit_tests` is build.zig's list of the unit tests, each with a `name` and a
/// `module`, and holds each name of `counted_tests`. `optimize` is the mode of the module graph.
pub fn add(
    b: *std.Build,
    pepegrillo: *std.Build.Module,
    optimize: std.builtin.OptimizeMode,
    unit_tests: anytype,
) void {
    const step = b.step("line-coverage", "Count the lines of each library module that its tests run, under kcov 43 (Linux)");
    // -Drelease builds the module graph in ReleaseSafe, where the optimizer merges and removes
    // lines, so the count is always of a Debug build.
    if (optimize != .Debug) {
        step.dependOn(&b.addFail("zig build line-coverage counts a Debug build: run it without -Drelease").step);
        return;
    }
    const tool = b.addExecutable(.{ .name = "line_coverage", .root_module = b.createModule(.{
        .root_source_file = b.path("tools/line_coverage.zig"),
        .target = b.graph.host,
        .optimize = .Debug,
        .imports = &.{.{ .name = "pepegrillo", .module = pepegrillo }},
    }) });
    const run = b.addRunArtifact(tool);
    for (counted_tests) |name| {
        const module = module_of(unit_tests, name);
        assert(module.optimize.? == .Debug);
        run.addArtifactArg(b.addTest(.{ .name = name, .root_module = module, .use_llvm = true }));
    }
    // kcov finds each source at the path the compiler wrote, and the tool resolves its directories
    // from the working directory, so the tool runs at the root of the tree.
    run.setCwd(b.path("."));
    run.has_side_effects = true;
    step.dependOn(&run.step);
}

/// The module of the unit tests named `name`. A name that build.zig no longer has stops the build,
/// so the count never omits a module that build.zig renames.
fn module_of(unit_tests: anytype, name: []const u8) *std.Build.Module {
    for (unit_tests) |entry| {
        if (std.mem.eql(u8, entry.name, name)) return entry.module;
    }
    std.debug.panic("line-coverage: build.zig has no unit tests named {s}", .{name});
}
