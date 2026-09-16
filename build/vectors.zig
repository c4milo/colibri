//! The published vectors colibri decodes in-process (decision 25), and the steps that run them.
//! build.zig stays short (CLAUDE.md, Layout), so the wiring lives here.
//!
//! `zig build hpack-vectors` runs tools/hpack_vectors.zig over the vendored
//! src/hpack/hpack-test-case, and `zig build test` runs the same step. The tool runs on the build
//! host in Debug: a tool never ships.
const std = @import("std");

const hpack_test_case_directory = "src/hpack/hpack-test-case";

pub const Steps = struct {
    /// `zig build test`.
    test_step: *std.Build.Step,
    /// `zig build test-tools`.
    tool_test_step: *std.Build.Step,
};

pub fn add(b: *std.Build, steps: Steps) void {
    const core = host_module(b, "src/core/core.zig");
    const wire = host_module(b, "src/wire/wire.zig");
    wire.addImport("core", core);
    const http = host_module(b, "src/http/http.zig");
    http.addImport("core", core);
    const hpack = host_module(b, "src/hpack/hpack.zig");
    hpack.addImport("core", core);
    hpack.addImport("wire", wire);
    hpack.addImport("http", http);

    const tool_module = host_module(b, "tools/hpack_vectors.zig");
    tool_module.addImport("hpack", hpack);
    const tool = b.addExecutable(.{ .name = "hpack_vectors", .root_module = tool_module });

    const run = b.addRunArtifact(tool);
    run.addDirectoryArg(b.path(hpack_test_case_directory));
    const step = b.step("hpack-vectors", "Decode " ++ hpack_test_case_directory ++ " with the hpack module");
    step.dependOn(&run.step);
    steps.test_step.dependOn(&run.step);

    const tests = b.addTest(.{ .name = "hpack_vectors", .root_module = tool_module });
    const run_tests = &b.addRunArtifact(tests).step;
    steps.test_step.dependOn(run_tests);
    steps.tool_test_step.dependOn(run_tests);
}

fn host_module(b: *std.Build, root_source_file: []const u8) *std.Build.Module {
    return b.createModule(.{
        .root_source_file = b.path(root_source_file),
        .target = b.graph.host,
        .optimize = .Debug,
    });
}
