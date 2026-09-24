//! The published vectors colibri decodes in-process (decision 25), and the steps that run them.
//! build.zig stays short (CLAUDE.md, Layout), so this file holds the wiring.
//!
//! `zig build hpack-vectors` runs tools/hpack_vectors.zig over the vendored
//! src/hpack/hpack-test-case, `zig build h2-frames` runs tools/h2_frames.zig over the vendored
//! src/h2/http2-frame-test-case, and `zig build qpack-vectors` runs tools/qpack_vectors.zig over
//! the qifs package (decision 75); `zig build test` runs all three steps. Each tool runs on the build host
//! in Debug over its own host copy of the module graph: a tool never ships.
const std = @import("std");

const hpack_test_case_directory = "src/hpack/hpack-test-case";
const http2_frame_test_case_directory = "src/h2/http2-frame-test-case";

pub const Steps = struct {
    /// `zig build test`.
    test_step: *std.Build.Step,
    /// `zig build test-tools`.
    tool_test_step: *std.Build.Step,
};

/// One vectors tool: its source, the module it imports, the step that runs it and the directory
/// it runs over.
const Tool = struct {
    name: []const u8,
    root_source_file: []const u8,
    module_name: []const u8,
    module: *std.Build.Module,
    step_name: []const u8,
    directory: std.Build.LazyPath,
};

/// `qifs` is the qpackers/qifs package's directory, which build.zig requests.
pub fn add(b: *std.Build, steps: Steps, qifs: std.Build.LazyPath) void {
    const core = host_module(b, "src/core/core.zig");
    const wire = host_module(b, "src/wire/wire.zig");
    wire.addImport("core", core);
    const http = host_module(b, "src/http/http.zig");
    http.addImport("core", core);
    const hpack = host_module(b, "src/hpack/hpack.zig");
    hpack.addImport("core", core);
    hpack.addImport("wire", wire);
    hpack.addImport("http", http);
    const tls = host_module(b, "src/tls/tls.zig");
    tls.addImport("core", core);
    // The same imports build/modules.zig gives `h2`.
    const h2 = host_module(b, "src/h2/h2.zig");
    h2.addImport("core", core);
    h2.addImport("wire", wire);
    h2.addImport("http", http);
    h2.addImport("hpack", hpack);
    h2.addImport("tls", tls);
    // The same imports build/modules.zig gives `qpack`.
    const qpack = host_module(b, "src/qpack/qpack.zig");
    qpack.addImport("core", core);
    qpack.addImport("wire", wire);
    qpack.addImport("http", http);

    add_tool(b, steps, .{
        .name = "hpack_vectors",
        .root_source_file = "tools/hpack_vectors.zig",
        .module_name = "hpack",
        .module = hpack,
        .step_name = "hpack-vectors",
        .directory = b.path(hpack_test_case_directory),
    });
    add_tool(b, steps, .{
        .name = "h2_frames",
        .root_source_file = "tools/h2_frames.zig",
        .module_name = "h2",
        .module = h2,
        .step_name = "h2-frames",
        .directory = b.path(http2_frame_test_case_directory),
    });
    add_tool(b, steps, .{
        .name = "qpack_vectors",
        .root_source_file = "tools/qpack_vectors.zig",
        .module_name = "qpack",
        .module = qpack,
        .step_name = "qpack-vectors",
        .directory = qifs,
    });
}

/// Wires one tool: its run step over its directory, hooked into `zig build test`, and its own
/// tests, hooked into `zig build test` and `zig build test-tools`.
fn add_tool(b: *std.Build, steps: Steps, tool: Tool) void {
    const tool_module = host_module(b, tool.root_source_file);
    tool_module.addImport(tool.module_name, tool.module);
    const executable = b.addExecutable(.{ .name = tool.name, .root_module = tool_module });

    const run = b.addRunArtifact(executable);
    run.addDirectoryArg(tool.directory);
    const step = b.step(
        tool.step_name,
        b.fmt("Run {s} with the {s} module", .{ tool.root_source_file, tool.module_name }),
    );
    step.dependOn(&run.step);
    steps.test_step.dependOn(&run.step);

    const tests = b.addTest(.{ .name = tool.name, .root_module = tool_module });
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
