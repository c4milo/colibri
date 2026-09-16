//! The generated sources of docs/design.md §8 step 1, and the steps that write and check them.
//! build.zig stays short (CLAUDE.md, Layout), so the wiring lives here.
//!
//! One generator, a tool that writes into `src/` and a check that `zig build test` runs:
//!   - `zig build huffman-table` rewrites src/wire/huffman_table.zig from RFC 7541 Appendix B, and
//!     the test step runs the same tool with `--check`, which fails when the committed table is not
//!     what the RFC text yields.
//!
//! The tool runs on the build host in Debug: a tool never ships.
const std = @import("std");

const rfc7541_path = "docs/rfcs/rfc7541.txt";
const huffman_table_path = "src/wire/huffman_table.zig";

pub const Steps = struct {
    /// `zig build test`.
    test_step: *std.Build.Step,
    /// `zig build test-tools`.
    tool_test_step: *std.Build.Step,
};

pub fn add(b: *std.Build, steps: Steps) void {
    add_huffman_table(b, steps);
}

fn add_huffman_table(b: *std.Build, steps: Steps) void {
    const tool = b.addExecutable(.{
        .name = "huffman_table",
        .root_module = host_module(b, "tools/huffman_table.zig"),
    });

    const write = b.addRunArtifact(tool);
    write.addArg("--write");
    write.addFileArg(b.path(rfc7541_path));
    write.addArg(b.pathFromRoot(huffman_table_path));
    write.has_side_effects = true;
    const write_step = b.step(
        "huffman-table",
        "Rewrite " ++ huffman_table_path ++ " from RFC 7541 Appendix B",
    );
    write_step.dependOn(&write.step);

    const check = b.addRunArtifact(tool);
    check.addArg("--check");
    check.addFileArg(b.path(rfc7541_path));
    check.addFileArg(b.path(huffman_table_path));
    steps.test_step.dependOn(&check.step);

    add_tool_tests(b, steps, tool.root_module, "huffman_table");
}

/// A tool's own tests, run by `zig build test` and `zig build test-tools`.
fn add_tool_tests(b: *std.Build, steps: Steps, module: *std.Build.Module, name: []const u8) void {
    const tests = b.addTest(.{ .name = name, .root_module = module });
    const run = &b.addRunArtifact(tests).step;
    steps.test_step.dependOn(run);
    steps.tool_test_step.dependOn(run);
}

fn host_module(b: *std.Build, root_source_file: []const u8) *std.Build.Module {
    return b.createModule(.{
        .root_source_file = b.path(root_source_file),
        .target = b.graph.host,
        .optimize = .Debug,
    });
}
