//! The generated sources of docs/design.md §8 step 1, and the steps that write and check them.
//! build.zig stays short (CLAUDE.md, Layout), so the wiring lives here.
//!
//! Two generators, each a tool that writes into `src/` and a check that `zig build test` runs:
//!   - `zig build huffman-table` rewrites src/wire/huffman_table.zig from RFC 7541 Appendix B, and
//!     the test step runs the same tool with `--check`, which fails when the committed table is not
//!     what the RFC text yields.
//!   - `zig build static-table` rewrites src/hpack/static_table.zig from RFC 7541 Appendix A, and
//!     the test step runs the same tool with `--check`.
//!   - `zig build golden` rewrites the corpus under src/golden/ from its pure case table, and
//!     `zig build golden-check` runs the golden module's tests, which compare the committed files
//!     with the same table through `@embedFile`.
//!
//! Both tools run on the build host in Debug: a tool never ships.
const std = @import("std");

const rfc7541_path = "docs/rfcs/rfc7541.txt";
const huffman_table_path = "src/wire/huffman_table.zig";
const static_table_path = "src/hpack/static_table.zig";
const golden_directory = "src/golden";

pub const Steps = struct {
    /// `zig build test`.
    test_step: *std.Build.Step,
    /// `zig build test-tools`.
    tool_test_step: *std.Build.Step,
    /// The run of the golden module's unit tests, which is what golden-check is.
    golden_tests: *std.Build.Step,
};

pub fn add(b: *std.Build, steps: Steps) void {
    add_huffman_table(b, steps);
    add_static_table(b, steps);
    add_golden(b, steps);
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

fn add_static_table(b: *std.Build, steps: Steps) void {
    const tool = b.addExecutable(.{
        .name = "static_table",
        .root_module = host_module(b, "tools/static_table.zig"),
    });

    const write = b.addRunArtifact(tool);
    write.addArg("--write");
    write.addFileArg(b.path(rfc7541_path));
    write.addArg(b.pathFromRoot(static_table_path));
    write.has_side_effects = true;
    const write_step = b.step(
        "static-table",
        "Rewrite " ++ static_table_path ++ " from RFC 7541 Appendix A",
    );
    write_step.dependOn(&write.step);

    const check = b.addRunArtifact(tool);
    check.addArg("--check");
    check.addFileArg(b.path(rfc7541_path));
    check.addFileArg(b.path(static_table_path));
    steps.test_step.dependOn(&check.step);

    add_tool_tests(b, steps, tool.root_module, "static_table");
}

fn add_golden(b: *std.Build, steps: Steps) void {
    const core = host_module(b, "src/core/core.zig");
    const wire = host_module(b, "src/wire/wire.zig");
    wire.addImport("core", core);
    const http = host_module(b, "src/http/http.zig");
    http.addImport("core", core);
    const hpack = host_module(b, "src/hpack/hpack.zig");
    hpack.addImport("core", core);
    hpack.addImport("wire", wire);
    hpack.addImport("http", http);
    const corpus = host_module(b, "src/golden/corpus.zig");
    corpus.addImport("core", core);
    corpus.addImport("wire", wire);
    corpus.addImport("hpack", hpack);

    const tool_module = host_module(b, "tools/golden.zig");
    tool_module.addImport("golden_corpus", corpus);
    const tool = b.addExecutable(.{ .name = "golden", .root_module = tool_module });

    const write = b.addRunArtifact(tool);
    write.addArg(b.pathFromRoot(golden_directory));
    write.has_side_effects = true;
    const write_step = b.step(
        "golden",
        "Rewrite the corpus under " ++ golden_directory ++ " from its case table",
    );
    write_step.dependOn(&write.step);

    const check_step = b.step("golden-check", "Check the committed corpus against its case table");
    check_step.dependOn(steps.golden_tests);

    add_tool_tests(b, steps, tool_module, "golden");
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
