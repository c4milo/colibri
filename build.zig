//! Build graph for colibri (docs/design.md §8 step 0): `zig build` compiles every module,
//! `zig build lint` scores every function's cognitive complexity and runs the rules of tools/lint
//! over the tree, `zig build test` runs the lint and then every module's unit tests, and
//! `zig build test-<module>` runs one module's tests with nothing else in the graph, which is
//! what a mutation is measured against.
//!
//! `zig build graph-gate` is step 0's own gate: it compiles a source that imports `http` from
//! inside `src/quic/` and requires the compile to fail. That is what shows invariant 26 is held
//! by the build rather than by review.
//!
//! `zig build huffman-table` and `zig build golden` rewrite the generated sources of step 1, and
//! `zig build test` checks both against their sources; build/generated.zig wires them.
//!
//! `zig build lint-commits` checks the commit messages this branch adds and `zig build hooks`
//! points this clone's core.hooksPath at .githooks; neither is part of `zig build test`, because
//! commit shape is a property of the history, not of the code.
//!
//! There are no dependencies, and colibri is meant to keep it that way (CLAUDE.md, Ask before).
//! The module graph is build/modules.zig.
const std = @import("std");
const assert = std.debug.assert;
const modules = @import("build/modules.zig");
const generated = @import("build/generated.zig");

/// The cognitive-complexity threshold of CLAUDE.md (Conventions). Never raised: a function over
/// it is split.
const cognitive_complexity_max = "15";

/// Every directory `zig build lint` scores and `zig build fmt` checks, beside build.zig itself.
const source_directories = [_][]const u8{ "build", "src", "tools" };

/// Every directory the tools/lint rules read: the sources above plus the documents, which the
/// markdown rule covers.
const lint_rule_directories = [_][]const u8{ "build", "src", "tools", "docs" };

/// The tools/lint rules that gate the build. CLAUDE.md (Commands) names all eleven; the ones not
/// listed here are report-only until their findings are settled, and are run by hand.
const lint_rules = [_][]const u8{
    "heap",
    "io",
    "determinism",
    "unbounded-loop",
    "relative-import",
    "module-graph",
    "markdown",
    "file-length",
};

/// Every tool whose own tests `zig build test` runs. A gate that does not check the checkers
/// leaves a rule free to lose its own test with no build saying so.
const tool_test_roots = [_][]const u8{
    "tools/lint/main.zig",
    "tools/cognitive_complexity.zig",
    "tools/commit_lint.zig",
};

/// The git revision range `zig build lint-commits` checks.
const commit_lint_range = "origin/main..HEAD";

/// The directory `zig build hooks` points this clone's core.hooksPath at.
const hooks_directory = ".githooks";

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    // Assertions stay on in production (CLAUDE.md non-negotiable 4), so the build offers Debug
    // and ReleaseSafe only: `-Drelease` selects ReleaseSafe, and the `-Doptimize` option that
    // would admit ReleaseFast or ReleaseSmall is never declared.
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSafe });
    assert(optimize == .Debug or optimize == .ReleaseSafe);

    const graph = modules.add(b, target, optimize);

    const install_step = b.getInstallStep();
    const test_step = b.step("test", "Run the lint, then every module's unit tests");
    test_step.dependOn(add_lint_step(b));

    const unit_test_modules = [_]struct { name: []const u8, module: *std.Build.Module }{
        .{ .name = "core", .module = graph.core },
        .{ .name = "wire", .module = graph.wire },
        .{ .name = "http", .module = graph.http },
        .{ .name = "tls", .module = graph.tls },
        .{ .name = "crypto", .module = graph.crypto },
        .{ .name = "hpack", .module = graph.hpack },
        .{ .name = "qpack", .module = graph.qpack },
        .{ .name = "quic", .module = graph.quic },
        .{ .name = "h2", .module = graph.h2 },
        .{ .name = "h3", .module = graph.h3 },
        .{ .name = "sim", .module = graph.sim },
        .{ .name = "golden", .module = graph.golden },
    };
    var golden_tests: ?*std.Build.Step = null;
    for (unit_test_modules) |entry| {
        const unit_tests = b.addTest(.{ .name = entry.name, .root_module = entry.module });
        install_step.dependOn(&unit_tests.step);
        const run = &b.addRunArtifact(unit_tests).step;
        test_step.dependOn(run);
        add_narrow_test_step(b, entry.name).dependOn(run);
        if (entry.module == graph.golden) golden_tests = run;
    }

    // The tools verify the tree, so they run on the host in Debug: a tool never ships.
    const tool_test_step = add_narrow_test_step(b, "tools");
    for (tool_test_roots) |root| {
        const tool_tests = b.addTest(.{
            .name = std.fs.path.stem(root),
            .root_module = host_module(b, root),
        });
        const run = &b.addRunArtifact(tool_tests).step;
        test_step.dependOn(run);
        tool_test_step.dependOn(run);
    }

    generated.add(b, .{
        .test_step = test_step,
        .tool_test_step = tool_test_step,
        .golden_tests = golden_tests.?,
    });

    test_step.dependOn(add_graph_gate_step(b));
    add_commit_lint_step(b, install_step);
    add_hooks_step(b);

    const fmt_step = b.step("fmt", "Check formatting of every Zig source");
    fmt_step.dependOn(&b.addFmt(.{
        .paths = &(.{"build.zig"} ++ source_directories),
        .check = true,
    }).step);
}

/// `zig build test-<name>`: the tests of one module, or of the tools, with nothing else in the
/// graph. `zig build test` is the gate and stays the gate; these steps are the inner loop of a
/// mutation, which is run against the narrowest target that can catch it.
fn add_narrow_test_step(b: *std.Build, name: []const u8) *std.Build.Step {
    return b.step(
        b.fmt("test-{s}", .{name}),
        b.fmt("Run the {s} tests alone, with nothing else in the graph", .{name}),
    );
}

/// A module compiled for the build host in Debug: every tool, and nothing else.
fn host_module(b: *std.Build, root_source_file: []const u8) *std.Build.Module {
    return b.createModule(.{
        .root_source_file = b.path(root_source_file),
        .target = b.graph.host,
        .optimize = .Debug,
    });
}

/// `zig build lint`: the cognitive-complexity score over build.zig and every source directory at
/// the threshold of CLAUDE.md, then the tools/lint rules over the tree. Both tools run on the
/// build host whatever `-Dtarget` says.
fn add_lint_step(b: *std.Build) *std.Build.Step {
    const complexity = b.addExecutable(.{
        .name = "cognitive_complexity",
        .root_module = host_module(b, "tools/cognitive_complexity.zig"),
    });
    const complexity_run = b.addRunArtifact(complexity);
    complexity_run.addArgs(&.{ "--max", cognitive_complexity_max });
    complexity_run.addFileArg(b.path("build.zig"));
    for (source_directories) |directory| {
        complexity_run.addDirectoryArg(b.path(directory));
    }

    const rules = b.addExecutable(.{
        .name = "lint",
        .root_module = host_module(b, "tools/lint/main.zig"),
    });
    const rules_run = b.addRunArtifact(rules);
    for (lint_rules) |rule| {
        rules_run.addArgs(&.{ "--rule", rule });
    }
    for (lint_rule_directories) |directory| {
        rules_run.addDirectoryArg(b.path(directory));
    }
    rules_run.step.dependOn(&complexity_run.step);

    const lint_step = b.step("lint", "Score cognitive complexity, then run the tools/lint rules");
    lint_step.dependOn(&rules_run.step);
    return lint_step;
}

/// `zig build graph-gate`: design §8 step 0's gate. A module can import only what
/// build/modules.zig gives it, and the way to show that is to try the import that must fail.
/// `tools/graph_gate.zig` compiles `tools/fixtures/quic_imports_http.zig` as a module of the
/// `quic` shape and requires the compile to fail with an unknown-module error. A gate that
/// asserted the rule in a linter would only be checking what the source says; this checks what
/// the build does.
fn add_graph_gate_step(b: *std.Build) *std.Build.Step {
    const gate = b.addExecutable(.{
        .name = "graph_gate",
        .root_module = host_module(b, "tools/graph_gate.zig"),
    });
    const gate_run = b.addRunArtifact(gate);
    gate_run.addArg(b.graph.zig_exe);
    gate_run.addDirectoryArg(b.path("src"));
    gate_run.addDirectoryArg(b.path("tools/fixtures"));
    // Re-run the gate when the graph it checks changes, not only when the tool does.
    gate_run.addFileInput(b.path("build/modules.zig"));

    const step = b.step("graph-gate", "Require that src/quic/ cannot import an HTTP module");
    step.dependOn(&gate_run.step);
    return step;
}

/// `zig build lint-commits`: the Conventional Commit rules of CLAUDE.md over the commits this
/// branch adds. Not part of `zig build test`: commit shape is a property of the history.
fn add_commit_lint_step(b: *std.Build, install_step: *std.Build.Step) void {
    const tool = b.addExecutable(.{
        .name = "commit_lint",
        .root_module = host_module(b, "tools/commit_lint.zig"),
    });
    install_step.dependOn(&tool.step);
    const run = b.addRunArtifact(tool);
    run.addArgs(&.{ "--range", commit_lint_range });
    const step = b.step("lint-commits", "Check the commit messages this branch adds");
    step.dependOn(&run.step);
}

/// `zig build hooks`: point this clone's core.hooksPath at .githooks, once after cloning.
fn add_hooks_step(b: *std.Build) void {
    const run = b.addSystemCommand(&.{ "git", "config", "core.hooksPath", hooks_directory });
    const step = b.step("hooks", "Point this clone's core.hooksPath at " ++ hooks_directory);
    step.dependOn(&run.step);
}
