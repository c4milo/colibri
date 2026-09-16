//! `zig build lint`: the cognitive-complexity score, then the tools/lint rules over the tree, then
//! the same rules over a canary tree. build.zig stays short (CLAUDE.md, Layout), so the wiring
//! lives here.
//!
//! The rules run with no `--rule` argument, so every rule tools/lint/main.zig registers gates the
//! build. A clean tree cannot show that: a run that dropped a rule passes a tree that rule would
//! have passed anyway. The canary can. It is a tree written into the build cache holding one
//! violation of every rule, and the lint must exit 1 over it and print each rule of `canary_rules`
//! on stdout. Both runs take their arguments from `add_rules_run`, so a change to how the rules
//! are selected reaches the canary too.
const std = @import("std");

/// The cognitive-complexity threshold of CLAUDE.md (Conventions). Never raised: a function over
/// it is split.
const cognitive_complexity_max = "15";

/// Every rule the canary must see reported: every rule tools/lint/main.zig registers.
const canary_rules = [_][]const u8{
    "heap",
    "io",
    "determinism",
    "unbounded-loop",
    "relative-import",
    "module-graph",
    "markdown",
    "file-length",
    "magic-numbers",
};

/// The most lines a hand-written file may hold (tools/lint/file_length.zig).
const file_length_max_lines = 500;

/// One violation of each Zig rule under `src/`, in the order `canary_rules` names them, then enough
/// comment lines to pass the file-length limit.
const canary_source =
    \\const std = @import("std");
    \\const other = @import("../other.zig");
    \\pub fn canary(allocator: std.mem.Allocator) void {
    \\    _ = allocator;
    \\    _ = std.posix;
    \\    _ = std.time;
    \\    while (true) {}
    \\    var buffer: [4096]u8 = undefined;
    \\    _ = &buffer;
    \\}
    \\
++ "//\n" ** file_length_max_lines;

/// A fence with no language, which the markdown rule refuses.
const canary_markdown =
    \\# canary
    \\
    \\```
    \\code
    \\```
    \\
;

/// An import build/modules.zig must never give `quic`, which the module-graph rule refuses.
const canary_modules =
    \\pub fn add() void {
    \\    quic.addImport("http", http);
    \\}
    \\
;

pub const Options = struct {
    /// Every directory the complexity score reads, beside build.zig itself.
    source_directories: []const []const u8,
    /// Every directory the tools/lint rules read.
    rule_directories: []const []const u8,
    /// The complexity tool, built on pepegrillo.
    complexity: *std.Build.Step.Compile,
    /// The tools/lint driver, built on pepegrillo.
    rules: *std.Build.Step.Compile,
};

pub fn add(b: *std.Build, options: Options) *std.Build.Step {
    const complexity_run = b.addRunArtifact(options.complexity);
    complexity_run.addArgs(&.{ "--max", cognitive_complexity_max });
    complexity_run.addFileArg(b.path("build.zig"));
    for (options.source_directories) |directory| {
        complexity_run.addDirectoryArg(b.path(directory));
    }

    const tree_run = add_rules_run(b, options.rules);
    for (options.rule_directories) |directory| {
        tree_run.addDirectoryArg(b.path(directory));
    }
    tree_run.step.dependOn(&complexity_run.step);

    const canary_run = add_rules_run(b, options.rules);
    canary_run.addDirectoryArg(add_canary_tree(b));
    canary_run.expectExitCode(1);
    for (canary_rules) |rule| {
        canary_run.addCheck(.{ .expect_stdout_match = b.fmt("[{s}]", .{rule}) });
    }
    canary_run.step.dependOn(&tree_run.step);

    const lint_step = b.step("lint", "Score cognitive complexity, then run the tools/lint rules");
    lint_step.dependOn(&canary_run.step);
    return lint_step;
}

/// A run of the tools/lint driver with every registered rule enabled. Both runs start here.
fn add_rules_run(b: *std.Build, rules: *std.Build.Step.Compile) *std.Build.Step.Run {
    return b.addRunArtifact(rules);
}

fn add_canary_tree(b: *std.Build) std.Build.LazyPath {
    const tree = b.addWriteFiles();
    _ = tree.add("src/quic/canary.zig", canary_source);
    _ = tree.add("docs/canary.md", canary_markdown);
    _ = tree.add("build/modules.zig", canary_modules);
    return tree.getDirectory();
}
