//! `zig build lint`: the cognitive-complexity score, then the tools/lint rules over the tree, then
//! the same rules over a canary tree. build.zig stays short (CLAUDE.md, Layout), so the wiring
//! is in this file.
//!
//! The rules run with no `--rule` argument, so every rule tools/lint/main.zig registers checks the
//! build. A clean tree cannot show that: a run that dropped a rule passes a tree that rule would
//! have passed anyway. The canary tree shows it. It is a tree written into the build cache holding
//! one violation of every rule, and the lint must exit 1 over it and print each rule of
//! `canary_rules` on stdout. The rotor-import canaries must each print their one finding too.
//! A third run reads a tree of the files that rotor-import allows, and must exit 0 (decision 159).
//! Each run takes its arguments from `add_rules_run`, so a change to how the rules are selected
//! applies to the canary too.
const std = @import("std");

/// The cognitive-complexity threshold of CLAUDE.md (Conventions). Never raised: a function over
/// it is split.
const cognitive_complexity_max = "15";

/// Every rule the canary must see reported: every rule tools/lint/main.zig registers.
const canary_rules = [_][]const u8{
    "heap",
    "io",
    "determinism",
    "testing-clock",
    "unbounded-loop",
    "relative-import",
    "module-graph",
    "markdown",
    "file-length",
    "magic-numbers",
    "rfc-citation",
    "peer-index",
    "static-alignment",
    "global-state",
    "root-exports",
    "rotor-import",
    "type-function-suffix",
    "kept-options-pointer",
};

/// The most lines a hand-written file may hold (tools/lint/file_length.zig).
const file_length_max_lines = 500;

/// One violation of each Zig rule under `src/`, then enough comment lines to pass the file-length
/// limit. (Drop "in the order `canary_rules` names them": the relative-import violation is written first, before heap's.)
const canary_source =
    \\const std = @import("std");
    \\const other = @import("/canary/other.zig");
    \\pub fn canary(allocator: std.mem.Allocator) !void {
    \\    _ = allocator;
    \\    _ = std.posix;
    \\    _ = std.time;
    \\    while (true) {}
    \\    var buffer: [4096]u8 = undefined;
    \\    _ = &buffer;
    \\    if (buffer.len == 0) return error.Empty;
    \\}
    \\var memory: Memory = undefined;
    \\pub fn parse(reader: *Reader, buffer: []u8) !void {
    \\    _ = buffer[0..try reader.take_int_big(u16)];
    \\}
    \\pub fn BlockOf(comptime count: usize) type {
    \\    return [count]u8;
    \\}
    \\pub const Held = struct {
    \\    options: *const Options,
    \\    pub fn init(held: *Held, options: *const Options) void {
    \\        held.* = .{ .options = options };
    \\    }
    \\};
    \\
++ "//\n" ** file_length_max_lines;

/// A clock in `src/testing/`, which the testing-clock rule refuses.
const canary_testing_source =
    \\const std = @import("std");
    \\pub fn canary() void {
    \\    _ = std.time;
    \\}
    \\
;

/// A fence with no language, which the markdown rule refuses.
const canary_markdown =
    \\# canary
    \\
    \\```
    \\code
    \\```
    \\
;

/// A library module's root that exports a file whole, which the root-exports rule refuses.
const canary_root =
    \\pub const frame = @import("frame.zig");
    \\
;

/// An import build/modules.zig must never give `quic`, which the module-graph rule refuses.
const canary_modules =
    \\pub fn add() void {
    \\    quic.addImport("http", http);
    \\}
    \\
;

/// Rotor given to `quic`, which the rotor-import rule refuses in the build (decision 159).
const canary_rotor_build =
    \\pub fn add() void {
    \\    quic.addImport("rotor", rotor);
    \\}
    \\
;

/// An import of Rotor, which the rotor-import rule refuses in `src/server/` and in the driver of
/// `colibri`, and allows in its Rotor adapter and in `src/testing/`.
const canary_rotor_source =
    \\const rotor = @import("rotor");
    \\
;

/// The one finding of each rotor-import canary, with its place.
const canary_rotor_findings = [_][]const u8{
    "build/rotor.zig:2:5: error: [rotor-import]",
    "src/server/canary_rotor.zig:1:15: error: [rotor-import]",
    "src/colibri/client.zig:1:15: error: [rotor-import]",
};

/// What the rotor-import rule allows: Rotor given to `colibri` through a lazy fetch, and an import
/// of Rotor in the Rotor adapter and in `src/testing/`. No rule may report a finding over it.
const allowed_rotor_build =
    \\pub fn add(b: *std.Build) void {
    \\    const rotor = b.lazyDependency("rotor", .{}) orelse return;
    \\    colibri.addImport("rotor", rotor.module("rotor"));
    \\}
    \\
;

pub const Options = struct {
    /// Every directory the complexity score reads, beside build.zig itself.
    source_directories: []const []const u8,
    /// Every directory the tools/lint rules read.
    rule_directories: []const []const u8,
    /// Every file the tools/lint rules read beside those directories.
    rule_files: []const []const u8,
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
    for (options.rule_files) |file| {
        tree_run.addFileArg(b.path(file));
    }
    tree_run.step.dependOn(&complexity_run.step);

    const canary_run = add_rules_run(b, options.rules);
    canary_run.addDirectoryArg(add_canary_tree(b));
    canary_run.expectExitCode(1);
    for (canary_rules) |rule| {
        canary_run.addCheck(.{ .expect_stdout_match = b.fmt("[{s}]", .{rule}) });
    }
    for (canary_rotor_findings) |finding| {
        canary_run.addCheck(.{ .expect_stdout_match = finding });
    }
    canary_run.step.dependOn(&tree_run.step);

    // Decision 159: the files rotor-import allows give no finding, so the run exits 0.
    const allowed_run = add_rules_run(b, options.rules);
    allowed_run.addDirectoryArg(add_allowed_tree(b));
    allowed_run.expectExitCode(0);
    allowed_run.step.dependOn(&canary_run.step);

    const lint_step = b.step("lint", "Score cognitive complexity, then run the tools/lint rules");
    lint_step.dependOn(&allowed_run.step);
    return lint_step;
}

/// A run of the tools/lint driver with every registered rule enabled. Both runs start here.
fn add_rules_run(b: *std.Build, rules: *std.Build.Step.Compile) *std.Build.Step.Run {
    return b.addRunArtifact(rules);
}

fn add_canary_tree(b: *std.Build) std.Build.LazyPath {
    const tree = b.addWriteFiles();
    _ = tree.add("src/quic/canary.zig", canary_source);
    _ = tree.add("src/testing/canary.zig", canary_testing_source);
    _ = tree.add("docs/canary.md", canary_markdown);
    _ = tree.add("build/modules.zig", canary_modules);
    _ = tree.add("src/h2/h2.zig", canary_root);
    _ = tree.add("build/rotor.zig", canary_rotor_build);
    _ = tree.add("src/server/canary_rotor.zig", canary_rotor_source);
    _ = tree.add("src/colibri/client.zig", canary_rotor_source);
    return tree.getDirectory();
}

fn add_allowed_tree(b: *std.Build) std.Build.LazyPath {
    const tree = b.addWriteFiles();
    _ = tree.add("build/rotor.zig", allowed_rotor_build);
    _ = tree.add("src/colibri/rotor_host.zig", canary_rotor_source);
    _ = tree.add("src/testing/canary_rotor.zig", canary_rotor_source);
    return tree.getDirectory();
}
