//! colibri lint: the rules of CLAUDE.md and docs/invariants.md that a parser and a line scanner
//! can check, one file per rule under tools/lint/.
//!
//! Run:  lint [--rule NAME]... PATH...
//! Test: zig test tools/lint/main.zig
//!
//! Every PATH is a file, or a directory walked recursively with the `skipped_directories` left
//! out. Every regular file found is handed to every enabled rule; each rule reads the path and
//! decides whether the file is its concern. A `.zig` file is parsed once, and a file that does not
//! parse is reported as a finding of the `parse` pseudo-rule. With no `--rule`, every rule in
//! `rules` runs; with one or more, only those.
//!
//! One line per finding, sorted by path, line, column and rule:
//!
//!     path:line: [rule-name] message
//!
//! Exit status: 0 when nothing was found, 1 when any finding was reported or a file failed to
//! read, 2 on a usage error.
//!
//! This tool is developer tooling. It is never linked into the library, so it allocates, reads the
//! filesystem, and is exempt from the rules it enforces over `src/` (CLAUDE.md, Layout).

const std = @import("std");
const Allocator = std.mem.Allocator;
const Ast = std.zig.Ast;
const Io = std.Io;
const paths = @import("paths.zig");
const report = @import("report.zig");

/// Every rule, in the order `--rule` names are looked up. Each exports a `name` and a
/// `check(context, file)`. build.zig names the same eight in `lint_rules`.
const rules = .{
    @import("heap.zig"),
    @import("io.zig"),
    @import("determinism.zig"),
    @import("unbounded_loop.zig"),
    @import("relative_import.zig"),
    @import("module_graph.zig"),
    @import("markdown.zig"),
    @import("file_length.zig"),
};
const rule_count = rules.len;

/// The rule name a file that fails to parse is reported under.
const parse_rule_name = "parse";

/// Longest path the walk builds.
const max_path_bytes: usize = 4096;

/// Files visited per run across every PATH. More is reported as an error.
const max_files_per_run: usize = 65536;

/// Command-line arguments the tool reads before giving up.
const max_arguments: usize = 1024;

/// Bytes buffered for standard output before a flush.
const output_buffer_bytes: usize = 16 * 1024;

/// Longest parse error message the tool renders.
const max_parse_error_bytes: usize = 512;

/// Directories the walk does not enter: build output, never hand-written.
const skipped_directories = [_][]const u8{ ".zig-cache", "zig-out", ".git" };

const exit_clean: u8 = 0;
const exit_findings: u8 = 1;
const exit_usage: u8 = 2;

const rule_flag = "--rule";

const Options = struct {
    enabled: [rule_count]bool = @splat(true),
    paths: []const []const u8 = &.{},
};

const ArgumentError = error{
    MissingValue,
    UnknownRule,
    UnknownFlag,
    NoPaths,
} || Allocator.Error;

/// Reads `arguments` (without the program name) into `Options`.
fn parse_arguments(arena: Allocator, arguments: []const []const u8) ArgumentError!Options {
    var options: Options = .{};
    var selected: [rule_count]bool = @splat(false);
    var any_selected = false;
    var path_list: std.ArrayList([]const u8) = .empty;
    try path_list.ensureTotalCapacity(arena, arguments.len);
    var index: usize = 0;
    while (index < arguments.len) : (index += 1) {
        const argument = arguments[index];
        if (std.mem.eql(u8, argument, rule_flag)) {
            index += 1;
            if (index >= arguments.len) return error.MissingValue;
            const rule_index = rule_index_of(arguments[index]) orelse return error.UnknownRule;
            selected[rule_index] = true;
            any_selected = true;
        } else if (std.mem.startsWith(u8, argument, "--")) {
            return error.UnknownFlag;
        } else {
            path_list.appendAssumeCapacity(argument);
        }
    }
    if (path_list.items.len == 0) return error.NoPaths;
    if (any_selected) options.enabled = selected;
    options.paths = path_list.items;
    return options;
}

fn rule_index_of(rule_name: []const u8) ?usize {
    inline for (rules, 0..) |rule, index| {
        if (std.mem.eql(u8, rule.name, rule_name)) return index;
    }
    return null;
}

/// One run: the walk, the per-file dispatch, and the counts the exit status is computed from.
const Run = struct {
    context: report.Context,
    enabled: [rule_count]bool,
    files_seen: usize = 0,
    file_errors: usize = 0,
    /// Set by the tests so a passing run writes nothing. `main` leaves it false.
    quiet: bool = false,

    fn lint_path(self: *Run, path: []const u8) !void {
        const stat = Io.Dir.cwd().statFile(self.context.io, path, .{}) catch |failure| {
            return self.file_error(path, @errorName(failure));
        };
        if (stat.kind != .directory) return self.lint_file(path);
        var dir = Io.Dir.cwd().openDir(self.context.io, path, .{ .iterate = true }) catch |failure| {
            return self.file_error(path, @errorName(failure));
        };
        defer dir.close(self.context.io);
        try self.walk_directory(dir, path);
    }

    /// Visits every regular file under `dir`, reported under `root/...`, entering every directory
    /// but the skipped ones.
    fn walk_directory(self: *Run, dir: Io.Dir, root: []const u8) !void {
        var walker = try dir.walkSelectively(self.context.arena);
        defer walker.deinit();
        var path_buffer: [max_path_bytes]u8 = undefined;
        while (try walker.next(self.context.io)) |entry| {
            switch (entry.kind) {
                .directory => if (!is_skipped_directory(entry.basename)) {
                    try walker.enter(self.context.io, entry);
                },
                .file => {
                    const joined = paths.join(&path_buffer, root, entry.path) catch {
                        return self.file_error(entry.path, "PathTooLong");
                    };
                    try self.lint_file(joined);
                },
                else => {},
            }
        }
    }

    fn lint_file(self: *Run, path: []const u8) !void {
        self.files_seen += 1;
        if (self.files_seen > max_files_per_run) return error.TooManyFiles;
        const source = self.context.read_file(path) orelse return self.file_error(path, "Unreadable");
        defer self.context.arena.free(source);
        var tree: Ast = undefined;
        var tree_pointer: ?*const Ast = null;
        if (paths.has_extension(path, paths.zig_extension)) {
            tree = try Ast.parse(self.context.arena, source, .zig);
            if (tree.errors.len == 0) {
                tree_pointer = &tree;
            } else {
                try self.report_parse_error(path, &tree);
            }
        }
        defer if (tree_pointer != null) tree.deinit(self.context.arena);
        try self.dispatch(.{ .path = path, .source = source, .tree = tree_pointer });
    }

    fn dispatch(self: *Run, file: report.File) !void {
        inline for (rules, 0..) |rule, index| {
            if (self.enabled[index]) try rule.check(&self.context, file);
        }
    }

    /// The first parse error, at its token, as the `parse` pseudo-rule.
    fn report_parse_error(self: *Run, path: []const u8, tree: *const Ast) !void {
        const first = tree.errors[0];
        var message_buffer: [max_parse_error_bytes]u8 = undefined;
        var writer: Io.Writer = .fixed(&message_buffer);
        tree.renderError(first, &writer) catch {};
        const location = tree.tokenLocation(0, first.token);
        try self.context.findings.add(
            parse_rule_name,
            path,
            location.line + 1,
            location.column + 1,
            "{s}",
            .{writer.buffered()},
        );
    }

    /// Counts a file the rules could not read, and prints it unless the caller asked for silence.
    /// A test drives `lint_path` over a deliberately missing path and passes; printing there would
    /// put the run under `zig build`'s "failed command" heading on a green run, which is how a
    /// real failure gets lost in the noise. A test prints only when it fails.
    fn file_error(self: *Run, path: []const u8, reason: []const u8) void {
        self.file_errors += 1;
        if (self.quiet) return;
        std.debug.print("{s}: error: {s}\n", .{ path, reason });
    }
};

fn is_skipped_directory(basename: []const u8) bool {
    for (skipped_directories) |skipped| {
        if (std.mem.eql(u8, basename, skipped)) return true;
    }
    return false;
}

/// 0 when nothing was found and every file was read, else 1.
fn exit_status(finding_count: usize, file_errors: usize) u8 {
    return if (finding_count != 0 or file_errors != 0) exit_findings else exit_clean;
}

fn print_usage() void {
    std.debug.print("usage: lint [--rule NAME]... PATH...\nrules:", .{});
    inline for (rules) |rule| std.debug.print(" {s}", .{rule.name});
    std.debug.print("\n", .{});
}

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const all_arguments = try init.minimal.args.toSlice(arena);
    if (all_arguments.len > max_arguments) return error.TooManyArguments;
    const arguments = if (all_arguments.len == 0) all_arguments else all_arguments[1..];
    const options = parse_arguments(arena, arguments) catch |failure| {
        std.debug.print("error: {s}\n", .{@errorName(failure)});
        print_usage();
        std.process.exit(exit_usage);
    };

    var run: Run = .{
        .context = .{ .arena = arena, .io = init.io, .findings = .{ .arena = arena } },
        .enabled = options.enabled,
    };
    for (options.paths) |path| try run.lint_path(path);
    run.context.findings.sort();

    var output_buffer: [output_buffer_bytes]u8 = undefined;
    // Streaming, not positional: a positional writer starts at offset 0 and overwrites earlier
    // output when standard output is redirected to a file.
    var writer = Io.File.stdout().writerStreaming(init.io, &output_buffer);
    try run.context.findings.write(&writer.interface);
    try writer.interface.flush();
    std.process.exit(exit_status(run.context.findings.count(), run.file_errors));
}

// Tests. The rules carry their own; these pin the walk, the arguments, the parse pseudo-rule and
// the exit status. The support files are pulled in so `zig test tools/lint/main.zig` runs every
// test the tool holds.

const testing = std.testing;

comptime {
    _ = @import("ast.zig");
    _ = @import("chain_scan.zig");
    _ = @import("paths.zig");
    _ = @import("report.zig");
    _ = @import("text.zig");
}

test "parse_arguments reads --rule and paths, and defaults to every rule" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const options = try parse_arguments(arena, &.{ "--rule", "heap", "--rule", "markdown", "src", "docs" });
    try testing.expect(options.enabled[rule_index_of("heap").?]);
    try testing.expect(options.enabled[rule_index_of("markdown").?]);
    try testing.expect(!options.enabled[rule_index_of("determinism").?]);
    try testing.expectEqual(2, options.paths.len);
    try testing.expectEqualStrings("docs", options.paths[1]);

    const defaults = try parse_arguments(arena, &.{"src"});
    for (defaults.enabled) |enabled| try testing.expect(enabled);
}

test "parse_arguments reports usage errors" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try testing.expectError(error.NoPaths, parse_arguments(arena, &.{ "--rule", "heap" }));
    try testing.expectError(error.MissingValue, parse_arguments(arena, &.{ "src", "--rule" }));
    try testing.expectError(error.UnknownRule, parse_arguments(arena, &.{ "--rule", "tabs", "src" }));
    try testing.expectError(error.UnknownFlag, parse_arguments(arena, &.{ "--max", "src" }));
}

test "the eight rules of build.zig are the eight rules registered here" {
    const expected = [_][]const u8{
        "heap",
        "io",
        "determinism",
        "unbounded-loop",
        "relative-import",
        "module-graph",
        "markdown",
        "file-length",
    };
    try testing.expectEqual(expected.len, rule_count);
    inline for (rules, 0..) |rule, index| {
        try testing.expectEqualStrings(expected[index], rule.name);
        try testing.expectEqual(index, rule_index_of(rule.name).?);
        for (rule.name) |byte| try testing.expect(std.ascii.isLower(byte) or byte == '-');
    }
}

test "the exit status is 1 on a finding or a file error and 0 otherwise" {
    try testing.expectEqual(exit_clean, exit_status(0, 0));
    try testing.expectEqual(exit_findings, exit_status(1, 0));
    try testing.expectEqual(exit_findings, exit_status(0, 1));
    try testing.expectEqual(exit_findings, exit_status(3, 2));
}

/// Writes the fixture tree the walk tests read: two files to lint, one under a subdirectory, and
/// one each under the skipped directories.
fn write_walk_fixture(dir: Io.Dir) !void {
    const io = testing.io;
    const spinner = "pub fn spin() void {\n    while (true) {}\n}\n";
    try dir.createDirPath(io, "src/quic");
    try dir.writeFile(io, .{ .sub_path = "src/quic/quic.zig", .data = spinner });
    try dir.createDirPath(io, "docs");
    try dir.writeFile(io, .{ .sub_path = "docs/design.md", .data = "3b. Folded.\n" });
    try dir.createDirPath(io, ".zig-cache/deep");
    try dir.writeFile(io, .{ .sub_path = ".zig-cache/deep/cached.zig", .data = spinner });
    try dir.createDirPath(io, "zig-out");
    try dir.writeFile(io, .{ .sub_path = "zig-out/built.zig", .data = spinner });
}

test "the walk visits every regular file, skips the build output, and reports root-joined paths" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var tmp = testing.tmpDir(.{ .iterate = true });
    defer tmp.cleanup();
    try write_walk_fixture(tmp.dir);

    var run: Run = .{
        .context = .{ .arena = arena, .io = testing.io, .findings = .{ .arena = arena } },
        .enabled = @splat(true),
    };
    // The reported path is the root label joined with the entry's path; the files are read through
    // `tmp.dir`, so the label need not exist.
    var root_buffer: [max_path_bytes]u8 = undefined;
    const root = try std.fmt.bufPrint(&root_buffer, ".zig-cache/tmp/{s}", .{tmp.sub_path});
    try run.walk_directory(tmp.dir, root);
    run.context.findings.sort();

    try testing.expectEqual(2, run.files_seen);
    try testing.expectEqual(0, run.file_errors);
    const findings = run.context.findings.items.items;
    try testing.expectEqual(2, findings.len);
    try testing.expectEqualStrings("markdown", findings[0].rule);
    try testing.expect(std.mem.endsWith(u8, findings[0].path, "/docs/design.md"));
    try testing.expectEqualStrings("unbounded-loop", findings[1].rule);
    try testing.expect(std.mem.startsWith(u8, findings[1].path, root));
}

test "lint_path on a single file runs the rules on it" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDirPath(testing.io, "src");
    try tmp.dir.writeFile(testing.io, .{
        .sub_path = "src/spin.zig",
        .data = "pub fn spin() void {\n    while (true) {}\n}\n",
    });
    var path_buffer: [max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buffer, ".zig-cache/tmp/{s}/src/spin.zig", .{tmp.sub_path});

    var run: Run = .{
        .context = .{ .arena = arena, .io = testing.io, .findings = .{ .arena = arena } },
        .enabled = @splat(true),
    };
    try run.lint_path(path);
    try testing.expectEqual(1, run.files_seen);
    try testing.expectEqual(1, run.context.findings.count());
    try testing.expectEqual(exit_findings, exit_status(run.context.findings.count(), run.file_errors));
}

test "a missing path is a file error and a clean file exits 0" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "clean.zig", .data = "const one = 1;\n" });
    var path_buffer: [max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buffer, ".zig-cache/tmp/{s}/clean.zig", .{tmp.sub_path});

    var run: Run = .{
        .context = .{ .arena = arena, .io = testing.io, .findings = .{ .arena = arena } },
        .enabled = @splat(true),
        .quiet = true,
    };
    try run.lint_path(path);
    try testing.expectEqual(exit_clean, exit_status(run.context.findings.count(), run.file_errors));
    try run.lint_path(".zig-cache/tmp/no-such-directory/missing.zig");
    try testing.expectEqual(1, run.file_errors);
    try testing.expectEqual(exit_findings, exit_status(run.context.findings.count(), run.file_errors));
}

test "a .zig file that does not parse is reported under the parse pseudo-rule" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "broken.zig", .data = "fn broken( {\n" });
    var path_buffer: [max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_buffer, ".zig-cache/tmp/{s}/broken.zig", .{tmp.sub_path});

    var run: Run = .{
        .context = .{ .arena = arena, .io = testing.io, .findings = .{ .arena = arena } },
        .enabled = @splat(true),
    };
    try run.lint_path(path);
    const findings = run.context.findings.items.items;
    try testing.expectEqual(1, findings.len);
    try testing.expectEqualStrings(parse_rule_name, findings[0].rule);
    try testing.expectEqual(1, findings[0].line);
    try testing.expect(findings[0].message.len != 0);
}

test "--rule limits the dispatch to the named rules" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const source: [:0]const u8 =
        "const page = std.heap.page_allocator;\npub fn spin() void {\n    while (true) {}\n}\n";
    var tree = try Ast.parse(arena, source, .zig);
    defer tree.deinit(arena);

    var run: Run = .{
        .context = .{ .arena = arena, .io = testing.io, .findings = .{ .arena = arena } },
        .enabled = (try parse_arguments(arena, &.{ "--rule", "heap", "src" })).enabled,
    };
    try run.dispatch(.{ .path = "src/quic/quic.zig", .source = source, .tree = &tree });
    const findings = run.context.findings.items.items;
    try testing.expectEqual(1, findings.len);
    try testing.expectEqualStrings("heap", findings[0].rule);
}
