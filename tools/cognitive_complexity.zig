//! Cognitive complexity linter for Zig source, and the check behind the
//! CLAUDE.md rule that a function stays at cognitive complexity 15 or less.
//!
//! Run:  cognitive_complexity --max <N> <path>...
//! Test: zig test tools/cognitive_complexity.zig
//!
//! Each path is a file, or a directory walked recursively for `.zig` files
//! with `.git`, `.zig-cache` and `zig-out` skipped. The tool parses each file
//! with `std.zig.Ast`, scores every function and every `test` block, and
//! prints one line per declaration over the threshold:
//!
//!     path:line: name scored SCORE (max N)
//!
//! It reports every violation, not the first, and then exits 1. When nothing
//! is over the threshold it prints one summary line and exits 0. A usage error
//! exits 2.
//!
//! Definition: SonarSource Cognitive Complexity (G. Ann Campbell, v1.2),
//! mapped onto Zig syntax as follows. The mapping is settled; the scorer and
//! its tests are `cognitive_complexity_scorer.zig`.
//!
//! Structural increments. Each adds 1 plus the nesting level at that point,
//! and the nesting level rises by one inside its body:
//!   - `if`, as a statement or as an expression, with or without a payload
//!     capture (`if (optional) |value|`).
//!   - `switch`: 1 for the whole switch, never one per prong. Prong bodies sit
//!     one level deeper than the switch; prongs add no level of their own, and
//!     `inline` prongs and the `else` prong are ordinary prongs.
//!   - `for` and `while`, including `inline for` and `inline while`. The loop
//!     condition and inputs sit at the loop's own level; the body and the
//!     `while` continue expression sit one level deeper.
//!   - `catch`. Every `catch` has an operand, a block or an expression, with or
//!     without an `|err|` payload, so every `catch` is structural and its
//!     operand sits one level deeper.
//!   - `orelse` whose operand is a block. The block sits one level deeper.
//!
//! Increments that raise no nesting level. Each adds exactly 1:
//!   - `else` on an `if`, `for`, or `while`, statement or expression.
//!   - `else if`: the `if` written after an `else` adds 1 in total, not 2, and
//!     its body sits at the same level as the first `if`'s body.
//!   - `orelse` whose operand is not a block, such as `orelse return`.
//!   - `break` or `continue` that names a label. An unlabelled `break` or
//!     `continue` adds nothing.
//!   - Each sequence of like boolean operators: `a and b and c` adds 1,
//!     `a and b or c` adds 2 because the operator changes, and parentheses
//!     start a new sequence, so `a and (b and c)` adds 2. `!` starts a new
//!     sequence the same way, because its operand is a new expression. A
//!     sequence is read from the parsed tree, by operator precedence, not
//!     token by token. `and` binds tighter than `or`, so `a or b and c or d`
//!     parses as `(a or (b and c)) or d`: one `or` sequence holding one `and`
//!     sequence, and the score is 2. Read token by token the operator changes
//!     twice and the score would be 3. The tree reading is the one
//!     SonarSource's own implementation uses, and it is the one pinned here.
//!   - Recursion: a call whose callee is a bare identifier equal to the
//!     enclosing function's name adds 1. A call through a field access
//!     (`self.name()`, `Self.name()`) adds nothing, because the tool has no
//!     type information to tell which function that names.
//!
//! Nesting. The level rises by one inside the body of every structural
//! increment above, and inside the body of a nested function. Zig allows a
//! function declaration only as a container member, so a nested function is one
//! declared in a `struct`, `enum`, `union`, or `opaque` that itself appears
//! inside a function body. Such a function is scored twice: on its own, and as
//! part of the enclosing function one level deeper.
//!
//! Constructs that add nothing and raise no level: `defer`, `errdefer`,
//! `comptime` expressions and blocks, `nosuspend`, labelled blocks, `try`,
//! `unreachable`, `return`, `suspend`, `resume`, `asm`, `.?`, `!`, error
//! unions, and every plain expression.
//!
//! Declarations scored: every `fn` with a body, at the top level or as a member
//! of any container at any depth, including containers inside function bodies
//! and inside `return struct { ... }` expressions. An `extern` prototype has no
//! body and is not scored. `test` blocks are scored too, under the name the
//! block carries, because CLAUDE.md puts them under the same limit: a test a
//! reader cannot hold in their head checks whatever it happens to do rather
//! than what it says.

const std = @import("std");
const Io = std.Io;
const scorer = @import("cognitive_complexity_scorer.zig");
const FunctionScore = scorer.FunctionScore;

comptime {}

/// Threshold used when the command line names none. CLAUDE.md sets it: a score
/// of 15 passes, 16 fails.
const default_max_score: u32 = 15;
/// Command-line arguments the tool reads before giving up.
const max_arguments: usize = 1024;
/// Largest source file the tool reads. A larger one is reported, not scored.
const max_source_bytes: usize = 4 * 1024 * 1024;
/// Bytes buffered for standard output before a flush.
const output_buffer_bytes: usize = 16 * 1024;
/// Directory names the walk never descends into.
const skipped_directories = [_][]const u8{ ".git", ".zig-cache", "zig-out" };
/// Extension a file needs for the walk to score it.
const zig_extension = ".zig";

const Options = struct {
    max_score: u32,
    paths: []const []const u8,
};

const ArgumentError = error{
    MissingMaxValue,
    UnknownOption,
    NoPaths,
} || std.fmt.ParseIntError || std.mem.Allocator.Error;

/// Reads `--max <N>` and the paths after it. Every other leading `-` is an
/// error, so a mistyped option never becomes a path.
fn parse_arguments(arena: std.mem.Allocator, arguments: []const [:0]const u8) ArgumentError!Options {
    var max_score: u32 = default_max_score;
    var paths: std.ArrayList([]const u8) = .empty;
    var index: usize = 0;
    while (index < arguments.len) : (index += 1) {
        const argument = arguments[index];
        if (std.mem.eql(u8, argument, "--max")) {
            if (index + 1 >= arguments.len) return error.MissingMaxValue;
            index += 1;
            max_score = try std.fmt.parseInt(u32, arguments[index], 10);
        } else if (std.mem.startsWith(u8, argument, "-")) {
            return error.UnknownOption;
        } else {
            try paths.append(arena, argument);
        }
    }
    if (paths.items.len == 0) return error.NoPaths;
    return .{ .max_score = max_score, .paths = paths.items };
}

fn print_usage() void {
    std.debug.print("usage: cognitive_complexity [--max N] <path>...\n", .{});
}

fn is_skipped_directory(name: []const u8) bool {
    for (skipped_directories) |skipped| {
        if (std.mem.eql(u8, name, skipped)) return true;
    }
    return false;
}

fn is_zig_source(name: []const u8) bool {
    return std.mem.endsWith(u8, name, zig_extension);
}

/// One file the tool could not score, kept so the run reports it instead of
/// passing silently over source it never read.
const Unscored = struct {
    path: []const u8,
    reason: []const u8,
};

/// Collects the scores of every file under every path given on the command
/// line. Results are sorted before printing so a run's output does not depend
/// on the order the file system hands back directory entries.
const Report = struct {
    arena: std.mem.Allocator,
    io: Io,
    scores: std.ArrayList(FunctionScore) = .empty,
    unscored: std.ArrayList(Unscored) = .empty,

    fn lint_path(self: *Report, path: []const u8) !void {
        const stat = try Io.Dir.cwd().statFile(self.io, path, .{});
        if (stat.kind == .directory) return self.lint_directory(path);
        try self.lint_file(path);
    }

    fn lint_directory(self: *Report, path: []const u8) !void {
        var dir = try Io.Dir.cwd().openDir(self.io, path, .{ .iterate = true });
        defer dir.close(self.io);
        var walker = try dir.walkSelectively(self.arena);
        defer walker.deinit();
        while (try walker.next(self.io)) |entry| {
            if (entry.kind == .directory) {
                if (!is_skipped_directory(entry.basename)) try walker.enter(self.io, entry);
                continue;
            }
            if (entry.kind != .file or !is_zig_source(entry.basename)) continue;
            const full_path = try std.fs.path.join(self.arena, &.{ path, entry.path });
            try self.lint_file(full_path);
        }
    }

    fn lint_file(self: *Report, path: []const u8) !void {
        const source = Io.Dir.cwd().readFileAllocOptions(
            self.io,
            path,
            self.arena,
            .limited(max_source_bytes),
            .of(u8),
            0,
        ) catch |err| return self.record_unscored(path, @errorName(err));
        const scores = scorer.score_source(self.arena, path, source) catch |err| switch (err) {
            error.OutOfMemory => return err,
            else => return self.record_unscored(path, @errorName(err)),
        };
        try self.scores.appendSlice(self.arena, scores);
    }

    fn record_unscored(self: *Report, path: []const u8, reason: []const u8) !void {
        try self.unscored.append(self.arena, .{
            .path = try self.arena.dupe(u8, path),
            .reason = reason,
        });
    }
};

/// Orders violations by path, then by line, so the report reads top to bottom
/// through each file.
fn scored_before(_: void, left: FunctionScore, right: FunctionScore) bool {
    const order = std.mem.order(u8, left.path, right.path);
    if (order != .eq) return order == .lt;
    return left.line < right.line;
}

/// Prints every violation, then either the failure count or the summary.
/// Returns the process exit status.
fn print_report(writer: *Io.Writer, report: *Report, max_score: u32) !u8 {
    std.mem.sort(FunctionScore, report.scores.items, {}, scored_before);
    var violations: usize = 0;
    var highest: u32 = 0;
    for (report.scores.items) |scored| {
        if (scored.score > highest) highest = scored.score;
        if (scored.score <= max_score) continue;
        violations += 1;
        try writer.print("{s}:{d}: {s} scored {d} (max {d})\n", .{
            scored.path,
            scored.line,
            scored.name,
            scored.score,
            max_score,
        });
    }
    for (report.unscored.items) |unscored| {
        try writer.print("{s}: not scored ({s})\n", .{ unscored.path, unscored.reason });
    }
    if (violations == 0 and report.unscored.items.len == 0) {
        try writer.print(
            "cognitive-complexity: {d} functions scored, highest {d} (max {d})\n",
            .{ report.scores.items.len, highest, max_score },
        );
        try writer.flush();
        return 0;
    }
    try writer.print(
        "cognitive-complexity: {d} of {d} functions over the limit, {d} files not scored\n",
        .{ violations, report.scores.items.len, report.unscored.items.len },
    );
    try writer.flush();
    return 1;
}

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const all_arguments = try init.minimal.args.toSlice(arena);
    if (all_arguments.len > max_arguments) return error.TooManyArguments;
    const arguments = if (all_arguments.len == 0) all_arguments else all_arguments[1..];
    const options = parse_arguments(arena, arguments) catch |err| {
        std.debug.print("error: {s}\n", .{@errorName(err)});
        print_usage();
        std.process.exit(2);
    };

    // A path the caller named and the tool cannot open is a usage error, not a
    // score: exit 2 with the path, rather than a stack trace.
    var report: Report = .{ .arena = arena, .io = init.io };
    for (options.paths) |path| report.lint_path(path) catch |err| {
        std.debug.print("error: cannot read '{s}': {s}\n", .{ path, @errorName(err) });
        std.process.exit(2);
    };

    var output_buffer: [output_buffer_bytes]u8 = undefined;
    // Streaming, not positional: a positional writer starts at offset 0 and
    // overwrites earlier output when stdout is redirected to a file.
    var writer = Io.File.stdout().writerStreaming(init.io, &output_buffer);
    const status = try print_report(&writer.interface, &report, options.max_score);
    std.process.exit(status);
}

const testing = std.testing;

/// Runs `print_report` over the given scores and returns the text and status.
fn run_report(
    arena: std.mem.Allocator,
    buffer: []u8,
    scores: []const FunctionScore,
    max_score: u32,
) !struct { []const u8, u8 } {
    var report: Report = .{ .arena = arena, .io = undefined };
    try report.scores.appendSlice(arena, scores);
    var writer: Io.Writer = .fixed(buffer);
    const status = try print_report(&writer, &report, max_score);
    return .{ writer.buffered(), status };
}

test "a function over the threshold is named and the status is one" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var buffer: [512]u8 = undefined;
    const text, const status = try run_report(arena_state.allocator(), &buffer, &.{
        .{ .path = "src/h2/frame.zig", .line = 12, .name = "parse", .score = 9 },
        .{ .path = "src/h2/frame.zig", .line = 40, .name = "write", .score = 2 },
    }, 3);
    try testing.expectEqual(@as(u8, 1), status);
    try testing.expect(std.mem.startsWith(u8, text, "src/h2/frame.zig:12: parse scored 9 (max 3)\n"));
    // The second function is under the threshold, so it is not named.
    try testing.expect(std.mem.indexOf(u8, text, "write") == null);
}

test "every violation is reported, not only the first" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var buffer: [512]u8 = undefined;
    const text, const status = try run_report(arena_state.allocator(), &buffer, &.{
        .{ .path = "b.zig", .line = 3, .name = "second", .score = 20 },
        .{ .path = "a.zig", .line = 7, .name = "first", .score = 16 },
    }, 15);
    try testing.expectEqual(@as(u8, 1), status);
    // Sorted by path, so `a.zig` is printed before `b.zig`.
    try testing.expectEqualStrings(
        \\a.zig:7: first scored 16 (max 15)
        \\b.zig:3: second scored 20 (max 15)
        \\cognitive-complexity: 2 of 2 functions over the limit, 0 files not scored
        \\
    , text);
}

test "a clean run prints one summary line and the status is zero" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var buffer: [512]u8 = undefined;
    // A score equal to the threshold passes: 15 passes, 16 fails.
    const text, const status = try run_report(arena_state.allocator(), &buffer, &.{
        .{ .path = "a.zig", .line = 1, .name = "small", .score = 4 },
        .{ .path = "a.zig", .line = 9, .name = "at_the_limit", .score = 15 },
    }, 15);
    try testing.expectEqual(@as(u8, 0), status);
    try testing.expectEqualStrings(
        "cognitive-complexity: 2 functions scored, highest 15 (max 15)\n",
        text,
    );
}

test "a score one over the threshold fails" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var buffer: [512]u8 = undefined;
    const text, const status = try run_report(arena_state.allocator(), &buffer, &.{
        .{ .path = "a.zig", .line = 9, .name = "one_over", .score = 16 },
    }, 15);
    try testing.expectEqual(@as(u8, 1), status);
    try testing.expect(std.mem.startsWith(u8, text, "a.zig:9: one_over scored 16 (max 15)\n"));
}

test "parse_arguments reads the threshold and the paths" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const options = try parse_arguments(
        arena_state.allocator(),
        &[_][:0]const u8{ "--max", "7", "src", "tools" },
    );
    try testing.expectEqual(@as(u32, 7), options.max_score);
    try testing.expectEqual(@as(usize, 2), options.paths.len);
    try testing.expectEqualStrings("src", options.paths[0]);
    try testing.expectEqualStrings("tools", options.paths[1]);
}

test "parse_arguments rejects a missing value, an unknown option, and no paths" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try testing.expectError(
        error.MissingMaxValue,
        parse_arguments(arena, &[_][:0]const u8{"--max"}),
    );
    try testing.expectError(
        error.UnknownOption,
        parse_arguments(arena, &[_][:0]const u8{ "--limit", "3", "src" }),
    );
    try testing.expectError(error.NoPaths, parse_arguments(arena, &[_][:0]const u8{}));
    // Without `--max` the threshold is the one CLAUDE.md states.
    const options = try parse_arguments(arena, &[_][:0]const u8{"src"});
    try testing.expectEqual(default_max_score, options.max_score);
}

test "the walk skips build output directories and non-Zig files" {
    try testing.expect(is_skipped_directory(".zig-cache"));
    try testing.expect(is_skipped_directory("zig-out"));
    try testing.expect(is_skipped_directory(".git"));
    try testing.expect(!is_skipped_directory("src"));
    try testing.expect(is_zig_source("frame.zig"));
    try testing.expect(!is_zig_source("frame.zig.orig"));
    try testing.expect(!is_zig_source("README.md"));
}
