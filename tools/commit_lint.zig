//! Commit-message linter for the Conventional Commit rules of CLAUDE.md (Commits). It reads
//! commit messages out of git and prints one line per finding; it changes nothing.
//!
//! Run:  zig build lint-commits            # the commits this branch adds to origin/main
//!       zig run tools/commit_lint.zig -- --range REV [REV...]
//! Test: zig test tools/commit_lint.zig
//!
//! `--range` takes every following argument up to the next flag or the end of the command line,
//! and hands them all to git as revision arguments. The tool runs
//! `git log --format=%H%x00%P%x00%B%x00 REV... --` and splits the output on NUL: three fields per
//! commit, the sha, the parents, and the raw message, with a newline between one commit's last
//! field and the next commit's sha. `%B` is the message the rules read; `%H` is what lets a
//! finding name the commit it came from; `%P` is what makes a merge commit visible, and a commit
//! with two or more parents is skipped, because its message is git's and not the author's.
//!
//! Any revision arguments git accepts work: `zig build lint-commits` passes the one range
//! `origin/main..HEAD`, and .githooks/pre-push passes `SHA --not --remotes` for a branch the
//! remote has never seen.
//!
//! One line per finding:
//!
//!     sha: severity: rule-name: message
//!
//! The severity is `violation` for a rule of CLAUDE.md that was broken, and `warning` for a scope
//! outside the module graph, which `commit_lint_rules.zig` states the case for.
//!
//! Exit status: 0 when no rule was violated, warnings included; 1 when any rule was violated; 2 on
//! a usage error or a git log that failed. The hook reads the difference: it refuses a push on 1
//! and reports a broken linter on 2.
//!
//! The rules are `commit_lint_rules.zig`, their tests are `commit_lint_rules_test.zig`, and the
//! message model they read is `commit_lint_message.zig`. This file reads the command line, calls
//! git, and returns the exit status.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const message_model = @import("commit_lint_message.zig");
const rules = @import("commit_lint_rules.zig");

// The other files, imported so that `zig test tools/commit_lint.zig` compiles them and runs their
// tests. build.zig names this file alone as the tool's test root.
comptime {
    _ = message_model;
    _ = rules;
    _ = @import("commit_lint_rules_test.zig");
}

const range_flag = "--range";

/// The git command the tool runs, one argument per constant.
const git_program = "git";
const git_log_command = "log";
const git_log_format = "--format=%H%x00%P%x00%B%x00";
/// Ends the revision arguments, so a range is never read as a path.
const git_revision_terminator = "--";
/// The exit status git reports when the log succeeded.
const git_success: u8 = 0;

/// The byte git writes between the fields of one commit.
const field_separator: u8 = 0;
/// The bytes git writes between one commit's last field and the next commit's sha, trimmed off the
/// sha before it is read.
const record_separators = "\n\r";
/// Fields git writes per commit: the sha, the parents, and the message.
const fields_per_commit: usize = 3;
/// Parents that make a commit a merge.
const merge_parent_count: usize = 2;

/// Command-line arguments the tool reads before giving up.
const arguments_max: usize = 1024;
/// Commits one range may hold. More is an error, never a truncated run.
const commits_per_run_max: usize = 65536;
/// Bytes of git log output the tool reads.
const git_output_bytes_max: usize = 64 * 1024 * 1024;
/// Bytes of git's error output the tool prints back.
const git_stderr_bytes_max: usize = 64 * 1024;
/// Bytes buffered for standard output before a flush.
const output_buffer_bytes: usize = 16 * 1024;

const exit_clean: u8 = 0;
const exit_violations: u8 = 1;
const exit_usage: u8 = 2;

pub const Options = struct {
    /// The revision arguments to hand git, in the order they were given.
    revisions: []const []const u8,
};

pub const ArgumentError = error{ MissingValue, UnknownArgument, TwoRanges, NoRange };

/// The arguments from `start` up to the next flag or the end. A revision git spells with leading
/// hyphens, `--not` or `--remotes`, is no flag of this tool, so it lands here.
fn values_after(arguments: []const []const u8, start: usize) []const []const u8 {
    var end = start;
    while (end < arguments.len and !std.mem.eql(u8, arguments[end], range_flag)) end += 1;
    return arguments[start..end];
}

/// Reads `arguments` (without the program name) into `Options`. Exactly one `--range` is wanted:
/// none and two are both usage errors.
pub fn parse_arguments(arguments: []const []const u8) ArgumentError!Options {
    var revisions: ?[]const []const u8 = null;
    var index: usize = 0;
    while (index < arguments.len) {
        if (!std.mem.eql(u8, arguments[index], range_flag)) return error.UnknownArgument;
        if (revisions != null) return error.TwoRanges;
        const values = values_after(arguments, index + 1);
        if (values.len == 0) return error.MissingValue;
        revisions = values;
        index += 1 + values.len;
    }
    return .{ .revisions = revisions orelse return error.NoRange };
}

/// One commit as `git log` wrote it.
pub const Commit = struct {
    sha: []const u8,
    /// The parent shas, separated by spaces; empty for the root commit.
    parents: []const u8,
    /// The raw message: subject, body and trailers.
    body: []const u8,
};

/// True when the commit has two or more parents.
pub fn is_merge(parents: []const u8) bool {
    var iterator = std.mem.tokenizeScalar(u8, parents, ' ');
    var count: usize = 0;
    while (iterator.next()) |_| {
        count += 1;
        if (count >= merge_parent_count) return true;
    }
    return false;
}

/// Splits `git log` output into commits. Reading stops at the first field group whose sha is
/// empty, which is the newline git writes after the last commit.
pub fn split_commits(arena: Allocator, output: []const u8) ![]const Commit {
    var fields: std.ArrayList([]const u8) = .empty;
    var iterator = std.mem.splitScalar(u8, output, field_separator);
    while (iterator.next()) |field| {
        if (fields.items.len >= commits_per_run_max * fields_per_commit) return error.TooManyCommits;
        try fields.append(arena, field);
    }
    var commits: std.ArrayList(Commit) = .empty;
    var index: usize = 0;
    while (index + fields_per_commit <= fields.items.len) : (index += fields_per_commit) {
        const sha = std.mem.trim(u8, fields.items[index], record_separators);
        if (sha.len == 0) break;
        try commits.append(arena, .{
            .sha = sha,
            .parents = fields.items[index + 1],
            .body = fields.items[index + 2],
        });
    }
    return commits.items;
}

/// Runs every rule over every non-merge commit of `git log` output.
pub fn lint_commits(arena: Allocator, findings: *rules.Findings, output: []const u8) !void {
    for (try split_commits(arena, output)) |commit| {
        if (is_merge(commit.parents)) continue;
        const message = try message_model.parse(arena, commit.body);
        try rules.check_all(findings, commit.sha, &message);
    }
}

/// The standard output of `git log` over `revisions`, or an error with git's own error output
/// printed.
fn run_git_log(arena: Allocator, io: Io, revisions: []const []const u8) ![]u8 {
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.appendSlice(arena, &.{ git_program, git_log_command, git_log_format });
    try argv.appendSlice(arena, revisions);
    try argv.append(arena, git_revision_terminator);
    const result = try std.process.run(arena, io, .{
        .argv = argv.items,
        .stdout_limit = .limited(git_output_bytes_max),
        .stderr_limit = .limited(git_stderr_bytes_max),
    });
    const status = switch (result.term) {
        .exited => |code| code,
        else => return error.GitDidNotExit,
    };
    if (status != git_success) {
        const written = try std.mem.join(arena, " ", revisions);
        std.debug.print("git log {s}: {s}", .{ written, result.stderr });
        return error.GitFailed;
    }
    return result.stdout;
}

fn print_usage() void {
    std.debug.print("usage: commit_lint --range REV [REV...]\n", .{});
}

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const all_arguments = try init.minimal.args.toSlice(arena);
    if (all_arguments.len > arguments_max) return error.TooManyArguments;
    const arguments = if (all_arguments.len == 0) all_arguments else all_arguments[1..];
    const options = parse_arguments(arguments) catch |err| {
        std.debug.print("error: {s}\n", .{@errorName(err)});
        print_usage();
        std.process.exit(exit_usage);
    };

    var findings: rules.Findings = .{ .arena = arena };
    const output = run_git_log(arena, init.io, options.revisions) catch |err| {
        std.debug.print("error: {s}\n", .{@errorName(err)});
        std.process.exit(exit_usage);
    };
    lint_commits(arena, &findings, output) catch |err| {
        std.debug.print("error: {s}\n", .{@errorName(err)});
        std.process.exit(exit_usage);
    };

    var output_buffer: [output_buffer_bytes]u8 = undefined;
    // Streaming, not positional: a positional writer starts at offset 0 and overwrites earlier
    // output when standard output is redirected to a file.
    var writer = Io.File.stdout().writerStreaming(init.io, &output_buffer);
    try findings.write(&writer.interface);
    try writer.interface.flush();
    std.process.exit(if (findings.count_violations() == 0) exit_clean else exit_violations);
}

// Tests. The rules have their own file; these pin the command line, the split of git's output, and
// the merge skip.

const testing = std.testing;

test "parse_arguments takes exactly one --range" {
    const one = (try parse_arguments(&.{ "--range", "a..b" })).revisions;
    try testing.expectEqual(1, one.len);
    try testing.expectEqualStrings("a..b", one[0]);
    try testing.expectError(error.NoRange, parse_arguments(&.{}));
    try testing.expectError(error.MissingValue, parse_arguments(&.{"--range"}));
    try testing.expectError(error.TwoRanges, parse_arguments(&.{ "--range", "a..b", "--range", "c..d" }));
    try testing.expectError(error.UnknownArgument, parse_arguments(&.{"--message"}));
    try testing.expectError(error.UnknownArgument, parse_arguments(&.{"a..b"}));
}

test "parse_arguments hands --range every revision argument that follows it" {
    // The shape .githooks/pre-push passes for a branch the remote has never seen: a sha and the
    // two arguments that exclude every remote-tracking ref.
    const revisions = (try parse_arguments(&.{ "--range", "abc123", "--not", "--remotes" })).revisions;
    try testing.expectEqual(3, revisions.len);
    try testing.expectEqualStrings("abc123", revisions[0]);
    try testing.expectEqualStrings("--not", revisions[1]);
    try testing.expectEqualStrings("--remotes", revisions[2]);
}

test "is_merge counts the parents git wrote" {
    try testing.expect(!is_merge(""));
    try testing.expect(!is_merge("aaa"));
    try testing.expect(is_merge("aaa bbb"));
    try testing.expect(is_merge("aaa bbb ccc"));
}

/// The output git writes for two commits: fields separated by NUL, and a newline between one
/// commit's last field and the next commit's sha.
const two_commit_log =
    "aaa\x00" ++ "ppp\x00" ++ "feat(h2): add the frame reader\n\x00" ++
    "\nbbb\x00" ++ "\x00" ++ "fix(hpack): reject an index of zero\n\x00" ++ "\n";

test "split_commits reads three fields per commit and stops at the trailing newline" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const commits = try split_commits(arena_state.allocator(), two_commit_log);
    try testing.expectEqual(2, commits.len);
    try testing.expectEqualStrings("aaa", commits[0].sha);
    try testing.expectEqualStrings("ppp", commits[0].parents);
    try testing.expectEqualStrings("feat(h2): add the frame reader\n", commits[0].body);
    try testing.expectEqualStrings("bbb", commits[1].sha);
    try testing.expectEqualStrings("", commits[1].parents);
}

test "split_commits reads empty output as no commit" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    try testing.expectEqual(0, (try split_commits(arena_state.allocator(), "")).len);
}

test "lint_commits reports one line per finding, named by sha" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var findings: rules.Findings = .{ .arena = arena };
    try lint_commits(arena, &findings, "aaa\x00ppp\x00Adds the frame reader.\n\x00\n");
    try testing.expectEqual(1, findings.count());
    try testing.expectEqualStrings("aaa", findings.items.items[0].source);
    try testing.expectEqualStrings(rules.subject_format_rule, findings.items.items[0].rule);
    try testing.expectEqual(1, findings.count_violations());
}

test "lint_commits reports nothing for a conforming range" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var findings: rules.Findings = .{ .arena = arena };
    try lint_commits(arena, &findings, two_commit_log);
    try testing.expectEqual(0, findings.count());
}

test "lint_commits skips a merge commit, whose message git wrote" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var findings: rules.Findings = .{ .arena = arena };
    try lint_commits(arena, &findings, "aaa\x00bbb ccc\x00Merge branch 'topic' into main\n\x00\n");
    try testing.expectEqual(0, findings.count());
}

test "the same merge message on one parent is not skipped" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var findings: rules.Findings = .{ .arena = arena };
    try lint_commits(arena, &findings, "aaa\x00bbb\x00Merge branch 'topic' into main\n\x00\n");
    try testing.expectEqual(1, findings.count());
    try testing.expectEqualStrings(rules.subject_format_rule, findings.items.items[0].rule);
}

test "a warning alone leaves the exit status clean" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var findings: rules.Findings = .{ .arena = arena };
    try lint_commits(arena, &findings, "aaa\x00ppp\x00feat(frobnicator): add the frame reader\n\x00\n");
    try testing.expectEqual(1, findings.count());
    try testing.expectEqual(0, findings.count_violations());
    try testing.expectEqualStrings(rules.scope_known_rule, findings.items.items[0].rule);
}
