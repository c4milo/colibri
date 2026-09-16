//! file-length: a hand-written source file stays at or under 500 lines, its tests included
//! (CLAUDE.md, Conventions). Split the file rather than raise the limit, and name every piece
//! after the file it came from: `hpack.zig` becomes `hpack_decode.zig`, `hpack_table.zig`, and so
//! on, keeping the original name as the entry point.
//!
//! Over every `.zig` and `.sh` file under `src/`, `tools/` and `build/`, the rule counts lines the
//! way an editor numbers them — one per newline, plus one for a last line with no newline — and
//! reports a file over the limit once, at the first line past it.
//!
//! Markdown is exempt: a document's audited unit is the section, not the file, and the design set
//! is deliberately long.

const std = @import("std");
const paths = @import("paths.zig");
const report = @import("report.zig");
const text = @import("text.zig");

pub const name = "file-length";

/// The most lines a hand-written source file may hold.
pub const max_lines: u32 = 500;

/// Extensions the rule reads. Markdown is not one of them.
const checked_extensions = [_][]const u8{ ".zig", ".sh" };

/// Directories the rule reads.
const checked_directories = [_][]const u8{ "src", "tools", "build" };

pub fn applies(path: []const u8) bool {
    if (!paths.is_under_any(path, &checked_directories)) return false;
    for (checked_extensions) |extension| {
        if (paths.has_extension(path, extension)) return true;
    }
    return false;
}

pub fn check(context: *report.Context, file: report.File) !void {
    if (!applies(file.path)) return;
    const lines = text.count_lines(file.source);
    if (lines <= max_lines) return;
    try context.findings.add(
        name,
        file.path,
        max_lines + 1,
        1,
        "{d} lines, over the {d}-line limit; split the file",
        .{ lines, max_lines },
    );
}

// Tests. Each fixture pins one shape from the header.

const testing = std.testing;
const harness = @import("harness.zig");

/// One line of a fixture. A comment line so that the passing fixture is also a file that compiles.
const fixture_line = "//\n";

const passing_fixture: [:0]const u8 = fixture_line ** max_lines;
const failing_fixture: [:0]const u8 = fixture_line ** (max_lines + 1);

test "file-length passes a file at the limit" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try harness.run(arena_state.allocator(), @This(), "src/quic/quic.zig", passing_fixture);
    try harness.expect_messages(findings, &.{});
}

test "file-length flags one line over the limit, at that line" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try harness.run(arena_state.allocator(), @This(), "src/quic/quic.zig", failing_fixture);
    try harness.expect_messages(findings, &.{"501 lines, over the 500-line limit; split the file"});
    try testing.expectEqual(max_lines + 1, findings[0].line);
}

test "file-length reads .zig and .sh under src, tools and build" {
    try testing.expect(applies("src/quic/quic.zig"));
    try testing.expect(applies("./tools/lint/main.zig"));
    try testing.expect(applies("build/modules.zig"));
    try testing.expect(applies("tools/h2spec.sh"));
    try testing.expect(!applies("docs/design.md"));
    try testing.expect(!applies("README.md"));
    try testing.expect(!applies("build.zig"));
    try testing.expect(!applies("bench/run.sh"));
}

test "file-length reads no file outside the directories it names" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try harness.expect_messages(try harness.run(arena, @This(), "docs/design.md", failing_fixture), &.{});
    try harness.expect_messages(try harness.run(arena, @This(), "bench/run.sh", failing_fixture), &.{});
}
