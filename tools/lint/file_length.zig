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
//!
//! The rule is pepegrillo's `file_length` (decision 36). This file holds colibri's configuration of it
//! and the fixtures that pin that configuration.

const std = @import("std");
const pepegrillo = @import("pepegrillo");
const lint = pepegrillo.lint;
const file_length = lint.rules.file_length;

/// The most lines a hand-written file may hold.
pub const max_lines: u32 = 500;

/// The configuration: `.zig` and `.sh` files under `src/`, `tools/` and `build/`.
pub const config: file_length.Config = .{
    .scope = .{ .extensions = &.{ ".zig", ".sh" }, .include_directories = &.{ "src", "tools", "build" } },
    .max_lines = max_lines,
    .message_suffix = "; split the file",
};

const Rule = file_length.Rule(config);
pub const name = Rule.name;
pub const check = Rule.check;

// Tests. Each fixture pins one shape from the header.

const testing = std.testing;
const harness = lint.harness;

/// One line of a fixture. A comment line so that the passing fixture is also a file that compiles.
const fixture_line = "//\n";

const passing_fixture: [:0]const u8 = fixture_line ** max_lines;
const failing_fixture: [:0]const u8 = fixture_line ** (max_lines + 1);

test "file-length passes a file at the limit" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try harness.run(arena_state.allocator(), Rule, "src/quic/quic.zig", passing_fixture);
    try harness.expect_messages(findings, &.{});
}

test "file-length flags one line over the limit, at that line" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try harness.run(arena_state.allocator(), Rule, "src/quic/quic.zig", failing_fixture);
    try harness.expect_messages(findings, &.{"501 lines, over the 500-line limit; split the file"});
    try testing.expectEqual(max_lines + 1, findings[0].line);
}

test "file-length reads .zig and .sh under src, tools and build" {
    try testing.expect(config.scope.applies("src/quic/quic.zig"));
    try testing.expect(config.scope.applies("./tools/lint/main.zig"));
    try testing.expect(config.scope.applies("build/modules.zig"));
    try testing.expect(config.scope.applies("tools/h2spec.sh"));
    try testing.expect(!config.scope.applies("docs/design.md"));
    try testing.expect(!config.scope.applies("README.md"));
    try testing.expect(!config.scope.applies("build.zig"));
    try testing.expect(!config.scope.applies("bench/run.sh"));
}

test "file-length reads no file outside the directories it names" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try harness.expect_messages(try harness.run(arena, Rule, "docs/design.md", failing_fixture), &.{});
    try harness.expect_messages(try harness.run(arena, Rule, "bench/run.sh", failing_fixture), &.{});
}
