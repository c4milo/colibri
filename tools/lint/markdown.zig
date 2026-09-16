//! markdown: every Markdown file is GitHub-flavored Markdown and must render on GitHub as written
//! (CLAUDE.md, Conventions). A document that renders wrong is read wrong, and the design set is
//! the thing every later step is measured against.
//!
//! Over every `.md` file, the rule makes four checks:
//!   1. a bare pseudo list item: a line that starts with digits, one letter, a period and a space,
//!      such as `3b. ` or `0a. `. GitHub folds it into the paragraph above instead of rendering a
//!      list item, so the step it names disappears. Nest it as a list item.
//!   2. a fenced code block opened with no language: ``` with nothing after it. GitHub renders it
//!      unhighlighted, and CLAUDE.md requires a language on every fence.
//!   3. a table row whose column count differs from its header's. GitHub drops the extra cells and
//!      pads the missing ones, silently. Cells are split on every `|` that no backslash escapes,
//!      the way GitHub splits them, so a `|` written inside a code span counts as a cell boundary
//!      here exactly as it does there.
//!   4. trailing whitespace: a line ending in a space or a tab. Two trailing spaces are a hard
//!      line break in Markdown, which is invisible in the source and changes the render.
//!
//! Checks 1, 2 and 3 skip the inside of a fenced code block, where the text is not Markdown. Check
//! 4 does not: trailing whitespace inside a fence is still trailing whitespace in the file.
//!
//! What the rule does not check: the rest of the GFM rules CLAUDE.md names — no definition lists,
//! no LaTeX, a pipe inside a table cell written `\|` — and the render itself. It reads lines, not
//! a document tree, so a table written without its outer pipes, or a fence opened inside a list
//! item's indentation, is outside what it can see.
//!
//! The rule is pepegrillo's `markdown` (decision 36). This file holds colibri's configuration of it
//! and the fixtures that pin that configuration.

const std = @import("std");
const pepegrillo = @import("pepegrillo");
const lint = pepegrillo.lint;
const markdown = lint.rules.markdown;

/// The configuration. It reads every `.md` file and runs the four checks above. A pseudo list item
/// is matched with a letter of either case and reported at the line's first column.
pub const config: markdown.Config = .{
    .scope = .{ .extensions = &.{".md"} },
    .pseudo_list_item = true,
    .pseudo_list_letters = .any,
    .pseudo_list_column = .first,
    .fence_language = true,
    .table_columns = true,
    .trailing_whitespace = true,
    .messages = .{
        .pseudo_list_item = "bare \"{[marker]s}\" folds into the paragraph above on GitHub;" ++
            " nest it as a list item",
        .fence_language = "fenced code block opened with no language",
        .table_columns = "table row holds {[columns]d} columns; its header holds {[header_columns]d}",
        .trailing_whitespace = "trailing whitespace",
    },
};

const Rule = markdown.Rule(config);
pub const name = Rule.name;
pub const check = Rule.check;

// Tests. Each fixture pins one shape from the header.

const testing = std.testing;
const harness = lint.harness;

fn findings_of(
    arena: std.mem.Allocator,
    path: []const u8,
    source: [:0]const u8,
) ![]const lint.report.Finding {
    return harness.run(arena, Rule, path, source);
}

const passing_fixture: [:0]const u8 =
    \\# Design
    \\
    \\1. Step one.
    \\    1. Step one, part b.
    \\2. Step two.
    \\
    \\| Module | Imports |
    \\|---|---|
    \\| `quic` | `core`, `wire`, `crypto`, `tls` |
    \\| `h3` | `core`, `quic` |
    \\
    \\```zig
    \\const quic = @import("quic");
    \\```
    \\
    \\A cell may hold an escaped separator: `a \| b`.
;

const failing_fixture: [:0]const u8 =
    \\# Design
    \\
    \\3b. This folds into the paragraph above.
    \\
    \\| Module | Imports |
    \\|---|---|
    \\| `quic` | `core` | `wire` |
    \\
    \\```
    \\const quic = @import("quic");
    \\```
;

test "markdown passes a document that renders as written" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try findings_of(arena_state.allocator(), "docs/design.md", passing_fixture);
    try harness.expect_messages(findings, &.{});
}

test "markdown flags a bare pseudo list item, a wide table row and a fence with no language" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try findings_of(arena_state.allocator(), "docs/design.md", failing_fixture);
    try harness.expect_messages(findings, &.{
        "bare \"3b.\" folds into the paragraph above on GitHub; nest it as a list item",
        "table row holds 3 columns; its header holds 2",
        "fenced code block opened with no language",
    });
    try testing.expectEqual(3, findings[0].line);
    try testing.expectEqual(7, findings[1].line);
    try testing.expectEqual(9, findings[2].line);
}

test "markdown flags trailing whitespace, inside a fence as well as outside" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try findings_of(arena_state.allocator(), "docs/invariants.md", "# Invariants  \n\n```zig\nconst a = 1;\t\n```\nclean\n");
    try harness.expect_messages(findings, &.{
        "trailing whitespace",
        "trailing whitespace",
    });
    try testing.expectEqual(1, findings[0].line);
    try testing.expectEqual(4, findings[1].line);
}

test "markdown does not read the inside of a fence as Markdown" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try findings_of(arena_state.allocator(), "docs/design.md",
        \\```text
        \\3b. Not a list item here.
        \\| one | two | three |
        \\```
    );
    try harness.expect_messages(findings, &.{});
}

test "markdown reads every .md file and no other" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try testing.expect(config.scope.applies("docs/design.md"));
    try testing.expect(config.scope.applies("README.md"));
    try testing.expect(config.scope.applies("./CLAUDE.md"));
    try testing.expect(!config.scope.applies("src/quic/quic.zig"));
    try testing.expect(!config.scope.applies("docs/design.txt"));
    try harness.expect_messages(try findings_of(arena, "docs/design.txt", failing_fixture), &.{});
}

test "markdown flags an uppercase marker and an indented one, each at column 1" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try findings_of(arena_state.allocator(), "docs/design.md",
        \\12A. Upper case.
        \\
        \\  3b. Indented.
    );
    try harness.expect_messages(findings, &.{
        "bare \"12A.\" folds into the paragraph above on GitHub; nest it as a list item",
        "bare \"3b.\" folds into the paragraph above on GitHub; nest it as a list item",
    });
    try testing.expectEqual(1, findings[1].column);
}

test "markdown counts a pipe inside a code span as a cell boundary and reports nothing else" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    // GitHub splits the row into three cells, which is the header's count, so nothing is wrong
    // with the table as GitHub renders it.
    const findings = try findings_of(arena_state.allocator(), "docs/design.md",
        \\| a | b | c |
        \\|---|---|---|
        \\| `x|y` | z |
    );
    try harness.expect_messages(findings, &.{});
}
