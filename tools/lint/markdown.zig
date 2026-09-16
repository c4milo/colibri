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

const std = @import("std");
const paths = @import("paths.zig");
const report = @import("report.zig");
const text = @import("text.zig");

pub const name = "markdown";

const markdown_extension = ".md";

/// The line that opens and closes a fenced code block.
const fence_marker = "```";

/// The cell separator of a table row.
const cell_separator: u8 = '|';

/// The byte that escapes a cell separator inside a cell.
const escape: u8 = '\\';

pub fn applies(path: []const u8) bool {
    return paths.has_extension(path, markdown_extension);
}

pub fn check(context: *report.Context, file: report.File) !void {
    if (!applies(file.path)) return;
    var scanner: Scanner = .{ .findings = &context.findings, .path = file.path };
    var lines: text.LineIterator = .{ .source = file.source };
    while (lines.next()) |line| try scanner.read(line);
}

/// Reads the document one line at a time, carrying the two pieces of state a line check needs:
/// whether the reader is inside a fenced code block, and how many columns the table being read
/// declared in its header.
const Scanner = struct {
    findings: *report.Findings,
    path: []const u8,
    inside_fence: bool = false,
    /// Columns the header of the table being read declared, or null between tables.
    table_columns: ?usize = null,

    fn read(self: *Scanner, line: text.Line) !void {
        try self.check_trailing_whitespace(line);
        const trimmed = std.mem.trimStart(u8, line.text, " \t");
        if (std.mem.startsWith(u8, trimmed, fence_marker)) return self.read_fence(line, trimmed);
        if (self.inside_fence) return;
        try self.check_pseudo_list_item(line, trimmed);
        try self.check_table_row(line, trimmed);
    }

    fn read_fence(self: *Scanner, line: text.Line, trimmed: []const u8) !void {
        self.table_columns = null;
        self.inside_fence = !self.inside_fence;
        // A closing fence carries no language, so only the opening one is checked.
        if (!self.inside_fence) return;
        const language = std.mem.trim(u8, trimmed[fence_marker.len..], " \t");
        if (language.len != 0) return;
        try self.add(line, "fenced code block opened with no language", .{});
    }

    fn check_trailing_whitespace(self: *Scanner, line: text.Line) !void {
        if (line.raw.len == 0) return;
        const last = line.raw[line.raw.len - 1];
        if (last != ' ' and last != '\t') return;
        try self.add(line, "trailing whitespace", .{});
    }

    fn check_pseudo_list_item(self: *Scanner, line: text.Line, trimmed: []const u8) !void {
        const marker = pseudo_list_marker(trimmed) orelse return;
        try self.add(
            line,
            "bare \"{s}\" folds into the paragraph above on GitHub; nest it as a list item",
            .{marker},
        );
    }

    fn check_table_row(self: *Scanner, line: text.Line, trimmed: []const u8) !void {
        if (trimmed.len == 0 or trimmed[0] != cell_separator) {
            self.table_columns = null;
            return;
        }
        const columns = count_columns(trimmed);
        const header_columns = self.table_columns orelse {
            self.table_columns = columns;
            return;
        };
        if (columns == header_columns) return;
        // A separator row is measured too: a `|---|---|` of the wrong width is the same error.
        try self.add(
            line,
            "table row holds {d} columns; its header holds {d}",
            .{ columns, header_columns },
        );
    }

    fn add(
        self: *Scanner,
        line: text.Line,
        comptime format: []const u8,
        arguments: anytype,
    ) !void {
        try self.findings.add(name, self.path, line.number, 1, format, arguments);
    }
};

/// The `3b.` of a line that starts with digits, one letter, a period and a space.
fn pseudo_list_marker(line: []const u8) ?[]const u8 {
    var index: usize = 0;
    while (index < line.len and std.ascii.isDigit(line[index])) index += 1;
    if (index == 0) return null;
    if (index + 2 >= line.len) return null;
    if (!std.ascii.isAlphabetic(line[index])) return null;
    if (line[index + 1] != '.' or line[index + 2] != ' ') return null;
    return line[0 .. index + 2];
}

/// The number of cells a table row holds. The outer separators are not cells, so `| a | b |` holds
/// two; a separator escaped as `\|` is content and does not split a cell.
fn count_columns(row: []const u8) usize {
    const trimmed = std.mem.trimEnd(u8, row, " \t");
    var body = trimmed;
    if (body.len != 0 and body[0] == cell_separator) body = body[1..];
    if (body.len != 0 and ends_with_separator(body)) body = body[0 .. body.len - 1];
    var cells: usize = 1;
    for (body, 0..) |byte, index| {
        if (byte != cell_separator) continue;
        if (index != 0 and body[index - 1] == escape) continue;
        cells += 1;
    }
    return cells;
}

/// True when the row's last byte is a separator that no backslash escapes.
fn ends_with_separator(body: []const u8) bool {
    if (body[body.len - 1] != cell_separator) return false;
    if (body.len < 2) return true;
    return body[body.len - 2] != escape;
}

// Tests. Each fixture pins one shape from the header.

const testing = std.testing;
const harness = @import("harness.zig");

fn findings_of(
    arena: std.mem.Allocator,
    path: []const u8,
    source: [:0]const u8,
) ![]const report.Finding {
    return harness.run(arena, @This(), path, source);
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

test "markdown counts a table's columns the way GitHub splits them" {
    try testing.expectEqual(2, count_columns("| a | b |"));
    try testing.expectEqual(2, count_columns("|---|---|"));
    try testing.expectEqual(3, count_columns("| a | b | c |"));
    try testing.expectEqual(2, count_columns("| a \\| b | c |"));
    try testing.expectEqual(2, count_columns("| a `x | y` |"));
    try testing.expectEqual(2, count_columns("| a | b"));
}

test "markdown reads a pseudo list item and nothing that resembles one" {
    try testing.expectEqualStrings("3b.", pseudo_list_marker("3b. text").?);
    try testing.expectEqualStrings("0a.", pseudo_list_marker("0a. text").?);
    try testing.expectEqualStrings("12A.", pseudo_list_marker("12A. text").?);
    try testing.expectEqual(null, pseudo_list_marker("3. text"));
    try testing.expectEqual(null, pseudo_list_marker("3b.text"));
    try testing.expectEqual(null, pseudo_list_marker("b. text"));
    try testing.expectEqual(null, pseudo_list_marker("3b."));
}

test "markdown reads every .md file and no other" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try testing.expect(applies("docs/design.md"));
    try testing.expect(applies("README.md"));
    try testing.expect(applies("./CLAUDE.md"));
    try testing.expect(!applies("src/quic/quic.zig"));
    try testing.expect(!applies("docs/design.txt"));
    try harness.expect_messages(try findings_of(arena, "docs/design.txt", failing_fixture), &.{});
}
