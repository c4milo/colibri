//! The shape of one commit message, as the rules of `commit_lint_rules.zig` read it: the subject
//! line, the body, and the trailer block. `tools/commit_lint.zig` is the entry point that calls
//! git and prints what the rules found; this file only splits text.
//!
//! `parse` splits the text into lines the way an editor shows them: one trailing newline is
//! removed first, so `subject\n` is one line and `subject\n\n` is two, the second blank. Line 0 is
//! the subject. The final block of `Key: value` lines whose keys are all in `trailer_keys` is the
//! trailer block; it is parsed off, so the body rules never count it against the paragraph, word
//! or column limits (CLAUDE.md, Commits). The body is what is left between the subject and the
//! trailer block, with the blank lines at either end left out.
//!
//! `trailer_keys` is a closed set because an open one lets a paragraph opt out of the body rules
//! by opening with one capitalised word and a colon. A final paragraph starting `Note: ` or
//! `Reason: ` is body, counted like any other body line.
//!
//! A block counts as trailers only when it is the last paragraph: the line before it is blank, or
//! it is the first line after the subject. A run of `Key: value` lines at the end of a longer
//! paragraph stays body.
const std = @import("std");
const Allocator = std.mem.Allocator;

/// The byte that ends a line.
pub const line_feed: u8 = '\n';

/// The bytes that count as whitespace inside a line and at its end.
pub const whitespace = " \t\r";

/// The byte that separates a trailer key from its value.
pub const trailer_colon: u8 = ':';

/// The closed set of keys a trailer line may name (CLAUDE.md, Commits), matched without regard to
/// case. A `Key: value` line naming anything else is body.
pub const trailer_keys = [_][]const u8{ "Co-Authored-By", "Signed-off-by", "Reviewed-by", "Refs", "Closes" };

/// Lines one message may hold. A longer message is an error, never a truncated read.
pub const lines_max: usize = 4096;

/// One commit message split into the parts the rules check. `body_start`, `body_end`,
/// `trailer_start` and `trailer_end` index `lines`, so a rule can name the line a violation sits
/// on.
pub const Message = struct {
    lines: []const []const u8,
    /// Line 0, or empty when the message holds no line at all.
    subject: []const u8,
    body_start: usize,
    body_end: usize,
    trailer_start: usize,
    trailer_end: usize,

    pub fn body_lines(self: *const Message) []const []const u8 {
        return self.lines[self.body_start..self.body_end];
    }

    pub fn trailer_lines(self: *const Message) []const []const u8 {
        return self.lines[self.trailer_start..self.trailer_end];
    }

    /// The 1-based line number of body line `index`.
    pub fn body_line_number(self: *const Message, index: usize) usize {
        return self.body_start + index + 1;
    }

    /// The index into `lines` of the first non-blank line after the subject, or null when the
    /// message is a subject and nothing else.
    pub fn first_content_index(self: *const Message) ?usize {
        var index: usize = 1;
        while (index < self.lines.len) : (index += 1) {
            if (!is_blank(self.lines[index])) return index;
        }
        return null;
    }
};

pub fn parse(arena: Allocator, text: []const u8) !Message {
    const lines = try split_lines(arena, text);
    if (lines.len == 0) {
        return .{
            .lines = lines,
            .subject = "",
            .body_start = 0,
            .body_end = 0,
            .trailer_start = 0,
            .trailer_end = 0,
        };
    }
    const content_end = last_content_end(lines);
    const trailer_start = trailer_start_index(lines, content_end);
    var body_start: usize = 1;
    while (body_start < trailer_start and is_blank(lines[body_start])) body_start += 1;
    var body_end = trailer_start;
    while (body_end > body_start and is_blank(lines[body_end - 1])) body_end -= 1;
    return .{
        .lines = lines,
        .subject = lines[0],
        .body_start = body_start,
        .body_end = body_end,
        .trailer_start = trailer_start,
        .trailer_end = content_end,
    };
}

/// The lines of `text`, with one trailing newline removed first. Empty text holds no line at all;
/// `"\n"` holds one blank line.
fn split_lines(arena: Allocator, text: []const u8) ![]const []const u8 {
    if (text.len == 0) return &.{};
    const trimmed = if (text[text.len - 1] == line_feed) text[0 .. text.len - 1] else text;
    var list: std.ArrayList([]const u8) = .empty;
    var iterator = std.mem.splitScalar(u8, trimmed, line_feed);
    while (iterator.next()) |line| {
        if (list.items.len >= lines_max) return error.TooManyLines;
        try list.append(arena, line);
    }
    return list.items;
}

/// One past the last non-blank line, never below 1, so the subject stays.
fn last_content_end(lines: []const []const u8) usize {
    var end = lines.len;
    while (end > 1 and is_blank(lines[end - 1])) end -= 1;
    return end;
}

/// The first line of the trailer block ending at `end`, or `end` itself when the last paragraph is
/// not a trailer block.
fn trailer_start_index(lines: []const []const u8, end: usize) usize {
    var start = end;
    while (start > 1 and is_trailer_line(lines[start - 1])) start -= 1;
    if (start == end) return end;
    if (start > 1 and !is_blank(lines[start - 1])) return end;
    return start;
}

/// True when the line reads `Key: value` with a key of `trailer_keys`, the shape git calls a
/// trailer.
pub fn is_trailer_line(line: []const u8) bool {
    const colon = std.mem.indexOfScalar(u8, line, trailer_colon) orelse return false;
    if (!is_trailer_key(line[0..colon])) return false;
    const value = line[colon + 1 ..];
    if (value.len == 0 or value[0] != ' ') return false;
    return std.mem.trim(u8, value, whitespace).len != 0;
}

/// True when the key is one of `trailer_keys`, whatever its case.
fn is_trailer_key(key: []const u8) bool {
    for (trailer_keys) |known| {
        if (std.ascii.eqlIgnoreCase(key, known)) return true;
    }
    return false;
}

/// True when the line holds nothing but whitespace.
pub fn is_blank(line: []const u8) bool {
    return std.mem.trim(u8, line, whitespace).len == 0;
}

/// The columns the line occupies: its codepoints, or its bytes when the line is not valid UTF-8.
pub fn columns(line: []const u8) usize {
    return std.unicode.utf8CountCodepoints(line) catch line.len;
}

/// The first whitespace-delimited word of the text, or empty text.
pub fn first_word(text: []const u8) []const u8 {
    var iterator = std.mem.tokenizeAny(u8, text, whitespace);
    return iterator.next() orelse "";
}

/// Blocks of consecutive non-blank lines.
pub fn count_paragraphs(lines: []const []const u8) usize {
    var count: usize = 0;
    var inside = false;
    for (lines) |line| {
        if (is_blank(line)) {
            inside = false;
            continue;
        }
        if (!inside) {
            count += 1;
            inside = true;
        }
    }
    return count;
}

/// Whitespace-delimited words across the lines.
pub fn count_words(lines: []const []const u8) usize {
    var count: usize = 0;
    for (lines) |line| {
        var iterator = std.mem.tokenizeAny(u8, line, whitespace);
        while (iterator.next()) |_| count += 1;
    }
    return count;
}

/// Blank lines at the end of the message.
pub fn count_trailing_blank_lines(lines: []const []const u8) usize {
    var count: usize = 0;
    while (count < lines.len and is_blank(lines[lines.len - 1 - count])) count += 1;
    return count;
}

// Tests. Each one pins a shape the header states, because every rule reads this split and a split
// that silently changed would move rules off the lines they report.

const testing = std.testing;

test "parse splits lines the way an editor shows them" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try testing.expectEqual(0, (try parse(arena, "")).lines.len);
    try testing.expectEqual(1, (try parse(arena, "\n")).lines.len);
    try testing.expectEqual(1, (try parse(arena, "feat(h2): add the frame reader\n")).lines.len);
    try testing.expectEqual(2, (try parse(arena, "feat(h2): add the frame reader\n\n")).lines.len);
    try testing.expectEqualStrings("feat(h2): add x", (try parse(arena, "feat(h2): add x")).subject);
}

test "parse takes the last Key: value block as trailers and leaves it out of the body" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const message = try parse(arena,
        \\feat(h2): add the frame reader
        \\
        \\Why it exists.
        \\
        \\Co-Authored-By: A <a@example.com>
        \\Signed-off-by: B <b@example.com>
        \\
    );
    try testing.expectEqual(1, message.body_lines().len);
    try testing.expectEqualStrings("Why it exists.", message.body_lines()[0]);
    try testing.expectEqual(2, message.trailer_lines().len);
    try testing.expectEqualStrings("Signed-off-by: B <b@example.com>", message.trailer_lines()[1]);
    try testing.expectEqual(3, message.body_line_number(0));
}

test "a Key: value tail inside a paragraph stays body" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const message = try parse(arena,
        \\feat(h2): add the frame reader
        \\
        \\Why it exists.
        \\Refs: https://github.com/c4milo/colibri/issues/1
        \\
    );
    try testing.expectEqual(0, message.trailer_lines().len);
    try testing.expectEqual(2, message.body_lines().len);
}

test "the trailer block is parsed off the body, not left in it" {
    // Pins the split itself: a `trailer_start_index` that always answered `end` would leave these
    // two lines in the body and count them against the body limits.
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const message = try parse(arena, "feat(h2): add x\n\nwhy\n\nRefs: a\nCloses: b\n");
    try testing.expectEqual(2, message.trailer_lines().len);
    try testing.expectEqual(1, message.body_lines().len);
    try testing.expectEqualStrings("why", message.body_lines()[0]);
}

test "a subject with no body has an empty body and no trailers" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const message = try parse(arena, "feat(h2): add x\n");
    try testing.expectEqual(0, message.body_lines().len);
    try testing.expectEqual(0, message.trailer_lines().len);
    try testing.expectEqual(null, message.first_content_index());
}

test "first_content_index finds the first non-blank line after the subject" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try testing.expectEqual(1, (try parse(arena, "feat: add x\nbody\n")).first_content_index());
    try testing.expectEqual(2, (try parse(arena, "feat: add x\n\nbody\n")).first_content_index());
    try testing.expectEqual(3, (try parse(arena, "feat: add x\n\n\nbody\n")).first_content_index());
}

test "is_trailer_line wants a known key, one space, and a value" {
    try testing.expect(is_trailer_line("Co-Authored-By: A <a@example.com>"));
    try testing.expect(is_trailer_line("Refs: 1"));
    try testing.expect(!is_trailer_line("Refs:1"));
    try testing.expect(!is_trailer_line("Refs: "));
    try testing.expect(!is_trailer_line("no colon here"));
    try testing.expect(!is_trailer_line("two words: x"));
    try testing.expect(!is_trailer_line(": x"));
}

test "is_trailer_line takes every key of the closed set, in any case" {
    for (trailer_keys) |key| {
        var line_buffer: [128]u8 = undefined;
        try testing.expect(is_trailer_line(try std.fmt.bufPrint(&line_buffer, "{s}: a value", .{key})));
        var lower_buffer: [128]u8 = undefined;
        const lowered = std.ascii.lowerString(&lower_buffer, key);
        var lowered_line: [128]u8 = undefined;
        try testing.expect(is_trailer_line(try std.fmt.bufPrint(&lowered_line, "{s}: a value", .{lowered})));
    }
}

test "is_trailer_line refuses a key outside the closed set" {
    try testing.expect(!is_trailer_line("Note: why it exists"));
    try testing.expect(!is_trailer_line("Reason: why it exists"));
    try testing.expect(!is_trailer_line("Body: why it exists"));
}

test "a final Note: paragraph is body, not trailers" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const message = try parse(arena, "feat(h2): add x\n\nNote: why it exists\n");
    try testing.expectEqual(0, message.trailer_lines().len);
    try testing.expectEqual(1, message.body_lines().len);
}

test "columns counts codepoints and falls back to bytes" {
    try testing.expectEqual(3, columns("abc"));
    try testing.expectEqual(1, columns("é"));
    try testing.expectEqual(2, columns("\xff\xfe"));
}

test "paragraphs, words and trailing blank lines are counted over the lines given" {
    const lines = [_][]const u8{ "one two", "", "three", "", "" };
    try testing.expectEqual(2, count_paragraphs(&lines));
    try testing.expectEqual(3, count_words(&lines));
    try testing.expectEqual(2, count_trailing_blank_lines(&lines));
    try testing.expectEqual(0, count_paragraphs(&.{}));
}

test "first_word takes the leading word" {
    try testing.expectEqualStrings("adds", first_word("adds a thing"));
    try testing.expectEqualStrings("add", first_word("  add"));
    try testing.expectEqualStrings("", first_word("   "));
}
