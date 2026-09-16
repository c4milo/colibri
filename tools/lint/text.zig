//! The line reader the text rules share: an iterator over the lines of a source with their
//! 1-based numbers. Only the markdown rule and the file-length rule read text this way; every
//! other rule reads the parsed tree instead.

const std = @import("std");

pub const Line = struct {
    /// The line without its terminator and without a carriage return before it.
    text: []const u8,
    /// The line as written, carriage return included. The trailing-whitespace check reads this,
    /// so a file with CRLF terminators is measured on what it holds rather than on what an
    /// iterator tidied away.
    raw: []const u8,
    /// 1-based.
    number: usize,
    /// Byte offset of the line's first byte in the source.
    start: usize,
};

/// Yields every line of `source` without its terminator. A trailing newline ends the last line
/// and does not start an empty one.
pub const LineIterator = struct {
    source: []const u8,
    offset: usize = 0,
    number: usize = 0,

    pub fn next(self: *LineIterator) ?Line {
        if (self.offset >= self.source.len) return null;
        const remaining = self.source[self.offset..];
        const length = std.mem.indexOfScalar(u8, remaining, '\n') orelse remaining.len;
        const raw = remaining[0..length];
        const line: Line = .{
            .text = std.mem.trimEnd(u8, raw, "\r"),
            .raw = raw,
            .number = self.number + 1,
            .start = self.offset,
        };
        self.offset += @min(length + 1, remaining.len);
        self.number += 1;
        return line;
    }
};

/// Counts lines the way an editor numbers them: one per newline, plus one for a last line that
/// has no newline after it.
pub fn count_lines(source: []const u8) u32 {
    var count: u32 = 0;
    for (source) |byte| {
        if (byte == '\n') count += 1;
    }
    if (source.len > 0 and source[source.len - 1] != '\n') count += 1;
    return count;
}

// Tests.

const testing = std.testing;

test "LineIterator numbers lines from 1 and drops terminators" {
    var lines: LineIterator = .{ .source = "one\r\ntwo\n\nfour" };
    const one = lines.next().?;
    try testing.expectEqualStrings("one", one.text);
    try testing.expectEqualStrings("one\r", one.raw);
    try testing.expectEqual(1, one.number);
    try testing.expectEqual(0, one.start);
    const two = lines.next().?;
    try testing.expectEqualStrings("two", two.text);
    try testing.expectEqual(5, two.start);
    try testing.expectEqualStrings("", lines.next().?.text);
    const four = lines.next().?;
    try testing.expectEqualStrings("four", four.text);
    try testing.expectEqual(4, four.number);
    try testing.expectEqual(null, lines.next());
}

test "LineIterator does not start an empty line after a trailing newline" {
    var lines: LineIterator = .{ .source = "only\n" };
    try testing.expectEqualStrings("only", lines.next().?.text);
    try testing.expectEqual(null, lines.next());
    var empty: LineIterator = .{ .source = "" };
    try testing.expectEqual(null, empty.next());
}

test "count_lines counts lines the way an editor numbers them" {
    try testing.expectEqual(0, count_lines(""));
    try testing.expectEqual(1, count_lines("x"));
    try testing.expectEqual(1, count_lines("x\n"));
    try testing.expectEqual(2, count_lines("x\ny"));
    try testing.expectEqual(3, count_lines("x\ny\nz\n"));
}
