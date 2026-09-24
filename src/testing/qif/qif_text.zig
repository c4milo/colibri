//! The QIF text format of the "QPACK Offline Interop" page: a field line per line, its name and
//! value separated by a TAB, a blank line after each header set, and `#` for a comment. Part of
//! design §9's QIF tools.
//!
//! A decoder writes each set under a `# stream <id>` comment, because it may decode sets in an
//! order other than the one they were encoded in, and the corpus's `bin/sort-qif.pl` sorts on that
//! comment.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const qpack = @import("qpack");

const Writer = core.Writer;
const FieldSection = qpack.http.field_section.FieldSection;

pub const Error = qpack.http.field_section.AppendError || error{
    /// A line with no TAB between a name and a value.
    LineMalformed,
    /// A name or value longer than a field section holds (`field_name_len_max`,
    /// `field_value_len_max`).
    LineTooLong,
};

/// Reads the header sets of a QIF text, one at a time.
pub const Reader = struct {
    lines: std.mem.SplitIterator(u8, .scalar),

    pub fn init(text: []const u8) Reader {
        return .{ .lines = std.mem.splitScalar(u8, text, '\n') };
    }

    /// Fills `section` with the next header set, and answers false once the text holds no more.
    /// A run of blank lines ends one set.
    pub fn next(reader: *Reader, section: *FieldSection) Error!bool {
        section.init();
        // Bounded by the text's lines.
        while (reader.lines.next()) |raw| {
            const line = std.mem.trimEnd(u8, raw, "\r");
            if (std.mem.startsWith(u8, line, "#")) continue;
            if (line.len == 0) {
                if (section.len() > 0) return true;
                continue;
            }
            if (std.mem.indexOfScalar(u8, line, '\t') == null) return error.LineMalformed;
            // The first TAB separates the name from the value, and the value may hold more.
            var parts = std.mem.splitScalar(u8, line, '\t');
            const name = parts.first();
            const value = parts.rest();
            if (name.len > core.constants.field_name_len_max) return error.LineTooLong;
            if (value.len > core.constants.field_value_len_max) return error.LineTooLong;
            try section.append(name, value);
        }
        return section.len() > 0;
    }
};

/// Writes one header set under its `# stream <id>` comment, with the blank line after it.
pub fn write_set(writer: *Writer, stream_id: u64, section: *const FieldSection) core.writer.Error!void {
    try writer.print("# stream {d}\n", .{stream_id});
    for (0..section.len()) |index| {
        const line = section.get(@intCast(index));
        try writer.print("{s}\t{s}\n", .{ line.name, line.value });
    }
    try writer.write_byte('\n');
}

const testing = std.testing;

/// The section and output the tests fill, placed outside any stack frame. Test-only.
var test_section: FieldSection = undefined;
const test_room: usize = 256;
var test_output: [test_room]u8 = undefined;

test "a QIF text is header sets of TAB-separated lines, with comments and blank lines skipped" {
    var reader = Reader.init("# stream 4\n:path\t/index.html\n\n\n# a comment\nx-a\tb\tc\r\n");
    try testing.expect(try reader.next(&test_section));
    try testing.expectEqual(1, test_section.len());
    try testing.expectEqualStrings("/index.html", test_section.get(0).value);
    try testing.expect(try reader.next(&test_section));
    // The first TAB separates, and a value may hold more.
    try testing.expectEqualStrings("b\tc", test_section.get(0).value);
    try testing.expect(!try reader.next(&test_section));
    var malformed = Reader.init("no tab\n");
    try testing.expectError(error.LineMalformed, malformed.next(&test_section));
}

test "a set is written under its stream comment, and reads back as the same lines" {
    test_section.init();
    try test_section.append(":method", "GET");
    try test_section.append("x-a", "");
    var writer = Writer.init(&test_output);
    try write_set(&writer, 7, &test_section);
    try testing.expectEqualStrings("# stream 7\n:method\tGET\nx-a\t\n\n", writer.written());
    var reader = Reader.init(writer.written());
    try testing.expect(try reader.next(&test_section));
    try testing.expectEqual(2, test_section.len());
    try testing.expectEqualStrings("", test_section.get(1).value);
}
