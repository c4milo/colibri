//! Generates src/hpack/static_table.zig from the static table of RFC 7541 Appendix A, and checks
//! that the committed table is still what the RFC text yields (docs/design.md §8 step 3). The
//! shape is tools/huffman_table.zig's.
//!
//! Run:   zig build static-table      # rewrites src/hpack/static_table.zig
//! Check: zig build test              # runs this tool with --check
//! Test:  zig test tools/static_table.zig
//!
//! Usage: static_table (--write | --check) <rfc7541.txt> <static_table.zig>
//!
//! Appendix A's Table 1 is rows of `| index | name | value |`. The tool reads every row between
//! the appendix heading and the next one, requires the indices to run from 1 with no gap, and
//! refuses a name or value holding anything but printable ASCII, so that the generated source
//! needs no escaping.
//!
//! Exit status: 0 when the file was written or matches, 1 when --check finds a difference, 2 on a
//! usage error or an RFC text the tool cannot read as Appendix A.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const assert = std.debug.assert;

/// Entries in Appendix A (RFC 7541 §2.3.3 numbers them from 1).
const entry_count = 61;

/// Columns of one row: the index, the name and the value.
const row_columns = 3;

/// The heading that opens Appendix A, and the prefix of the heading that closes it. Lines between
/// them are the only lines read.
const appendix_heading = "Appendix A.  Static Table Definition";
const next_appendix_prefix = "Appendix B.";

/// The largest RFC text or table file the tool reads.
const input_bytes_max = 1 << 20;

const exit_mismatch: u8 = 1;
const exit_usage: u8 = 2;

const Entry = struct {
    name: []const u8,
    value: []const u8,
};

const Table = [entry_count]Entry;

const ParseError = error{
    AppendixMissing,
    RowMalformed,
    IndexOutOfOrder,
    EntryCountWrong,
    NotPrintable,
};

const Mode = enum { write, check };

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const arguments = try init.minimal.args.toSlice(arena);
    if (arguments.len != 4) usage();
    const mode: Mode = if (std.mem.eql(u8, arguments[1], "--write"))
        .write
    else if (std.mem.eql(u8, arguments[1], "--check"))
        .check
    else
        usage();
    const rfc_path = arguments[2];
    const table_path = arguments[3];
    const rfc_text = try Io.Dir.cwd().readFileAlloc(init.io, rfc_path, arena, .limited(input_bytes_max));
    const table = parse_appendix(rfc_text) catch |err| {
        std.debug.print("static-table: {s} is not RFC 7541 Appendix A: {s}\n", .{ rfc_path, @errorName(err) });
        std.process.exit(exit_usage);
    };
    var rendered: Io.Writer.Allocating = .init(arena);
    try render(&rendered.writer, &table);
    switch (mode) {
        .write => try Io.Dir.cwd().writeFile(init.io, .{ .sub_path = table_path, .data = rendered.written() }),
        .check => try check(init.io, arena, table_path, rendered.written()),
    }
}

fn usage() noreturn {
    std.debug.print("usage: static_table (--write | --check) <rfc7541.txt> <static_table.zig>\n", .{});
    std.process.exit(exit_usage);
}

fn check(io: Io, arena: Allocator, table_path: []const u8, expected: []const u8) !void {
    const committed = Io.Dir.cwd().readFileAlloc(io, table_path, arena, .limited(input_bytes_max)) catch |err| {
        std.debug.print("static-table: cannot read {s}: {s}\n", .{ table_path, @errorName(err) });
        std.process.exit(exit_mismatch);
    };
    if (std.mem.eql(u8, committed, expected)) return;
    std.debug.print(
        "static-table: {s} differs from what RFC 7541 Appendix A yields.\n" ++
            "  Run `zig build static-table` and review the diff.\n",
        .{table_path},
    );
    std.process.exit(exit_mismatch);
}

/// Reads every row of Appendix A's Table 1 out of the RFC text.
fn parse_appendix(text: []const u8) ParseError!Table {
    var table: Table = @splat(.{ .name = "", .value = "" });
    var lines = std.mem.splitScalar(u8, text, '\n');
    var inside = false;
    var row_count: usize = 0;
    while (lines.next()) |line| {
        if (!inside) {
            inside = std.mem.eql(u8, std.mem.trimEnd(u8, line, " \r"), appendix_heading);
            continue;
        }
        if (std.mem.startsWith(u8, line, next_appendix_prefix)) break;
        const row = try parse_row(line) orelse continue;
        if (row_count == entry_count or row.index != row_count + 1) return error.IndexOutOfOrder;
        table[row_count] = row.entry;
        row_count += 1;
    }
    if (!inside) return error.AppendixMissing;
    if (row_count != entry_count) return error.EntryCountWrong;
    return table;
}

const Row = struct {
    index: usize,
    entry: Entry,
};

/// Parses `| 16    | accept-encoding             | gzip, deflate |` into its three columns, with
/// the spaces that pad each column removed. A line that is not four bars around three columns,
/// or whose first column is not a number, is not a row: the column header and the `+---+` rules
/// fall out here.
fn parse_row(line: []const u8) ParseError!?Row {
    const trimmed = std.mem.trim(u8, line, " \r");
    if (!std.mem.startsWith(u8, trimmed, "|") or !std.mem.endsWith(u8, trimmed, "|")) return null;
    var columns: [row_columns][]const u8 = undefined;
    var pieces = std.mem.splitScalar(u8, trimmed[1 .. trimmed.len - 1], '|');
    for (&columns) |*column| {
        column.* = std.mem.trim(u8, pieces.next() orelse return null, " ");
    }
    if (pieces.next() != null) return null;
    const index = std.fmt.parseUnsigned(usize, columns[0], 10) catch return null;
    if (index == 0) return error.RowMalformed;
    for (columns[1..]) |column| {
        if (!is_plain(column)) return error.NotPrintable;
    }
    if (columns[1].len == 0) return error.RowMalformed;
    return .{ .index = index, .entry = .{ .name = columns[1], .value = columns[2] } };
}

/// True when every octet is printable ASCII and none needs escaping in a Zig string literal.
fn is_plain(column: []const u8) bool {
    for (column) |char| {
        if (!std.ascii.isPrint(char) or char == '"' or char == '\\') return false;
    }
    return true;
}

fn render(writer: *Io.Writer, table: *const Table) Io.Writer.Error!void {
    try writer.writeAll(
        \\//! The static table of RFC 7541 Appendix A: 61 entries, numbered from 1 (§2.3.3).
        \\//!
        \\//! Generated by tools/static_table.zig from docs/rfcs/rfc7541.txt. Do not edit by hand:
        \\//! `zig build static-table` rewrites this file, and `zig build test` fails when it differs
        \\//! from what the RFC text yields.
        \\
        \\/// One row of Appendix A.
        \\pub const Entry = struct {
        \\    name: []const u8,
        \\    value: []const u8,
        \\};
        \\
        \\/// Entry `n` of Appendix A is `entries[n - 1]`: the table is indexed from 1 (RFC 7541 §2.3.3).
        \\pub const entries = [61]Entry{
        \\
    );
    for (table, 1..) |entry, index| {
        try writer.print("    .{{ .name = \"{s}\", .value = \"{s}\" }}, // {d}\n", .{
            entry.name,
            entry.value,
            index,
        });
    }
    try writer.writeAll("};\n");
}

const testing = std.testing;

const sample_appendix =
    \\Appendix A.  Static Table Definition
    \\
    \\   Table 1 lists the predefined header fields that make up the static
    \\   table and gives the index of each entry.
    \\
    \\          +-------+-----------------------------+---------------+
    \\          | Index | Header Name                 | Header Value  |
    \\          +-------+-----------------------------+---------------+
    \\          | 1     | :authority                  |               |
    \\          | 2     | :method                     | GET           |
    \\          | 16    | accept-encoding             | gzip, deflate |
    \\
    \\Appendix B.  Huffman Code
;

test "a row yields its index, name and value with the padding removed" {
    const row = (try parse_row("          | 16    | accept-encoding             | gzip, deflate |")).?;
    try testing.expectEqual(16, row.index);
    try testing.expectEqualStrings("accept-encoding", row.entry.name);
    try testing.expectEqualStrings("gzip, deflate", row.entry.value);
    const empty = (try parse_row("          | 1     | :authority                  |               |")).?;
    try testing.expectEqualStrings("", empty.entry.value);
}

test "the column header, the rules and prose are not rows" {
    try testing.expectEqual(null, try parse_row("          | Index | Header Name                 | Header Value  |"));
    try testing.expectEqual(null, try parse_row("          +-------+-----------------------------+---------------+"));
    try testing.expectEqual(null, try parse_row("   Table 1 lists the predefined header fields"));
    try testing.expectEqual(null, try parse_row("          | 1     | :authority  |   |  extra   |"));
}

test "a row with an unprintable or quoted octet, an empty name or index 0 is refused" {
    try testing.expectError(error.NotPrintable, parse_row("| 1 | na\x01me | v |"));
    try testing.expectError(error.NotPrintable, parse_row("| 1 | name | \"v\" |"));
    try testing.expectError(error.RowMalformed, parse_row("| 1 |  | v |"));
    try testing.expectError(error.RowMalformed, parse_row("| 0 | name | v |"));
}

test "the appendix must run from 1 with no gap and hold exactly 61 rows" {
    try testing.expectError(error.IndexOutOfOrder, parse_appendix(sample_appendix));
    try testing.expectError(error.AppendixMissing, parse_appendix("no appendix here\n"));
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var text: std.ArrayList(u8) = .empty;
    try text.appendSlice(arena, appendix_heading ++ "\n");
    for (1..entry_count + 1) |index| {
        try text.print(arena, "| {d} | name-{d} | value |\n", .{ index, index });
    }
    try text.appendSlice(arena, next_appendix_prefix ++ "\n");
    const table = try parse_appendix(text.items);
    try testing.expectEqualStrings("name-61", table[entry_count - 1].name);
    try text.insertSlice(arena, text.items.len - next_appendix_prefix.len - 1, "| 62 | name-62 | value |\n");
    try testing.expectError(error.IndexOutOfOrder, parse_appendix(text.items));
}

test "the committed RFC text yields exactly the first and last entries of Appendix A" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const text = try Io.Dir.cwd().readFileAlloc(testing.io, "docs/rfcs/rfc7541.txt", arena_state.allocator(), .limited(input_bytes_max));
    const table = try parse_appendix(text);
    try testing.expectEqualStrings(":authority", table[0].name);
    try testing.expectEqualStrings("www-authenticate", table[entry_count - 1].name);
    try testing.expectEqualStrings("gzip, deflate", table[15].value);
}
