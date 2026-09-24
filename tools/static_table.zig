//! Generates a static table from an RFC's Appendix A, and checks that the committed table is
//! still what the RFC text yields (docs/design.md §8 steps 3 and 11). The shape is
//! tools/huffman_table.zig's.
//!
//! Two tables, one generator. HPACK's is RFC 7541 Appendix A, 61 entries numbered from 1;
//! QPACK's is RFC 9204 Appendix A, 99 entries numbered from 0. Both appendices are the same
//! rows of `| index | name | value |`, so the parser is one and the differences are a `Variant`.
//!
//! Run:   zig build static-table | zig build qpack-static-table
//! Check: zig build test              # runs this tool with --check for both
//! Test:  zig test tools/static_table.zig
//!
//! Usage: static_table (--write | --check) (hpack | qpack) <rfc.txt> <static_table.zig>
//!
//! The tool reads every row between the appendix heading and the next one, requires the indices
//! to run from the variant's first with no gap, and refuses a name or value holding anything but
//! printable ASCII, so that the generated source needs no escaping.
//!
//! RFC 9204's table wraps ten values onto rows of their own, whose index column is empty. Each
//! such row continues the row above. The RFC text breaks a line at a space, which it drops, or
//! after a `-` or a `/`, which it keeps, so a continuation joins with no space after either and
//! with one space otherwise. That rule gives all ten values as the RFC defines them: entry 52 is
//! `text/html; charset=utf-8` and entry 54 `text/plain;charset=utf-8`. RFC 7541's table wraps
//! none.
//!
//! Exit status: 0 when the file was written or matches, 1 when --check finds a difference, 2 on a
//! usage error or an RFC text the tool cannot read as Appendix A.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const assert = std.debug.assert;

/// Columns of one row: the index, the name and the value.
const row_columns = 3;

/// What differs between the two tables. Everything else below is shared.
const Variant = struct {
    /// The name on the command line.
    flag: []const u8,
    /// The RFC as a citation and as the vendored file the generated header names.
    rfc: []const u8,
    rfc_file: []const u8,
    /// How many entries the appendix holds, and the index of the first.
    entry_count: usize,
    first_index: usize,
    /// The heading that opens Appendix A, and the prefix of the heading that closes it. Lines
    /// between them are the only lines read.
    appendix_heading: []const u8,
    next_appendix_prefix: []const u8,
    /// The build step that rewrites the table, named in the generated header.
    build_step: []const u8,
    /// The two sentences of the generated header that state the numbering.
    numbering: []const u8,
    access: []const u8,
};

const hpack_variant: Variant = .{
    .flag = "hpack",
    .rfc = "RFC 7541",
    .rfc_file = "docs/rfcs/rfc7541.txt",
    .entry_count = 61,
    .first_index = 1,
    .appendix_heading = "Appendix A.  Static Table Definition",
    .next_appendix_prefix = "Appendix B.",
    .build_step = "static-table",
    .numbering = "numbered from 1 (§2.3.3)",
    .access = "Entry `n` of Appendix A is `entries[n - 1]`: the table is indexed from 1 (RFC 7541 §2.3.3).",
};

const qpack_variant: Variant = .{
    .flag = "qpack",
    .rfc = "RFC 9204",
    .rfc_file = "docs/rfcs/rfc9204.txt",
    .entry_count = 99,
    .first_index = 0,
    .appendix_heading = "Appendix A.  Static Table",
    .next_appendix_prefix = "Appendix B.",
    .build_step = "qpack-static-table",
    .numbering = "numbered from 0 (§3.1)",
    .access = "Entry `n` of Appendix A is `entries[n]`: the table is indexed from 0 (RFC 9204 §3.1).",
};

/// The largest RFC text or table file the tool reads.
const input_bytes_max = 1 << 20;

const exit_mismatch: u8 = 1;
const exit_usage: u8 = 2;

const Entry = struct {
    name: []const u8,
    value: []const u8,
};

fn Table(comptime variant: Variant) type {
    return [variant.entry_count]Entry;
}

const ParseError = Allocator.Error || error{
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
    if (arguments.len != 5) usage();
    const mode: Mode = if (std.mem.eql(u8, arguments[1], "--write"))
        .write
    else if (std.mem.eql(u8, arguments[1], "--check"))
        .check
    else
        usage();
    if (std.mem.eql(u8, arguments[2], hpack_variant.flag)) {
        return generate(hpack_variant, init, arena, mode, arguments[3], arguments[4]);
    }
    if (std.mem.eql(u8, arguments[2], qpack_variant.flag)) {
        return generate(qpack_variant, init, arena, mode, arguments[3], arguments[4]);
    }
    usage();
}

fn generate(
    comptime variant: Variant,
    init: std.process.Init,
    arena: Allocator,
    mode: Mode,
    rfc_path: []const u8,
    table_path: []const u8,
) !void {
    const rfc_text = try Io.Dir.cwd().readFileAlloc(init.io, rfc_path, arena, .limited(input_bytes_max));
    const table = parse_appendix(variant, arena, rfc_text) catch |err| {
        std.debug.print("{s}: {s} is not {s} Appendix A: {s}\n", .{ variant.build_step, rfc_path, variant.rfc, @errorName(err) });
        std.process.exit(exit_usage);
    };
    var rendered: Io.Writer.Allocating = .init(arena);
    try render(variant, &rendered.writer, &table);
    switch (mode) {
        .write => try Io.Dir.cwd().writeFile(init.io, .{ .sub_path = table_path, .data = rendered.written() }),
        .check => try check(variant, init.io, arena, table_path, rendered.written()),
    }
}

fn usage() noreturn {
    std.debug.print("usage: static_table (--write | --check) (hpack | qpack) <rfc.txt> <static_table.zig>\n", .{});
    std.process.exit(exit_usage);
}

fn check(comptime variant: Variant, io: Io, arena: Allocator, table_path: []const u8, expected: []const u8) !void {
    const committed = Io.Dir.cwd().readFileAlloc(io, table_path, arena, .limited(input_bytes_max)) catch |err| {
        std.debug.print("{s}: cannot read {s}: {s}\n", .{ variant.build_step, table_path, @errorName(err) });
        std.process.exit(exit_mismatch);
    };
    if (std.mem.eql(u8, committed, expected)) return;
    std.debug.print(
        variant.build_step ++ ": {s} differs from what " ++ variant.rfc ++ " Appendix A yields.\n" ++
            "  Run `zig build " ++ variant.build_step ++ "` and review the diff.\n",
        .{table_path},
    );
    std.process.exit(exit_mismatch);
}

/// Reads every row of Appendix A's Table 1 out of the RFC text, joining each continuation row onto
/// the row above.
fn parse_appendix(comptime variant: Variant, arena: Allocator, text: []const u8) ParseError!Table(variant) {
    var table: Table(variant) = @splat(.{ .name = "", .value = "" });
    var lines = std.mem.splitScalar(u8, text, '\n');
    var inside = false;
    var row_count: usize = 0;
    while (lines.next()) |line| {
        if (!inside) {
            inside = std.mem.eql(u8, std.mem.trimEnd(u8, line, " \r"), variant.appendix_heading);
            continue;
        }
        if (std.mem.startsWith(u8, line, variant.next_appendix_prefix)) break;
        const row = switch (try parse_row(variant, line) orelse continue) {
            .row => |row| row,
            .continuation => |rest| {
                try continue_row(arena, table[0..row_count], rest);
                continue;
            },
        };
        if (row_count == variant.entry_count or row.index != row_count + variant.first_index) {
            return error.IndexOutOfOrder;
        }
        table[row_count] = row.entry;
        row_count += 1;
    }
    if (!inside) return error.AppendixMissing;
    if (row_count != variant.entry_count) return error.EntryCountWrong;
    return table;
}

const Row = struct {
    index: usize,
    entry: Entry,
};

/// Joins a continuation onto the last row read, of which there must be one.
fn continue_row(arena: Allocator, read: []Entry, rest: Entry) ParseError!void {
    if (read.len == 0) return error.RowMalformed;
    const above = &read[read.len - 1];
    above.name = try join(arena, above.name, rest.name);
    above.value = try join(arena, above.value, rest.value);
}

/// A line of the table: a numbered row, or a row with no index that continues the one above.
const Line = union(enum) {
    row: Row,
    continuation: Entry,
};

/// Joins a column's continuation onto it: with no space after a `-` or a `/`, where the RFC text
/// breaks inside a value, and with the one space the text dropped otherwise.
fn join(arena: Allocator, first: []const u8, rest: []const u8) Allocator.Error![]const u8 {
    if (rest.len == 0) return first;
    if (first.len == 0) return rest;
    const glue: []const u8 = switch (first[first.len - 1]) {
        '-', '/' => "",
        else => " ",
    };
    return std.mem.concat(arena, u8, &.{ first, glue, rest });
}

/// Parses `| 16    | accept-encoding             | gzip, deflate |` into its three columns, with
/// the spaces that pad each column removed. A line that is not four bars around three columns,
/// or whose first column is neither a number nor empty, is not a row: the column header and the
/// `+---+` rules are rejected here. An empty first column is a continuation of the row above.
fn parse_row(comptime variant: Variant, line: []const u8) ParseError!?Line {
    const trimmed = std.mem.trim(u8, line, " \r");
    if (!std.mem.startsWith(u8, trimmed, "|") or !std.mem.endsWith(u8, trimmed, "|")) return null;
    var columns: [row_columns][]const u8 = undefined;
    var pieces = std.mem.splitScalar(u8, trimmed[1 .. trimmed.len - 1], '|');
    for (&columns) |*column| {
        column.* = std.mem.trim(u8, pieces.next() orelse return null, " ");
    }
    if (pieces.next() != null) return null;
    for (columns[1..]) |column| {
        if (!is_plain(column)) return error.NotPrintable;
    }
    if (columns[0].len == 0) return .{ .continuation = .{ .name = columns[1], .value = columns[2] } };
    const index = std.fmt.parseUnsigned(usize, columns[0], 10) catch return null;
    if (index < variant.first_index) return error.RowMalformed;
    if (columns[1].len == 0) return error.RowMalformed;
    return .{ .row = .{ .index = index, .entry = .{ .name = columns[1], .value = columns[2] } } };
}

/// True when every octet is printable ASCII and none needs escaping in a Zig string literal.
fn is_plain(column: []const u8) bool {
    for (column) |char| {
        if (!std.ascii.isPrint(char) or char == '"' or char == '\\') return false;
    }
    return true;
}

fn render(comptime variant: Variant, writer: *Io.Writer, table: *const Table(variant)) Io.Writer.Error!void {
    try writer.writeAll(header(variant));
    for (table, variant.first_index..) |entry, index| {
        try writer.print("    .{{ .name = \"{s}\", .value = \"{s}\" }}, // {d}\n", .{
            entry.name,
            entry.value,
            index,
        });
    }
    try writer.writeAll("};\n");
}

/// The generated file's header, built from the variant so the two tables read alike.
fn header(comptime variant: Variant) []const u8 {
    const count = std.fmt.comptimePrint("{d}", .{variant.entry_count});
    return "//! The static table of " ++ variant.rfc ++ " Appendix A: " ++ count ++ " entries, " ++
        variant.numbering ++ ".\n" ++
        "//!\n" ++
        "//! Generated by tools/static_table.zig from " ++ variant.rfc_file ++ ". Do not edit by hand:\n" ++
        "//! `zig build " ++ variant.build_step ++ "` rewrites this file, and `zig build test` fails when it differs\n" ++
        "//! from what the RFC text yields.\n" ++
        "\n" ++
        "/// One row of Appendix A.\n" ++
        "pub const Entry = struct {\n" ++
        "    name: []const u8,\n" ++
        "    value: []const u8,\n" ++
        "};\n" ++
        "\n" ++
        "/// " ++ variant.access ++ "\n" ++
        "pub const entries = [" ++ count ++ "]Entry{\n";
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
    const row = (try parse_row(hpack_variant, "          | 16    | accept-encoding             | gzip, deflate |")).?.row;
    try testing.expectEqual(16, row.index);
    try testing.expectEqualStrings("accept-encoding", row.entry.name);
    try testing.expectEqualStrings("gzip, deflate", row.entry.value);
    const empty = (try parse_row(hpack_variant, "          | 1     | :authority                  |               |")).?.row;
    try testing.expectEqualStrings("", empty.entry.value);
}

test "the column header, the rules and prose are not rows" {
    try testing.expectEqual(null, try parse_row(hpack_variant, "          | Index | Header Name                 | Header Value  |"));
    try testing.expectEqual(null, try parse_row(hpack_variant, "          +-------+-----------------------------+---------------+"));
    try testing.expectEqual(null, try parse_row(hpack_variant, "   Table 1 lists the predefined header fields"));
    try testing.expectEqual(null, try parse_row(hpack_variant, "          | 1     | :authority  |   |  extra   |"));
}

test "a row with an unprintable or quoted octet, an empty name or index 0 is refused" {
    try testing.expectError(error.NotPrintable, parse_row(hpack_variant, "| 1 | na\x01me | v |"));
    try testing.expectError(error.NotPrintable, parse_row(hpack_variant, "| 1 | name | \"v\" |"));
    try testing.expectError(error.RowMalformed, parse_row(hpack_variant, "| 1 |  | v |"));
    try testing.expectError(error.RowMalformed, parse_row(hpack_variant, "| 0 | name | v |"));
}

test "the appendix must run from 1 with no gap and hold exactly 61 rows" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try testing.expectError(error.IndexOutOfOrder, parse_appendix(hpack_variant, arena, sample_appendix));
    try testing.expectError(error.AppendixMissing, parse_appendix(hpack_variant, arena, "no appendix here\n"));
    var text: std.ArrayList(u8) = .empty;
    try text.appendSlice(arena, hpack_variant.appendix_heading ++ "\n");
    for (1..hpack_variant.entry_count + 1) |index| {
        try text.print(arena, "| {d} | name-{d} | value |\n", .{ index, index });
    }
    try text.appendSlice(arena, hpack_variant.next_appendix_prefix ++ "\n");
    const table = try parse_appendix(hpack_variant, arena, text.items);
    try testing.expectEqualStrings("name-61", table[hpack_variant.entry_count - 1].name);
    try text.insertSlice(arena, text.items.len - hpack_variant.next_appendix_prefix.len - 1, "| 62 | name-62 | value |\n");
    try testing.expectError(error.IndexOutOfOrder, parse_appendix(hpack_variant, arena, text.items));
}

test "the committed RFC text yields exactly the first and last entries of Appendix A" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const text = try Io.Dir.cwd().readFileAlloc(testing.io, hpack_variant.rfc_file, arena_state.allocator(), .limited(input_bytes_max));
    const table = try parse_appendix(hpack_variant, arena_state.allocator(), text);
    try testing.expectEqualStrings(":authority", table[0].name);
    try testing.expectEqualStrings("www-authenticate", table[hpack_variant.entry_count - 1].name);
    try testing.expectEqualStrings("gzip, deflate", table[15].value);
}

test "the committed RFC text yields exactly the first and last entries of QPACK's Appendix A" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const text = try Io.Dir.cwd().readFileAlloc(testing.io, qpack_variant.rfc_file, arena_state.allocator(), .limited(input_bytes_max));
    const table = try parse_appendix(qpack_variant, arena_state.allocator(), text);
    // RFC 9204 §3.1 numbers the static table from 0, so entry 0 is the first row.
    try testing.expectEqualStrings(":authority", table[0].name);
    try testing.expectEqualStrings("/", table[1].value);
    try testing.expectEqualStrings("x-frame-options", table[qpack_variant.entry_count - 1].name);
    // The ten values the RFC wraps onto a second or third row, whole.
    try testing.expectEqualStrings("application/dns-message", table[30].value);
    try testing.expectEqualStrings("public, max-age=31536000", table[41].value);
    try testing.expectEqualStrings("application/dns-message", table[44].value);
    try testing.expectEqualStrings("application/javascript", table[45].value);
    try testing.expectEqualStrings("application/x-www-form-urlencoded", table[47].value);
    try testing.expectEqualStrings("text/html; charset=utf-8", table[52].value);
    try testing.expectEqualStrings("text/plain;charset=utf-8", table[54].value);
    try testing.expectEqualStrings("max-age=31536000; includesubdomains", table[57].value);
    try testing.expectEqualStrings("max-age=31536000; includesubdomains; preload", table[58].value);
    try testing.expectEqualStrings("script-src 'none'; object-src 'none'; base-uri 'none'", table[85].value);
}

test "a continuation row joins with no space after a hyphen or a slash, and one space otherwise" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try testing.expectEqualStrings("a-b", try join(arena, "a-", "b"));
    try testing.expectEqualStrings("a/b", try join(arena, "a/", "b"));
    try testing.expectEqualStrings("a; b", try join(arena, "a;", "b"));
    try testing.expectEqualStrings("a", try join(arena, "a", ""));
    try testing.expectEqualStrings("b", try join(arena, "", "b"));
    const rest = (try parse_row(qpack_variant, "   |       |                                  | message               |")).?;
    try testing.expectEqualStrings("message", rest.continuation.value);
    // A continuation with no row above it is refused.
    const orphan = qpack_variant.appendix_heading ++ "\n|  |  | message |\n";
    try testing.expectError(error.RowMalformed, parse_appendix(qpack_variant, arena, orphan));
}

test "QPACK's appendix must run from 0 and HPACK's index 0 is still refused" {
    try testing.expectEqual(0, (try parse_row(qpack_variant, "| 0 | :authority | |")).?.row.index);
    try testing.expectError(error.RowMalformed, parse_row(hpack_variant, "| 0 | :authority | |"));
}
