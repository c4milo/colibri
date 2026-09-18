//! Generates src/wire/huffman_table.zig from the Huffman code of RFC 7541 Appendix B, and checks
//! that the committed table is still what the RFC text yields (docs/design.md §8 step 1).
//!
//! Run:   zig build huffman-table     # rewrites src/wire/huffman_table.zig
//! Check: zig build test              # runs this tool with --check
//! Test:  zig test tools/huffman_table.zig
//!
//! Usage: huffman_table (--write | --check) <rfc7541.txt> <huffman_table.zig>
//!
//! The RFC gives every code twice: as bits aligned to the most significant bit, and as hex
//! aligned to the least significant bit, with the length in bits in brackets. The tool reads both
//! columns and refuses a row where they disagree, so a transcription error in either column
//! is never written to the table. It also refuses a table that is not exactly symbols 0 to 256 in order.
//!
//! The table's own properties — Kraft equality, EOS at thirty set bits, canonical order — are
//! pinned by comptime asserts in src/wire/huffman.zig, where the decoder that depends on them is.
//!
//! Exit status: 0 when the file was written or matches, 1 when --check finds a difference, 2 on a
//! usage error or an RFC text the tool cannot read as Appendix B.
const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const assert = std.debug.assert;

/// Symbols in Appendix B: the 256 octets and EOS (RFC 7541 Appendix B).
const symbol_count = 257;

/// The longest code in Appendix B, in bits.
const code_bits_max = 30;

/// The heading that opens Appendix B, and the prefix of the heading that closes it. Lines between
/// them are the only lines read.
const appendix_heading = "Appendix B.  Huffman Code";
const next_appendix_prefix = "Appendix C.";

/// What precedes the bits column in every row: two spaces and the first bar.
const bits_column_marker = "  |";

/// The largest RFC text or table file the tool reads.
const input_bytes_max = 1 << 20;

const exit_mismatch: u8 = 1;
const exit_usage: u8 = 2;

const Code = struct {
    code: u32,
    bit_count: u8,
};

const Table = [symbol_count]Code;

const ParseError = error{
    AppendixMissing,
    RowMalformed,
    ColumnsDisagree,
    SymbolOutOfOrder,
    SymbolCountWrong,
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
        std.debug.print("huffman-table: {s} is not RFC 7541 Appendix B: {s}\n", .{ rfc_path, @errorName(err) });
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
    std.debug.print("usage: huffman_table (--write | --check) <rfc7541.txt> <huffman_table.zig>\n", .{});
    std.process.exit(exit_usage);
}

fn check(io: Io, arena: Allocator, table_path: []const u8, expected: []const u8) !void {
    const committed = Io.Dir.cwd().readFileAlloc(io, table_path, arena, .limited(input_bytes_max)) catch |err| {
        std.debug.print("huffman-table: cannot read {s}: {s}\n", .{ table_path, @errorName(err) });
        std.process.exit(exit_mismatch);
    };
    if (std.mem.eql(u8, committed, expected)) return;
    std.debug.print(
        "huffman-table: {s} differs from what RFC 7541 Appendix B yields.\n" ++
            "  Run `zig build huffman-table` and review the diff.\n",
        .{table_path},
    );
    std.process.exit(exit_mismatch);
}

/// Reads every row of Appendix B out of the RFC text.
fn parse_appendix(text: []const u8) ParseError!Table {
    var table: Table = @splat(.{ .code = 0, .bit_count = 0 });
    var lines = std.mem.splitScalar(u8, text, '\n');
    var inside = false;
    var row_count: usize = 0;
    while (lines.next()) |line| {
        if (!inside) {
            inside = std.mem.eql(u8, std.mem.trimEnd(u8, line, " \r"), appendix_heading);
            continue;
        }
        if (std.mem.startsWith(u8, line, next_appendix_prefix)) break;
        if (!is_row(line)) continue;
        const row = try parse_row(line);
        if (row_count == symbol_count or row.symbol != row_count) return error.SymbolOutOfOrder;
        table[row_count] = row.code;
        row_count += 1;
    }
    if (!inside) return error.AppendixMissing;
    if (row_count != symbol_count) return error.SymbolCountWrong;
    return table;
}

/// A row is a line holding the bits column and ending in the bracketed length. Anything else in
/// the appendix — prose, the column header, a page footer — is not a row.
fn is_row(line: []const u8) bool {
    const trimmed = std.mem.trimEnd(u8, line, " \r");
    return std.mem.indexOfScalar(u8, trimmed, '|') != null and std.mem.endsWith(u8, trimmed, "]");
}

const Row = struct {
    symbol: usize,
    code: Code,
};

/// Parses `'!' ( 33)  |11111110|00    3f8  [10]`: the symbol in parentheses, the bits column, the
/// hex column and the length. The two code columns must agree.
///
/// The ASCII column can itself be `(`, `)` or `|`, so the row is read from the bits column
/// backwards: the bits column is the first `|` that follows two spaces, and the symbol is the
/// last parenthesised number before it.
fn parse_row(line: []const u8) ParseError!Row {
    const bits_start = std.mem.indexOf(u8, line, bits_column_marker) orelse return error.RowMalformed;
    const head = line[0..bits_start];
    const open = std.mem.lastIndexOfScalar(u8, head, '(') orelse return error.RowMalformed;
    const close = std.mem.indexOfScalarPos(u8, head, open, ')') orelse return error.RowMalformed;
    const symbol = parse_decimal(head[open + 1 .. close]) orelse return error.RowMalformed;

    var fields = std.mem.tokenizeScalar(u8, line[bits_start..], ' ');
    const bits_column = fields.next() orelse return error.RowMalformed;
    const hex_column = fields.next() orelse return error.RowMalformed;
    const length_column = std.mem.trim(u8, fields.rest(), " \r[]");

    const bit_count = parse_decimal(length_column) orelse return error.RowMalformed;
    if (bit_count == 0 or bit_count > code_bits_max) return error.RowMalformed;
    const from_hex = std.fmt.parseUnsigned(u32, hex_column, 16) catch return error.RowMalformed;
    const from_bits = try parse_bits(bits_column, bit_count);
    if (from_hex != from_bits) return error.ColumnsDisagree;
    return .{ .symbol = symbol, .code = .{ .code = from_hex, .bit_count = @intCast(bit_count) } };
}

/// Reads `|11111110|00` as an integer, and requires exactly `bit_count` bits.
fn parse_bits(column: []const u8, bit_count: usize) ParseError!u32 {
    var value: u32 = 0;
    var seen: usize = 0;
    for (column) |char| {
        if (char == '|') continue;
        if (char != '0' and char != '1') return error.RowMalformed;
        if (seen == code_bits_max) return error.RowMalformed;
        value = (value << 1) | @intFromBool(char == '1');
        seen += 1;
    }
    if (seen != bit_count) return error.ColumnsDisagree;
    return value;
}

fn parse_decimal(text: []const u8) ?usize {
    return std.fmt.parseUnsigned(usize, std.mem.trim(u8, text, " "), 10) catch null;
}

fn render(writer: *Io.Writer, table: *const Table) Io.Writer.Error!void {
    try writer.writeAll(
        \\//! The Huffman code of RFC 7541 Appendix B, which RFC 9204 §4.1.2 adopts without modification.
        \\//!
        \\//! Generated by tools/huffman_table.zig from docs/rfcs/rfc7541.txt. Do not edit by hand:
        \\//! `zig build huffman-table` rewrites this file, and `zig build test` fails when it differs
        \\//! from what the RFC text yields.
        \\
        \\/// One row of Appendix B: the code aligned to its least significant bit, and its length in bits.
        \\pub const Code = struct {
        \\    code: u32,
        \\    bit_count: u8,
        \\};
        \\
        \\/// Indexed by symbol: 0 to 255 are octets, and 256 is EOS.
        \\pub const codes = [257]Code{
        \\
    );
    for (table, 0..) |row, symbol| {
        try writer.print("    .{{ .code = 0x{x}, .bit_count = {d} }}, // ", .{ row.code, row.bit_count });
        if (symbol == symbol_count - 1) {
            try writer.writeAll("EOS\n");
        } else {
            try writer.print("{d}\n", .{symbol});
        }
    }
    try writer.writeAll("};\n");
}

const testing = std.testing;

const sample_appendix =
    \\Appendix B.  Huffman Code
    \\
    \\   sym:  The symbol to be represented (see Section 5.2).
    \\
    \\                                                        code
    \\                          code as bits                 as hex   len
    \\        sym              aligned to MSB                aligned   in
    \\                                                       to LSB   bits
    \\
;

/// A synthetic Appendix B: the given rows, then enough filler rows to reach EOS, then Appendix C.
fn sample_with_rows(buffer: []u8, rows: []const []const u8) ![]const u8 {
    var writer: Io.Writer = .fixed(buffer);
    try writer.writeAll(sample_appendix);
    for (rows) |row| try writer.print("{s}\n", .{row});
    for (rows.len..symbol_count) |symbol| {
        try writer.print("       ({d:>3})  |00000                                     0  [ 5]\n", .{symbol});
    }
    try writer.writeAll("\nAppendix C.  Examples\n");
    return writer.buffered();
}

test "a row reads both code columns and its length" {
    const row = try parse_row("   '!' ( 33)  |11111110|00                                 3f8  [10]");
    try testing.expectEqual(33, row.symbol);
    try testing.expectEqual(0x3f8, row.code.code);
    try testing.expectEqual(10, row.code.bit_count);
    const eos = try parse_row("   EOS (256)  |11111111|11111111|11111111|111111      3fffffff  [30]");
    try testing.expectEqual(256, eos.symbol);
    try testing.expectEqual(0x3fffffff, eos.code.code);
}

test "a row whose ASCII column is a parenthesis or a bar still reads its symbol" {
    const open = try parse_row("   '(' ( 40)  |11111110|10                                 3fa  [10]");
    try testing.expectEqual(40, open.symbol);
    const close = try parse_row("   ')' ( 41)  |11111110|11                                 3fb  [10]");
    try testing.expectEqual(41, close.symbol);
    const bar = try parse_row("   '|' (124)  |11111111|100                                7fc  [11]");
    try testing.expectEqual(124, bar.symbol);
    try testing.expectEqual(0x7fc, bar.code.code);
}

test "a row whose bits and hex disagree is refused" {
    try testing.expectError(error.ColumnsDisagree, parse_row("  ( 33)  |11111110|01   3f8  [10]"));
    try testing.expectError(error.ColumnsDisagree, parse_row("  ( 33)  |11111110|0   3f8  [10]"));
    try testing.expectError(error.RowMalformed, parse_row("  ( 33)  |11111110|0x   3f8  [10]"));
    try testing.expectError(error.RowMalformed, parse_row("  ( 33)  |00000   0  [31]"));
}

test "the appendix yields 257 rows in order and stops at Appendix C" {
    var buffer: [32768]u8 = undefined;
    const text = try sample_with_rows(&buffer, &.{"       (  0)  |11111111|11000                             1ff8  [13]"});
    const table = try parse_appendix(text);
    try testing.expectEqual(0x1ff8, table[0].code);
    try testing.expectEqual(13, table[0].bit_count);
    try testing.expectEqual(5, table[256].bit_count);
}

test "a missing, reordered or short appendix is refused" {
    try testing.expectError(error.AppendixMissing, parse_appendix("Appendix A.  Static Table\n"));
    var buffer: [32768]u8 = undefined;
    const reordered = try sample_with_rows(&buffer, &.{"       (  1)  |00000   0  [ 5]"});
    try testing.expectError(error.SymbolOutOfOrder, parse_appendix(reordered));
    try testing.expectError(error.SymbolCountWrong, parse_appendix(sample_appendix ++ "Appendix C.\n"));
}

test "the rendered table names every symbol and closes the array" {
    var table: Table = @splat(.{ .code = 0x1f, .bit_count = 5 });
    table[256] = .{ .code = 0x3fffffff, .bit_count = 30 };
    var buffer: [32768]u8 = undefined;
    var writer: Io.Writer = .fixed(&buffer);
    try render(&writer, &table);
    const text = writer.buffered();
    try testing.expect(std.mem.indexOf(u8, text, "    .{ .code = 0x1f, .bit_count = 5 }, // 0\n") != null);
    try testing.expect(std.mem.endsWith(u8, text, "    .{ .code = 0x3fffffff, .bit_count = 30 }, // EOS\n};\n"));
}
