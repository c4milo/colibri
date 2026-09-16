//! Builds, decodes and describes the corpus cases of `corpus_cases.zig` (decision 26). Pure: it
//! reads no file and writes none. `tools/golden.zig` writes what `build` and `render_manifest`
//! produce, and `golden.zig` checks the committed files against the same two functions.
//!
//! A manifest is colibri's own format, so it is versioned (CLAUDE.md non-negotiable 6). Version 1
//! is a header line and one line per case, fields separated by one space:
//!
//!     colibri-golden-manifest version=1 format=<format> cases=<count>
//!     <name> len=<octets> crc32=0x<8 hex digits> verdict=<accept|error name> <parameters>
//!
//! The parameters name the construction and its inputs as `key=value` pairs, with `text` written as
//! hex octets, so a line states everything the case was built from.
const std = @import("std");
const assert = std.debug.assert;
pub const core = @import("core");
const wire = @import("wire");
pub const constants = @import("constants.zig");
pub const cases = @import("corpus_cases.zig");

const Reader = core.Reader;
const Writer = core.Writer;
const Case = cases.Case;
const Format = cases.Format;

/// Every error a corpus decode can return. A rejection outside this set does not compile.
pub const DecodeError = core.reader.Error || wire.string_literal.DecodeError || error{
    /// The decoder succeeded without consuming every octet of the case.
    TrailingOctets,
};

comptime {
    for (cases.all) |entry| {
        assert(entry.cases.len <= constants.cases_per_format_max);
        for (entry.cases) |case| {
            if (case.rejection) |rejection| {
                const in_set: DecodeError = @errorCast(rejection);
                assert(@errorName(in_set).len > 0);
            }
        }
    }
}

/// The cases of one format.
pub fn cases_of(format: Format) []const Case {
    for (cases.all) |entry| {
        if (entry.format == format) return entry.cases;
    }
    unreachable;
}

/// The case named `name` in `format`, which the table must hold.
pub fn find(format: Format, name: []const u8) *const Case {
    for (cases_of(format)) |*case| {
        if (std.mem.eql(u8, case.name, name)) return case;
    }
    unreachable;
}

/// Writes the octets `case` is built from.
pub fn build(format: Format, case: *const Case, output: *Writer) core.writer.Error!void {
    switch (case.construction) {
        .literal => |octets| try output.write_bytes(octets),
        .varint => |varint| try wire.varint.encode_with_len(
            output,
            varint.value,
            varint.encoded_len,
        ),
        .prefixed_integer => |integer| switch (case.prefix_size) {
            inline 1...8 => |size| try wire.prefixed_integer.encode(
                size,
                output,
                integer.high_bits,
                integer.value,
            ),
            else => unreachable,
        },
        .huffman => |text| try wire.huffman.encode(text, output),
        .string_literal => |literal| switch (case.prefix_size) {
            inline 2...8 => |size| try wire.string_literal.encode(
                size,
                output,
                literal.high_bits,
                literal.text,
                literal.coding,
            ),
            else => unreachable,
        },
        .truncated => |truncated| {
            var buffer: [constants.case_len_max]u8 = @splat(0);
            var whole = Writer.init(&buffer);
            try build(format, find(format, truncated.case_name), &whole);
            assert(truncated.drop <= whole.offset);
            try output.write_bytes(whole.written()[0 .. whole.offset - truncated.drop]);
        },
    }
}

/// Decodes `octets` as one value of `format`, and requires every octet consumed.
pub fn decode(format: Format, prefix_size: u4, octets: []const u8) DecodeError!void {
    var reader = Reader.init(octets);
    var buffer: [constants.decoded_len_max]u8 = @splat(0);
    var output = Writer.init(&buffer);
    switch (format) {
        .varint => _ = try wire.varint.decode(&reader),
        .prefixed_integer => switch (prefix_size) {
            inline 1...8 => |size| _ = try wire.prefixed_integer.decode(size, &reader),
            else => unreachable,
        },
        .huffman => try wire.huffman.decode(reader.take_rest(), &output),
        .string_literal => switch (prefix_size) {
            inline 2...8 => |size| _ = try wire.string_literal.decode(size, &reader, &output),
            else => unreachable,
        },
    }
    if (reader.remaining_len() != 0) return error.TrailingOctets;
}

/// Writes the version 1 manifest of one format.
pub fn render_manifest(format: Format, output: *Writer) core.writer.Error!void {
    const format_cases = cases_of(format);
    try output.print("colibri-golden-manifest version={d} format={t} cases={d}\n", .{
        constants.manifest_version,
        format,
        format_cases.len,
    });
    for (format_cases) |*case| {
        var buffer: [constants.case_len_max]u8 = @splat(0);
        var octets = Writer.init(&buffer);
        try build(format, case, &octets);
        try output.print("{s} len={d} crc32=0x{x:0>8} verdict=", .{
            case.name,
            octets.offset,
            std.hash.Crc32.hash(octets.written()),
        });
        const verdict = if (case.rejection) |rejection| @errorName(rejection) else "accept";
        try output.print("{s}", .{verdict});
        try render_parameters(format, case, output);
        try output.write_byte('\n');
    }
}

fn render_parameters(format: Format, case: *const Case, output: *Writer) core.writer.Error!void {
    if (format == .prefixed_integer or format == .string_literal) {
        try output.print(" prefix_size={d}", .{case.prefix_size});
    }
    try output.print(" construction={t}", .{case.construction});
    switch (case.construction) {
        .literal => {},
        .varint => |varint| try output.print(" value={d} encoded_len={d}", .{
            varint.value,
            varint.encoded_len,
        }),
        .prefixed_integer => |integer| try output.print(" high_bits=0x{x:0>2} value={d}", .{
            integer.high_bits,
            integer.value,
        }),
        .huffman => |text| try output.print(" text={x}", .{text}),
        .string_literal => |literal| try output.print(" high_bits=0x{x:0>2} coding={t} text={x}", .{
            literal.high_bits,
            literal.coding,
            literal.text,
        }),
        .truncated => |truncated| try output.print(" of={s} drop={d}", .{
            truncated.case_name,
            truncated.drop,
        }),
    }
}

const testing = std.testing;

test "every case's verdict is what its decoder returns" {
    for (cases.all) |entry| {
        for (entry.cases) |*case| {
            var buffer: [constants.case_len_max]u8 = @splat(0);
            var octets = Writer.init(&buffer);
            try build(entry.format, case, &octets);
            const result = decode(entry.format, case.prefix_size, octets.written());
            if (case.rejection) |rejection| {
                try testing.expectError(rejection, result);
            } else {
                try result;
            }
        }
    }
}

test "every format holds valid and invalid cases, and names are unique" {
    for (cases.all) |entry| {
        var accepted: usize = 0;
        for (entry.cases, 0..) |case, index| {
            if (case.rejection == null) accepted += 1;
            for (entry.cases[index + 1 ..]) |other| {
                try testing.expect(!std.mem.eql(u8, case.name, other.name));
            }
        }
        try testing.expect(accepted > 0 and accepted < entry.cases.len);
    }
}

test "the manifest names its version and one line per case" {
    var buffer: [constants.manifest_len_max]u8 = @splat(0);
    var output = Writer.init(&buffer);
    try render_manifest(.huffman, &output);
    var lines = std.mem.splitScalar(u8, output.written(), '\n');
    const header = "colibri-golden-manifest version=1 format=huffman cases=7";
    try testing.expectEqualStrings(header, lines.first());
    var line_buffer: [256]u8 = @splat(0);
    const expected = try std.fmt.bufPrint(
        &line_buffer,
        "huffman_octets_204_22 len=8 crc32=0x{x:0>8} verdict=accept construction=huffman text=cc16",
        .{std.hash.Crc32.hash(&.{ 0xff, 0xff, 0xfb, 0xff, 0xff, 0xff, 0xff, 0x7f })},
    );
    var line_count: usize = 0;
    var found = false;
    for (0..constants.cases_per_format_max + 1) |_| {
        const line = lines.next() orelse break;
        if (line.len == 0) continue;
        line_count += 1;
        if (std.mem.eql(u8, line, expected)) found = true;
    }
    try testing.expect(found);
    try testing.expectEqual(cases.huffman.len, line_count);
}
