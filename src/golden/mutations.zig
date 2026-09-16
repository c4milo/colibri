//! The corpus mutations (CLAUDE.md, "Tests are proved by mutation"). Each one edits the committed
//! octets of one corpus case and names the verdict the edited octets must produce. A mutation is a
//! rule written down as a counterexample: if a decoder change stops the edit producing its verdict,
//! `golden.zig` fails and names the rule that broke.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("constants.zig");
const cases = @import("corpus_cases.zig");

const Writer = core.Writer;
const Format = cases.Format;

pub const Edit = union(enum) {
    /// Replace the octet at `offset` with `value`.
    set: struct { offset: u8, value: u8 },
    /// Remove the last `count` octets.
    truncate: u8,
    /// Append these octets.
    append: []const u8,
};

pub const Mutation = struct {
    format: Format,
    case_name: []const u8,
    /// The rule the mutation guards, in words.
    rule: []const u8,
    edit: Edit,
    /// Null when the edited octets must still decode; otherwise the error they must produce.
    rejection: ?anyerror,
};

pub const all = [_]Mutation{
    .{
        .format = .varint,
        .case_name = "varint_1_octet_37",
        .rule = "RFC 9000 §16: the two high bits of the first octet give the length; 01 is two octets",
        .edit = .{ .set = .{ .offset = 0, .value = 0x65 } },
        .rejection = error.Truncated,
    },
    .{
        .format = .varint,
        .case_name = "varint_2_octets_37",
        .rule = "RFC 9000 §16: 00 in the high bits is a one-octet integer, so one octet is left",
        .edit = .{ .set = .{ .offset = 0, .value = 0x00 } },
        .rejection = error.TrailingOctets,
    },
    .{
        .format = .varint,
        .case_name = "varint_8_octets_max",
        .rule = "invariant 9: an eight-octet integer with seven octets present is truncated",
        .edit = .{ .truncate = 1 },
        .rejection = error.Truncated,
    },
    .{
        .format = .prefixed_integer,
        .case_name = "prefixed_integer_5_bit_10",
        .rule = "RFC 7541 §5.1: a prefix of all ones means continuation octets follow",
        .edit = .{ .set = .{ .offset = 0, .value = 0x1f } },
        .rejection = error.Truncated,
    },
    .{
        .format = .prefixed_integer,
        .case_name = "prefixed_integer_5_bit_1337",
        .rule = "RFC 7541 §5.1: the continuation flag set on the last octet promises another",
        .edit = .{ .set = .{ .offset = 2, .value = 0x8a } },
        .rejection = error.Truncated,
    },
    .{
        .format = .prefixed_integer,
        .case_name = "prefixed_integer_1_bit_max",
        .rule = "RFC 9204 §4.1.1, RFC 7541 §5.1: one bit past 62 is over colibri's limit",
        .edit = .{ .set = .{ .offset = 9, .value = 0x40 } },
        .rejection = error.IntegerTooLarge,
    },
    .{
        .format = .prefixed_integer,
        .case_name = "prefixed_integer_5_bit_too_long",
        .rule = "RFC 7541 §5.1: the octet limit fires on the tenth octet, before input runs out",
        .edit = .{ .truncate = 1 },
        .rejection = error.IntegerTooLong,
    },
    .{
        .format = .huffman,
        .case_name = "huffman_www_example_com",
        .rule = "RFC 7541 §5.2: padding must be the high bits of EOS, so a zero in it is refused",
        .edit = .{ .set = .{ .offset = 11, .value = 0xfe } },
        .rejection = error.HuffmanPaddingNotEos,
    },
    .{
        .format = .huffman,
        .case_name = "huffman_octets_204_22",
        .rule = "RFC 7541 §5.2: eight more ones after the padding make padding longer than 7 bits",
        .edit = .{ .append = &.{0xff} },
        .rejection = error.HuffmanPaddingTooLong,
    },
    .{
        .format = .huffman,
        .case_name = "huffman_empty",
        .rule = "RFC 7541 §5.2: an octet of ones with no symbol before it is padding over 7 bits",
        .edit = .{ .append = &.{0xff} },
        .rejection = error.HuffmanPaddingTooLong,
    },
    .{
        .format = .huffman,
        .case_name = "huffman_eos_in_data",
        .rule = "invariant 12: EOS completes at its thirtieth bit, whatever follows it",
        .edit = .{ .set = .{ .offset = 3, .value = 0xfc } },
        .rejection = error.HuffmanEosInData,
    },
    .{
        .format = .string_literal,
        .case_name = "string_literal_raw_custom_key",
        .rule = "invariant 9: a length one past the data present is truncated",
        .edit = .{ .set = .{ .offset = 0, .value = 0x0b } },
        .rejection = error.Truncated,
    },
    .{
        .format = .string_literal,
        .case_name = "string_literal_raw_custom_key",
        .rule = "RFC 7541 §5.2: the length counts every octet of data, so one short leaves one",
        .edit = .{ .set = .{ .offset = 0, .value = 0x09 } },
        .rejection = error.TrailingOctets,
    },
    .{
        .format = .string_literal,
        .case_name = "string_literal_huffman_www_example_com",
        .rule = "RFC 7541 §5.2: the H flag alone selects Huffman, so clearing it reads data raw",
        .edit = .{ .set = .{ .offset = 0, .value = 0x0c } },
        .rejection = null,
    },
    .{
        .format = .string_literal,
        .case_name = "string_literal_4_bit_huffman_no_cache",
        .rule = "RFC 9204 §4.1.2: the bits above the N-bit prefix belong to the previous field",
        .edit = .{ .set = .{ .offset = 0, .value = 0xde } },
        .rejection = null,
    },
};

comptime {
    assert(all.len <= constants.mutations_max);
}

/// Writes `octets` with `mutation`'s edit applied.
pub fn apply(
    mutation: *const Mutation,
    octets: []const u8,
    output: *Writer,
) core.writer.Error!void {
    switch (mutation.edit) {
        .set => |set| {
            assert(set.offset < octets.len);
            assert(octets[set.offset] != set.value);
            try output.write_bytes(octets[0..set.offset]);
            try output.write_byte(set.value);
            try output.write_bytes(octets[set.offset + 1 ..]);
        },
        .truncate => |count| {
            assert(count > 0 and count <= octets.len);
            try output.write_bytes(octets[0 .. octets.len - count]);
        },
        .append => |extra| {
            assert(extra.len > 0);
            try output.write_bytes(octets);
            try output.write_bytes(extra);
        },
    }
}
