//! Writing the field line representations of RFC 9204 §4.5. Part of design §8 step 11.
//!
//! The reader and the types are `representation.zig`; this is the other direction, split out
//! because a hand-written source file stays at or under 500 lines (CLAUDE.md). What it does not
//! do is choose: which of the five shapes a field line takes, and whether a string is Huffman
//! coded, are the encoder's decisions and arrive here already made.
//!
//! Every function writes all of its octets or none, so a writer that runs out of room leaves
//! nothing half-written behind it.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const constants = @import("constants.zig");
const representation = @import("representation.zig");

const Writer = core.Writer;
const Error = core.writer.Error;
const Representation = representation.Representation;
const Table = representation.Table;
const prefixed_integer = wire.prefixed_integer;
const string_literal = wire.string_literal;

/// Writes one field line representation (RFC 9204 §4.5).
pub fn write(writer: *Writer, held: Representation) Error!void {
    var cursor = writer.*;
    switch (held) {
        .indexed => |line| try write_indexed(&cursor, line),
        .indexed_post_base => |line| try prefixed_integer.encode(
            constants.indexed_post_base_prefix_bits,
            &cursor,
            constants.indexed_post_base_pattern,
            line.index,
        ),
        .literal_name_reference => |line| try write_literal_name_reference(&cursor, line),
        .literal_post_base_name_reference => |line| try write_literal_post_base(&cursor, line),
        .literal => |line| try write_literal(&cursor, line),
    }
    writer.* = cursor;
}

/// RFC 9204 §4.5.2: `1T` and the index.
fn write_indexed(cursor: *Writer, line: Representation.Indexed) Error!void {
    const high = constants.indexed_pattern | static_flag(line.table, constants.indexed_static_flag);
    try prefixed_integer.encode(constants.indexed_prefix_bits, cursor, high, line.index);
}

/// RFC 9204 §4.5.4: `01NT`, the name index, then the value as an 8-bit prefix string literal.
fn write_literal_name_reference(cursor: *Writer, line: Representation.LiteralNameReference) Error!void {
    var high = constants.literal_name_reference_pattern;
    if (line.never_indexed) high |= constants.literal_name_reference_never_flag;
    high |= static_flag(line.table, constants.literal_name_reference_static_flag);
    try prefixed_integer.encode(constants.literal_name_reference_prefix_bits, cursor, high, line.name_index);
    try string_literal.encode(constants.value_prefix_bits, cursor, 0, line.value, line.value_coding);
}

/// RFC 9204 §4.5.5: `0000N`, the post-Base name index, then the value.
fn write_literal_post_base(cursor: *Writer, line: Representation.LiteralPostBaseNameReference) Error!void {
    var high = constants.literal_post_base_pattern;
    if (line.never_indexed) high |= constants.literal_post_base_never_flag;
    try prefixed_integer.encode(constants.literal_post_base_prefix_bits, cursor, high, line.name_index);
    try string_literal.encode(constants.value_prefix_bits, cursor, 0, line.value, line.value_coding);
}

/// RFC 9204 §4.5.6: `001N`, the name as a 4-bit prefix string literal, then the value as an
/// 8-bit one.
fn write_literal(cursor: *Writer, line: Representation.Literal) Error!void {
    var high = constants.literal_pattern;
    if (line.never_indexed) high |= constants.literal_never_flag;
    try string_literal.encode(constants.literal_name_prefix_bits, cursor, high, line.name, line.name_coding);
    try string_literal.encode(constants.value_prefix_bits, cursor, 0, line.value, line.value_coding);
}

/// RFC 9204 §4.5.2's `T` bit, which is set for the static table.
fn static_flag(table: Table, flag: u8) u8 {
    return switch (table) {
        .static => flag,
        .dynamic => 0,
    };
}
