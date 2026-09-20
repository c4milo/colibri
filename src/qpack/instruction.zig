//! The encoder and decoder instruction streams of RFC 9204 §4.3 and §4.4. Part of design §8
//! step 11.
//!
//! This is the difference between QPACK and HPACK, in one file. RFC 9204 §2.2 names it: in HPACK
//! the encoded field section carries the instructions that mutate the dynamic table, so a
//! decoder reading a section always knows the table state it was encoded against. In QPACK the
//! sections travel on request streams and the table mutations on a stream of their own, which
//! QUIC may deliver in either order — and that one difference is why QPACK needs a Known
//! Received Count, a Required Insert Count, a Base and blocked-stream accounting, none of which
//! HPACK has ([decision 12](../../docs/decisions.md)).
//!
//! Four instructions run encoder to decoder (§4.3) and three run decoder to encoder (§4.4).
//! Both sets are told apart by the high bits of the first octet, exactly as §4.5's field line
//! representations are, and both reuse §4.1.1's prefixed integer and §4.1.2's string literal.
//!
//! Reading one consumes all of its octets or none, so a caller feeding a stream that has not
//! finished arriving can ask again with more.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const constants = @import("constants.zig");
const representation = @import("representation.zig");

const Reader = core.Reader;
const Writer = core.Writer;
const Coding = representation.Coding;
const Table = representation.Table;
const prefixed_integer = wire.prefixed_integer;
const string_literal = wire.string_literal;

pub const Error = string_literal.DecodeError;

/// One instruction the encoder sends the decoder (RFC 9204 §4.3).
pub const Encoder = union(enum) {
    /// §4.3.1: the capacity the encoder will use, at or below what the decoder advertised.
    set_capacity: u64,
    /// §4.3.2: insert an entry whose name is an existing one's.
    insert_name_reference: InsertNameReference,
    /// §4.3.3: insert an entry whose name and value are both literals.
    insert_literal: InsertLiteral,
    /// §4.3.4: insert a copy of an existing entry, named by its relative index. §2.1.1 uses it
    /// to keep an entry that is about to be evicted usable.
    duplicate: u64,

    pub const InsertNameReference = struct {
        table: Table,
        /// A static index, or a relative index into the dynamic table counted from the newest
        /// entry (§3.2.5's encoder-stream origin).
        name_index: u64,
        value: []const u8,
        value_coding: Coding,
    };

    pub const InsertLiteral = struct {
        name: []const u8,
        name_coding: Coding,
        value: []const u8,
        value_coding: Coding,
    };
};

/// One instruction the decoder sends the encoder (RFC 9204 §4.4).
pub const Decoder = union(enum) {
    /// §4.4.1: a field section on this stream has been decoded, so the entries it referenced
    /// have been received and may now be evicted.
    section_acknowledgment: u64,
    /// §4.4.2: this stream was reset or abandoned before its section was decoded, so the
    /// encoder can stop counting it against the blocked-stream limit.
    stream_cancellation: u64,
    /// §4.4.3: this many more entries have been received than the encoder last knew of, which
    /// is what moves §2.1.4's Known Received Count when no section acknowledged them.
    insert_count_increment: u64,
};

/// Reads one encoder instruction (RFC 9204 §4.3).
pub fn read_encoder(reader: *Reader, strings: *Writer) Error!Encoder {
    var cursor = reader.*;
    const first = try cursor.peek_byte();
    const found = try read_encoder_at(first, &cursor, strings);
    reader.* = cursor;
    return found;
}

fn read_encoder_at(first: u8, cursor: *Reader, strings: *Writer) Error!Encoder {
    if (first & constants.insert_name_reference_mask == constants.insert_name_reference_pattern) {
        return .{ .insert_name_reference = try read_insert_name_reference(first, cursor, strings) };
    }
    if (first & constants.insert_literal_mask == constants.insert_literal_pattern) {
        return .{ .insert_literal = try read_insert_literal(cursor, strings) };
    }
    if (first & constants.set_capacity_mask == constants.set_capacity_pattern) {
        return .{ .set_capacity = try prefixed_integer.decode(constants.set_capacity_prefix_bits, cursor) };
    }
    assert(first & constants.duplicate_mask == constants.duplicate_pattern);
    return .{ .duplicate = try prefixed_integer.decode(constants.duplicate_prefix_bits, cursor) };
}

/// RFC 9204 §4.3.2.
fn read_insert_name_reference(first: u8, cursor: *Reader, strings: *Writer) Error!Encoder.InsertNameReference {
    const table: Table = if (first & constants.insert_name_reference_static_flag != 0) .static else .dynamic;
    const name_index = try prefixed_integer.decode(constants.insert_name_reference_prefix_bits, cursor);
    const value = try read_string(cursor, strings, constants.value_prefix_bits);
    return .{
        .table = table,
        .name_index = name_index,
        .value = value.bytes,
        .value_coding = value.coding,
    };
}

/// RFC 9204 §4.3.3.
fn read_insert_literal(cursor: *Reader, strings: *Writer) Error!Encoder.InsertLiteral {
    const name = try read_string(cursor, strings, constants.insert_literal_name_prefix_bits);
    const value = try read_string(cursor, strings, constants.value_prefix_bits);
    return .{
        .name = name.bytes,
        .name_coding = name.coding,
        .value = value.bytes,
        .value_coding = value.coding,
    };
}

/// Reads one decoder instruction (RFC 9204 §4.4).
pub fn read_decoder(reader: *Reader) Error!Decoder {
    var cursor = reader.*;
    const first = try cursor.peek_byte();
    const found: Decoder = if (first & constants.section_acknowledgment_mask == constants.section_acknowledgment_pattern)
        .{ .section_acknowledgment = try prefixed_integer.decode(constants.section_acknowledgment_prefix_bits, &cursor) }
    else if (first & constants.stream_cancellation_mask == constants.stream_cancellation_pattern)
        .{ .stream_cancellation = try prefixed_integer.decode(constants.stream_cancellation_prefix_bits, &cursor) }
    else
        .{ .insert_count_increment = try prefixed_integer.decode(constants.insert_count_increment_prefix_bits, &cursor) };
    reader.* = cursor;
    return found;
}

/// Writes one encoder instruction. All of the octets are written, or none.
pub fn write_encoder(writer: *Writer, held: Encoder) core.writer.Error!void {
    var cursor = writer.*;
    switch (held) {
        .set_capacity => |capacity| try prefixed_integer.encode(
            constants.set_capacity_prefix_bits,
            &cursor,
            constants.set_capacity_pattern,
            capacity,
        ),
        .duplicate => |index| try prefixed_integer.encode(
            constants.duplicate_prefix_bits,
            &cursor,
            constants.duplicate_pattern,
            index,
        ),
        .insert_name_reference => |line| try write_insert_name_reference(&cursor, line),
        .insert_literal => |line| try write_insert_literal(&cursor, line),
    }
    writer.* = cursor;
}

fn write_insert_name_reference(cursor: *Writer, line: Encoder.InsertNameReference) core.writer.Error!void {
    var high = constants.insert_name_reference_pattern;
    if (line.table == .static) high |= constants.insert_name_reference_static_flag;
    try prefixed_integer.encode(constants.insert_name_reference_prefix_bits, cursor, high, line.name_index);
    try string_literal.encode(constants.value_prefix_bits, cursor, 0, line.value, line.value_coding);
}

fn write_insert_literal(cursor: *Writer, line: Encoder.InsertLiteral) core.writer.Error!void {
    try string_literal.encode(
        constants.insert_literal_name_prefix_bits,
        cursor,
        constants.insert_literal_pattern,
        line.name,
        line.name_coding,
    );
    try string_literal.encode(constants.value_prefix_bits, cursor, 0, line.value, line.value_coding);
}

/// Writes one decoder instruction. All of the octets are written, or none.
pub fn write_decoder(writer: *Writer, held: Decoder) core.writer.Error!void {
    switch (held) {
        .section_acknowledgment => |id| try prefixed_integer.encode(
            constants.section_acknowledgment_prefix_bits,
            writer,
            constants.section_acknowledgment_pattern,
            id,
        ),
        .stream_cancellation => |id| try prefixed_integer.encode(
            constants.stream_cancellation_prefix_bits,
            writer,
            constants.stream_cancellation_pattern,
            id,
        ),
        .insert_count_increment => |increment| try prefixed_integer.encode(
            constants.insert_count_increment_prefix_bits,
            writer,
            constants.insert_count_increment_pattern,
            increment,
        ),
    }
}

const String = struct {
    bytes: []const u8,
    coding: Coding,
};

/// Decodes one string literal into `strings` and returns what it wrote (RFC 9204 §4.1.2).
fn read_string(cursor: *Reader, strings: *Writer, comptime prefix_bits: u4) Error!String {
    const from = strings.written().len;
    const decoded = try string_literal.decode(prefix_bits, cursor, strings);
    return .{ .bytes = strings.written()[from..], .coding = decoded.coding };
}

const testing = std.testing;

/// Room for what a test writes and for the strings it decodes. Test-only.
const test_room: usize = 256;
var test_octets: [test_room]u8 = undefined;
var test_strings: [test_room]u8 = undefined;

/// Writes an encoder instruction and reads it back. Test-only.
fn round_trip_encoder(held: Encoder) !Encoder {
    var writer = Writer.init(&test_octets);
    try write_encoder(&writer, held);
    var reader = Reader.init(writer.written());
    var strings = Writer.init(&test_strings);
    const back = try read_encoder(&reader, &strings);
    try testing.expectEqual(0, reader.remaining_len());
    return back;
}

/// The same for a decoder instruction. Test-only.
fn round_trip_decoder(held: Decoder) !Decoder {
    var writer = Writer.init(&test_octets);
    try write_decoder(&writer, held);
    var reader = Reader.init(writer.written());
    const back = try read_decoder(&reader);
    try testing.expectEqual(0, reader.remaining_len());
    return back;
}

/// Reads one encoder instruction from octets. Test-only.
fn read_one(octets: []const u8) Error!Encoder {
    var reader = Reader.init(octets);
    var strings = Writer.init(&test_strings);
    return read_encoder(&reader, &strings);
}

test "§4.3.1: Set Dynamic Table Capacity is 001 and a 5-bit capacity" {
    // The 5-bit prefix carries 0 to 30 directly: 0x20 is a capacity of zero, which §3.2.2 names
    // as the way to empty the table.
    try testing.expectEqualSlices(u8, &.{0x20}, blk: {
        var writer = Writer.init(&test_octets);
        try write_encoder(&writer, .{ .set_capacity = 0 });
        break :blk writer.written();
    });
    try testing.expectEqual(0, (try read_one(&.{0x20})).set_capacity);
    try testing.expectEqual(30, (try read_one(&.{0x3e})).set_capacity);
    // At the prefix maximum it continues into the octets that follow.
    try testing.expectEqual(0x1000, (try round_trip_encoder(.{ .set_capacity = 0x1000 })).set_capacity);
}

test "§4.3.4: Duplicate is 000 and a relative index" {
    try testing.expectEqual(0, (try read_one(&.{0x00})).duplicate);
    try testing.expectEqual(7, (try round_trip_encoder(.{ .duplicate = 7 })).duplicate);
    // §3.2.5: on the encoder stream a relative index of 0 is the most recently inserted entry,
    // which is what §2.1.1 duplicates to keep it usable past an eviction.
    try testing.expectEqual(0x200, (try round_trip_encoder(.{ .duplicate = 0x200 })).duplicate);
}

test "§4.3.2: Insert with Name Reference names a table and an index" {
    // `1T` with T set: the static table, index 1, value `/x`.
    const octets = [_]u8{ 0xc1, 0x02, '/', 'x' };
    const found = (try read_one(&octets)).insert_name_reference;
    try testing.expectEqual(Table.static, found.table);
    try testing.expectEqual(1, found.name_index);
    try testing.expectEqualStrings("/x", found.value);
    var writer = Writer.init(&test_octets);
    try write_encoder(&writer, .{ .insert_name_reference = found });
    try testing.expectEqualSlices(u8, &octets, writer.written());
    // With T clear it is a relative index into the dynamic table.
    const dynamic = (try read_one(&.{ 0x81, 0x01, 'v' })).insert_name_reference;
    try testing.expectEqual(Table.dynamic, dynamic.table);
    try testing.expectEqual(1, dynamic.name_index);
    // A Huffman coded value comes back whole and shorter than it went in raw.
    const coded = try round_trip_encoder(.{ .insert_name_reference = .{
        .table = .static,
        .name_index = 1,
        .value = "/index.html",
        .value_coding = .huffman,
    } });
    try testing.expectEqualStrings("/index.html", coded.insert_name_reference.value);
    try testing.expectEqual(Coding.huffman, coded.insert_name_reference.value_coding);
}

test "§4.3.3: Insert with Literal Name carries both as string literals" {
    // `01` with the name as a 6-bit prefix literal and the value as an 8-bit one.
    const octets = [_]u8{ 0x43, 'a', 'b', 'c', 0x01, 'd' };
    const found = (try read_one(&octets)).insert_literal;
    try testing.expectEqualStrings("abc", found.name);
    try testing.expectEqualStrings("d", found.value);
    var writer = Writer.init(&test_octets);
    try write_encoder(&writer, .{ .insert_literal = found });
    try testing.expectEqualSlices(u8, &octets, writer.written());
    // Both halves survive Huffman coding, and each keeps its own choice.
    const mixed = try round_trip_encoder(.{ .insert_literal = .{
        .name = "custom-key",
        .name_coding = .huffman,
        .value = "custom-value",
        .value_coding = .raw,
    } });
    try testing.expectEqualStrings("custom-key", mixed.insert_literal.name);
    try testing.expectEqualStrings("custom-value", mixed.insert_literal.value);
    try testing.expectEqual(Coding.huffman, mixed.insert_literal.name_coding);
    try testing.expectEqual(Coding.raw, mixed.insert_literal.value_coding);
}

test "§4.3: the four encoder instructions are told apart by their high bits" {
    // The patterns do not overlap: 1xxxxxxx, 01xxxxxx, 001xxxxx and 000xxxxx cover every octet
    // exactly once, so no instruction can be read as another.
    for (0..256) |value| {
        const first: u8 = @intCast(value);
        var matches: usize = 0;
        if (first & constants.insert_name_reference_mask == constants.insert_name_reference_pattern) matches += 1;
        if (first & constants.insert_literal_mask == constants.insert_literal_pattern) matches += 1;
        if (first & constants.set_capacity_mask == constants.set_capacity_pattern) matches += 1;
        if (first & constants.duplicate_mask == constants.duplicate_pattern) matches += 1;
        try testing.expectEqual(1, matches);
    }
}

test "§4.4: the three decoder instructions round trip and do not overlap" {
    // §4.4.1: `1` and a 7-bit stream identifier.
    try testing.expectEqual(5, (try round_trip_decoder(.{ .section_acknowledgment = 5 })).section_acknowledgment);
    var reader = Reader.init(&.{0x85});
    try testing.expectEqual(5, (try read_decoder(&reader)).section_acknowledgment);
    // §4.4.2: `01` and a 6-bit stream identifier.
    try testing.expectEqual(5, (try round_trip_decoder(.{ .stream_cancellation = 5 })).stream_cancellation);
    var cancelled = Reader.init(&.{0x45});
    try testing.expectEqual(5, (try read_decoder(&cancelled)).stream_cancellation);
    // §4.4.3: `00` and a 6-bit increment.
    try testing.expectEqual(5, (try round_trip_decoder(.{ .insert_count_increment = 5 })).insert_count_increment);
    var incremented = Reader.init(&.{0x05});
    try testing.expectEqual(5, (try read_decoder(&incremented)).insert_count_increment);
    // Every octet reads as exactly one of the three.
    for (0..256) |value| {
        const first: u8 = @intCast(value);
        var matches: usize = 0;
        if (first & constants.section_acknowledgment_mask == constants.section_acknowledgment_pattern) matches += 1;
        if (first & constants.stream_cancellation_mask == constants.stream_cancellation_pattern) matches += 1;
        if (first & constants.insert_count_increment_mask == constants.insert_count_increment_pattern) matches += 1;
        try testing.expectEqual(1, matches);
    }
    // A large identifier continues past the prefix and still comes back.
    try testing.expectEqual(0x4000, (try round_trip_decoder(.{ .section_acknowledgment = 0x4000 })).section_acknowledgment);
}

test "an instruction cut short consumes nothing" {
    // A value literal whose octets have not all arrived, after a name index that has.
    var reader = Reader.init(&.{ 0xc1, 0x05, 'a' });
    var strings = Writer.init(&test_strings);
    try testing.expectError(error.Truncated, read_encoder(&reader, &strings));
    try testing.expectEqual(3, reader.remaining_len());
    // A capacity whose continuation octets are missing.
    var capacity = Reader.init(&.{0x3f});
    try testing.expectError(error.Truncated, read_encoder(&capacity, &strings));
    try testing.expectEqual(1, capacity.remaining_len());
    // The same on the decoder stream.
    var decoder = Reader.init(&.{0xff});
    try testing.expectError(error.Truncated, read_decoder(&decoder));
    try testing.expectEqual(1, decoder.remaining_len());
}

test "an instruction that does not fit writes nothing" {
    var room: [2]u8 = undefined;
    var tight = Writer.init(room[0..1]);
    try testing.expectError(error.NoSpaceLeft, write_encoder(&tight, .{ .insert_literal = .{
        .name = "a",
        .name_coding = .raw,
        .value = "b",
        .value_coding = .raw,
    } }));
    try testing.expectEqual(0, tight.written().len);
}
