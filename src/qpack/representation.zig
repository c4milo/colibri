//! The field line representations of RFC 9204 §4.5, and the field section prefix of §4.5.1.
//! Part of design §8 step 11.
//!
//! Five shapes, told apart by the high bits of the first octet: an index into a table, an index
//! past the Base, a literal value with the name taken from a table, the same with the name taken
//! from past the Base, and a literal name with a literal value. §4.5 draws all five; this reads
//! and writes them, and nothing more. What an index means is §3.2's, and which representation an
//! encoder chooses is the encoder's.
//!
//! **A name or value the reader decoded is written into a buffer the caller owns**, and the
//! representation carries slices of it (decision 35: colibri allocates nothing). The slices stay
//! good as long as that buffer does and nothing else is written into it.
//!
//! The primitives are shared with HPACK: §4.1.1's prefixed integer and §4.1.2's string literal
//! are RFC 7541 §5.1 and §5.2 with a wider value, and `wire` holds one copy of each.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const constants = @import("constants.zig");

const Reader = core.Reader;
const Writer = core.Writer;
const prefixed_integer = wire.prefixed_integer;
const string_literal = wire.string_literal;

pub const Error = string_literal.DecodeError || error{
    /// RFC 9204 §4.5.1.2: a field section prefix whose Sign bit is set and whose Delta Base is at
    /// or above the Required Insert Count would make the Base negative, which §4.5.1.2 forbids.
    BaseNegative,
};

/// Which table an index refers to (RFC 9204 §4.5.2's `T` bit).
pub const Table = enum { static, dynamic };

/// How a string was coded on the wire (RFC 9204 §4.1.2), kept so a reader can report what it saw
/// and a round trip can reproduce it.
pub const Coding = string_literal.Coding;

/// One field line as RFC 9204 §4.5 represents it.
pub const Representation = union(enum) {
    /// §4.5.2: the whole field line is one table entry.
    indexed: Indexed,
    /// §4.5.3: the same, for a dynamic entry at or above the Base.
    indexed_post_base: IndexedPostBase,
    /// §4.5.4: the name is a table entry and the value is a literal.
    literal_name_reference: LiteralNameReference,
    /// §4.5.5: the same, for a dynamic entry at or above the Base.
    literal_post_base_name_reference: LiteralPostBaseNameReference,
    /// §4.5.6: both the name and the value are literals.
    literal: Literal,

    pub const Indexed = struct {
        table: Table,
        /// A static table index when `table` is static, a relative index when it is dynamic.
        index: u64,
    };

    pub const IndexedPostBase = struct {
        /// RFC 9204 §3.2.6: counted forward from the Base rather than back from it.
        index: u64,
    };

    pub const LiteralNameReference = struct {
        /// RFC 9204 §4.5.4's `N` bit: an intermediary MUST forward this field line as a literal
        /// and MUST NOT put it in a dynamic table, which is §7.1.3's protection for a value that
        /// must not be at risk from compression.
        never_indexed: bool,
        table: Table,
        name_index: u64,
        value: []const u8,
        value_coding: Coding,
    };

    pub const LiteralPostBaseNameReference = struct {
        never_indexed: bool,
        name_index: u64,
        value: []const u8,
        value_coding: Coding,
    };

    pub const Literal = struct {
        never_indexed: bool,
        name: []const u8,
        name_coding: Coding,
        value: []const u8,
        value_coding: Coding,
    };
};

/// The field section prefix of RFC 9204 §4.5.1, as it sits on the wire. The Required Insert Count
/// here is the encoded one of §4.5.1.1, not the count itself: turning one into the other needs
/// the dynamic table's capacity and how many inserts the decoder has seen, which this layer does
/// not hold.
pub const Prefix = struct {
    encoded_insert_count: u64,
    /// §4.5.1.2: set when the Base is below the Required Insert Count.
    sign: bool,
    delta_base: u64,

    /// The prefix a field section that references no dynamic entry carries. §4.5.1.2: such a
    /// section may use any Base, and a Delta Base of zero is one of the shortest.
    pub const static_only: Prefix = .{ .encoded_insert_count = 0, .sign = false, .delta_base = 0 };

    /// RFC 9204 §4.5.1.2: the Base, given the Required Insert Count this prefix belongs to.
    pub fn base(prefix: Prefix, required_insert_count: u64) Error!u64 {
        if (!prefix.sign) return required_insert_count +| prefix.delta_base;
        // §4.5.1.2: an endpoint MUST treat a field block with a Sign bit of 1 as invalid if the
        // Required Insert Count is at or below the Delta Base, because the Base MUST NOT be
        // negative.
        if (required_insert_count <= prefix.delta_base) return Error.BaseNegative;
        return required_insert_count - prefix.delta_base - 1;
    }
};

/// Reads the field section prefix (RFC 9204 §4.5.1).
pub fn read_prefix(reader: *Reader) Error!Prefix {
    var cursor = reader.*;
    const encoded_insert_count = try prefixed_integer.decode(constants.required_insert_count_prefix_bits, &cursor);
    // §4.5.1: the Sign bit is the high bit of the octet the Delta Base starts in.
    const sign = (try cursor.peek_byte()) & constants.delta_base_sign_flag != 0;
    const delta_base = try prefixed_integer.decode(constants.delta_base_prefix_bits, &cursor);
    reader.* = cursor;
    return .{ .encoded_insert_count = encoded_insert_count, .sign = sign, .delta_base = delta_base };
}

/// Writes the field section prefix. All of the octets are written, or none.
pub fn write_prefix(writer: *Writer, prefix: Prefix) core.writer.Error!void {
    var cursor = writer.*;
    try prefixed_integer.encode(constants.required_insert_count_prefix_bits, &cursor, 0, prefix.encoded_insert_count);
    const sign_bits: u8 = if (prefix.sign) constants.delta_base_sign_flag else 0;
    try prefixed_integer.encode(constants.delta_base_prefix_bits, &cursor, sign_bits, prefix.delta_base);
    writer.* = cursor;
}

/// Reads one field line representation (RFC 9204 §4.5), writing any literal name or value into
/// `strings` and pointing at what it wrote. All of the octets are consumed, or none.
pub fn read(reader: *Reader, strings: *Writer) Error!Representation {
    var cursor = reader.*;
    const first = try cursor.peek_byte();
    const found = try read_by_pattern(first, &cursor, strings);
    reader.* = cursor;
    return found;
}

/// Picks the representation from the high bits of the first octet (RFC 9204 §4.5).
fn read_by_pattern(first: u8, cursor: *Reader, strings: *Writer) Error!Representation {
    if (first & constants.indexed_pattern_mask == constants.indexed_pattern) {
        return .{ .indexed = try read_indexed(first, cursor) };
    }
    if (first & constants.literal_name_reference_mask == constants.literal_name_reference_pattern) {
        return .{ .literal_name_reference = try read_literal_name_reference(first, cursor, strings) };
    }
    if (first & constants.literal_mask == constants.literal_pattern) {
        return .{ .literal = try read_literal(first, cursor, strings) };
    }
    if (first & constants.indexed_post_base_mask == constants.indexed_post_base_pattern) {
        const index = try prefixed_integer.decode(constants.indexed_post_base_prefix_bits, cursor);
        return .{ .indexed_post_base = .{ .index = index } };
    }
    assert(first & constants.literal_post_base_mask == constants.literal_post_base_pattern);
    return .{ .literal_post_base_name_reference = try read_literal_post_base(first, cursor, strings) };
}

/// RFC 9204 §4.5.2.
fn read_indexed(first: u8, cursor: *Reader) Error!Representation.Indexed {
    const table = table_of(first, constants.indexed_static_flag);
    const index = try prefixed_integer.decode(constants.indexed_prefix_bits, cursor);
    return .{ .table = table, .index = index };
}

/// RFC 9204 §4.5.4.
fn read_literal_name_reference(first: u8, cursor: *Reader, strings: *Writer) Error!Representation.LiteralNameReference {
    const never_indexed = first & constants.literal_name_reference_never_flag != 0;
    const table = table_of(first, constants.literal_name_reference_static_flag);
    const name_index = try prefixed_integer.decode(constants.literal_name_reference_prefix_bits, cursor);
    const value = try read_string(cursor, strings, constants.value_prefix_bits);
    return .{
        .never_indexed = never_indexed,
        .table = table,
        .name_index = name_index,
        .value = value.bytes,
        .value_coding = value.coding,
    };
}

/// RFC 9204 §4.5.5.
fn read_literal_post_base(first: u8, cursor: *Reader, strings: *Writer) Error!Representation.LiteralPostBaseNameReference {
    const never_indexed = first & constants.literal_post_base_never_flag != 0;
    const name_index = try prefixed_integer.decode(constants.literal_post_base_prefix_bits, cursor);
    const value = try read_string(cursor, strings, constants.value_prefix_bits);
    return .{
        .never_indexed = never_indexed,
        .name_index = name_index,
        .value = value.bytes,
        .value_coding = value.coding,
    };
}

/// RFC 9204 §4.5.6.
fn read_literal(first: u8, cursor: *Reader, strings: *Writer) Error!Representation.Literal {
    const never_indexed = first & constants.literal_never_flag != 0;
    const name = try read_string(cursor, strings, constants.literal_name_prefix_bits);
    const value = try read_string(cursor, strings, constants.value_prefix_bits);
    return .{
        .never_indexed = never_indexed,
        .name = name.bytes,
        .name_coding = name.coding,
        .value = value.bytes,
        .value_coding = value.coding,
    };
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

/// RFC 9204 §4.5.2's `T` bit: set means the static table.
fn table_of(first: u8, flag: u8) Table {
    return if (first & flag != 0) .static else .dynamic;
}

const testing = std.testing;
const representation_write = @import("representation_write.zig");

/// Room for the octets a test writes and for the strings it decodes, larger than any of them.
/// Test-only.
const test_room: usize = 256;
var test_octets: [test_room]u8 = undefined;
var test_strings: [test_room]u8 = undefined;

/// Reads one representation out of `octets`, with the strings written into `test_strings`.
fn read_one(octets: []const u8) Error!Representation {
    var reader = Reader.init(octets);
    var strings = Writer.init(&test_strings);
    return read(&reader, &strings);
}

/// Writes one representation and returns the octets. Test-only.
fn write_one(held: Representation) ![]const u8 {
    var writer = Writer.init(&test_octets);
    try representation_write.write(&writer, held);
    return writer.written();
}

test "B.1: the RFC's own encoded field section reads as it says it does" {
    // RFC 9204 Appendix B.1, stream 0: `0000` is the prefix, then `510b 2f69 6e64 6578 2e68 746d
    // 6c` is one Literal Field Line with Name Reference into static index 1, which is `:path`,
    // carrying the value `/index.html`.
    const octets = [_]u8{ 0x00, 0x00, 0x51, 0x0b } ++ "/index.html".*;
    var reader = Reader.init(&octets);
    const prefix = try read_prefix(&reader);
    try testing.expectEqual(0, prefix.encoded_insert_count);
    try testing.expect(!prefix.sign);
    try testing.expectEqual(0, prefix.delta_base);
    // §4.5.1.2: with no dynamic reference the Base is the Required Insert Count plus zero.
    try testing.expectEqual(0, try prefix.base(0));
    var strings = Writer.init(&test_strings);
    const line = (try read(&reader, &strings)).literal_name_reference;
    try testing.expect(!line.never_indexed);
    try testing.expectEqual(Table.static, line.table);
    try testing.expectEqual(1, line.name_index);
    try testing.expectEqualStrings("/index.html", line.value);
    try testing.expectEqual(Coding.raw, line.value_coding);
    // The name that index names is Appendix A's entry 1.
    try testing.expectEqualStrings(":path", static_table.entries[1].name);
    try testing.expectEqual(0, reader.remaining_len());
    // And writing it back yields the RFC's octets exactly.
    var writer = Writer.init(&test_octets);
    try write_prefix(&writer, Prefix.static_only);
    try representation_write.write(&writer, .{ .literal_name_reference = line });
    try testing.expectEqualSlices(u8, &octets, writer.written());
}

const static_table = @import("static_table.zig");

test "§4.5.2: an indexed field line names a table and an index" {
    // `1T` and a 6-bit index: 0xd1 is static index 17, which Appendix A gives as :method GET.
    const found = (try read_one(&.{0xd1})).indexed;
    try testing.expectEqual(Table.static, found.table);
    try testing.expectEqual(17, found.index);
    try testing.expectEqualStrings(":method", static_table.entries[17].name);
    try testing.expectEqualStrings("GET", static_table.entries[17].value);
    // With the T bit clear the same index is a relative index into the dynamic table.
    const dynamic = (try read_one(&.{0x91})).indexed;
    try testing.expectEqual(Table.dynamic, dynamic.table);
    try testing.expectEqual(17, dynamic.index);
    // An index at or above the 6-bit prefix continues into the octets that follow.
    const long = (try read_one(&.{ 0xff, 0x01 })).indexed;
    try testing.expectEqual(64, long.index);
    try testing.expectEqualSlices(u8, &.{ 0xff, 0x01 }, try write_one(.{ .indexed = long }));
}

test "§4.5.3: an indexed field line with a post-Base index is the 0001 pattern" {
    const found = (try read_one(&.{0x15})).indexed_post_base;
    try testing.expectEqual(5, found.index);
    try testing.expectEqualSlices(u8, &.{0x15}, try write_one(.{ .indexed_post_base = found }));
    // The 4-bit prefix carries 0 to 14 directly and continues above that.
    const long = (try read_one(&.{ 0x1f, 0x02 })).indexed_post_base;
    try testing.expectEqual(17, long.index);
    try testing.expectEqualSlices(u8, &.{ 0x1f, 0x02 }, try write_one(.{ .indexed_post_base = long }));
}

test "§4.5.4: the N and T bits of a literal with a name reference are read and written" {
    // `01NT` with N and T set: never indexed, static table, name index 1, value `a`.
    const octets = [_]u8{ 0x71, 0x01, 'a' };
    const found = (try read_one(&octets)).literal_name_reference;
    try testing.expect(found.never_indexed);
    try testing.expectEqual(Table.static, found.table);
    try testing.expectEqual(1, found.name_index);
    try testing.expectEqualStrings("a", found.value);
    try testing.expectEqualSlices(u8, &octets, try write_one(.{ .literal_name_reference = found }));
    // With both clear it is an ordinary dynamic reference.
    const plain = (try read_one(&.{ 0x41, 0x01, 'a' })).literal_name_reference;
    try testing.expect(!plain.never_indexed);
    try testing.expectEqual(Table.dynamic, plain.table);
    // A Huffman coded value sets the H bit of the value literal's prefix and comes back whole.
    const coded = try write_one(.{ .literal_name_reference = .{
        .never_indexed = false,
        .table = .static,
        .name_index = 1,
        .value = "/index.html",
        .value_coding = .huffman,
    } });
    var held: [test_room]u8 = undefined;
    @memcpy(held[0..coded.len], coded);
    const back = (try read_one(held[0..coded.len])).literal_name_reference;
    try testing.expectEqualStrings("/index.html", back.value);
    try testing.expectEqual(Coding.huffman, back.value_coding);
    // Appendix B.1 wrote the same field line raw in 13 octets, so the coded one is shorter.
    try testing.expect(coded.len < 13);
}

test "§4.5.5: a literal with a post-Base name reference is the 0000 pattern" {
    // `0000N` with N set and a 3-bit name index of 2, then the value `xy`.
    const octets = [_]u8{ 0x0a, 0x02, 'x', 'y' };
    const found = (try read_one(&octets)).literal_post_base_name_reference;
    try testing.expect(found.never_indexed);
    try testing.expectEqual(2, found.name_index);
    try testing.expectEqualStrings("xy", found.value);
    try testing.expectEqualSlices(u8, &octets, try write_one(.{ .literal_post_base_name_reference = found }));
}

test "§4.5.6: a literal name and value round trip, raw and Huffman coded" {
    // `001N` with N clear, the name as a 4-bit prefix literal and the value as an 8-bit one.
    const octets = [_]u8{ 0x23, 'a', 'b', 'c', 0x01, 'd' };
    const found = (try read_one(&octets)).literal;
    try testing.expect(!found.never_indexed);
    try testing.expectEqualStrings("abc", found.name);
    try testing.expectEqualStrings("d", found.value);
    try testing.expectEqual(Coding.raw, found.name_coding);
    try testing.expectEqualSlices(u8, &octets, try write_one(.{ .literal = found }));
    // Huffman coding sets the H bit of each literal's prefix, and what comes back is the same
    // string. RFC 9204 §4.1.2 is RFC 7541 §5.2's literal with QPACK's prefix sizes.
    const coded = try write_one(.{ .literal = .{
        .never_indexed = true,
        .name = "custom-key",
        .name_coding = .huffman,
        .value = "custom-value",
        .value_coding = .huffman,
    } });
    var held: [64]u8 = undefined;
    @memcpy(held[0..coded.len], coded);
    const back = (try read_one(held[0..coded.len])).literal;
    try testing.expect(back.never_indexed);
    try testing.expectEqualStrings("custom-key", back.name);
    try testing.expectEqualStrings("custom-value", back.value);
    try testing.expectEqual(Coding.huffman, back.name_coding);
    try testing.expectEqual(Coding.huffman, back.value_coding);
    try testing.expect(coded.len < "custom-key".len + "custom-value".len);
}

test "§4.5.1.2: the Base follows the Sign bit, and a negative one is refused" {
    // Sign clear: the Base is the Required Insert Count plus the Delta Base.
    const ahead: Prefix = .{ .encoded_insert_count = 4, .sign = false, .delta_base = 2 };
    try testing.expectEqual(11, try ahead.base(9));
    // Sign set: the Base is the count less the Delta Base less one, which is §4.5.1.2's rule for
    // an encoder that inserted entries while encoding the section it is referencing.
    const behind: Prefix = .{ .encoded_insert_count = 4, .sign = true, .delta_base = 2 };
    try testing.expectEqual(6, try behind.base(9));
    // §4.5.1.2: a Sign bit of 1 with a Delta Base at or above the count would make the Base
    // negative, which the same paragraph forbids.
    try testing.expectError(Error.BaseNegative, behind.base(2));
    try testing.expectError(Error.BaseNegative, behind.base(1));
    // Both halves survive the wire, Sign bit included.
    var writer = Writer.init(&test_octets);
    try write_prefix(&writer, behind);
    var reader = Reader.init(writer.written());
    try testing.expectEqual(behind, try read_prefix(&reader));
}

test "a representation that runs off the end consumes nothing" {
    // An indexed line whose continuation octets are missing, and a literal whose string is cut
    // short: both leave the reader where they found it, so a caller can wait for more octets.
    var reader = Reader.init(&.{0xff});
    var strings = Writer.init(&test_strings);
    try testing.expectError(error.Truncated, read(&reader, &strings));
    try testing.expectEqual(1, reader.remaining_len());
    var cut = Reader.init(&.{ 0x23, 'a', 'b' });
    try testing.expectError(error.Truncated, read(&cut, &strings));
    try testing.expectEqual(3, cut.remaining_len());
    // The one that matters: a literal whose name is whole and whose value is cut. The name was
    // already read when the value failed, so a reader that did not work on a copy would leave
    // the caller pointing into the middle of a representation it has not accepted.
    const partial = [_]u8{ 0x23, 'a', 'b', 'c', 0x05, 'd' };
    var half = Reader.init(&partial);
    try testing.expectError(error.Truncated, read(&half, &strings));
    try testing.expectEqual(partial.len, half.remaining_len());
    // And with the value whole it reads, so the octets before it were never the problem.
    const full = [_]u8{ 0x23, 'a', 'b', 'c', 0x05, 'd', 'e', 'f', 'g', 'h' };
    var whole = Reader.init(&full);
    var room = Writer.init(&test_strings);
    const line = (try read(&whole, &room)).literal;
    try testing.expectEqualStrings("abc", line.name);
    try testing.expectEqualStrings("defgh", line.value);
}

test "decision 77: every vector of spec/lean's proved Base decoding is this one's answer" {
    // spec/lean/Colibri/Qpack/Index.lean proves its `decodeBase` inverts the encoder's Sign bit and
    // Delta Base; its outputs over every input in range are here, and must be `Prefix.base`'s.
    var lines = std.mem.splitScalar(u8, @embedFile("base_vectors.txt"), '\n');
    var count: usize = 0;
    // Bounded by the file, which spec/lean/Vectors.lean writes.
    while (lines.next()) |line| {
        if (line.len == 0 or line[0] == '#') continue;
        var fields = std.mem.tokenizeScalar(u8, line, ' ');
        const required = try std.fmt.parseUnsigned(u64, fields.next().?, 10);
        const sign = std.mem.eql(u8, fields.next().?, "1");
        const delta = try std.fmt.parseUnsigned(u64, fields.next().?, 10);
        const answer = fields.next().?;
        const prefix: Prefix = .{ .encoded_insert_count = 0, .sign = sign, .delta_base = delta };
        if (std.mem.eql(u8, answer, "error")) {
            try testing.expectError(Error.BaseNegative, prefix.base(required));
        } else {
            try testing.expectEqual(try std.fmt.parseUnsigned(u64, answer, 10), try prefix.base(required));
        }
        count += 1;
    }
    // Every Required Insert Count and Delta Base from 0 to 8, with each Sign bit.
    try testing.expectEqual(162, count);
}
