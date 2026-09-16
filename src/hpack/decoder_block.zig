//! The representation reader of the HPACK decoder, split off decoder.zig for length: one
//! `Block` walks one complete field block over a `Decoder`, reading one representation of
//! RFC 7541 §6 per call to `next`. The check order each representation goes through is listed
//! in decoder.zig's header, and the tests of the refusals are here, beside the code that refuses.
//!
//! A representation is read whole or not at all. On `error.Truncated` the cursor stays at its
//! first octet and the dynamic table is untouched, so a caller holding a block cut mid-way, as
//! h2 does between a HEADERS frame and its CONTINUATION, can decode what is whole, keep the tail,
//! and feed it again with the next fragment.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const constants = @import("constants.zig");
const static_table = @import("static_table.zig");
const decoder_module = @import("decoder.zig");

const Reader = core.Reader;
const Writer = core.Writer;
const Decoder = decoder_module.Decoder;
const Error = decoder_module.Error;
const Field = decoder_module.Field;
const FieldLine = decoder_module.FieldLine;
const prefixed_integer = wire.prefixed_integer;
const string_literal = wire.string_literal;

/// The three literal representations of RFC 7541 §6.2.
const Literal = enum { incremental, without_indexing, never_indexed };

pub const Block = struct {
    decoder: *Decoder,
    reader: Reader,
    /// Field lines returned so far.
    fields: u32 = 0,
    /// Size updates read so far.
    updates: u32 = 0,

    /// The next field line, or null when the block is consumed.
    pub fn next(block: *Block) Error!?FieldLine {
        // Every pass but the last reads one size update, and at most two are allowed.
        for (0..constants.size_updates_per_block_max + 1) |_| {
            if (block.reader.remaining_len() == 0) return null;
            const first = try block.reader.peek_byte();
            // RFC 7541 §6: the representation is named by the first octet's high bits.
            if (first & constants.indexed_pattern != 0) return try block.indexed();
            if (first & constants.incremental_pattern != 0) {
                return try block.literal(.incremental, constants.incremental_prefix_bits);
            }
            if (first & constants.size_update_pattern != 0) {
                try block.size_update();
                continue;
            }
            if (first & constants.never_indexed_pattern != 0) {
                return try block.literal(.never_indexed, constants.literal_prefix_bits);
            }
            return try block.literal(.without_indexing, constants.literal_prefix_bits);
        }
        unreachable; // A third update fails inside size_update.
    }

    /// The octets consumed so far.
    pub fn consumed_len(block: *const Block) usize {
        return block.reader.offset;
    }

    fn indexed(block: *Block) Error!FieldLine {
        // RFC 9113 §4.3.1: after a lowered limit, the block must start with a size update.
        if (block.is_first() and block.decoder.lowered_limit != null) return error.SizeUpdateMissing;
        const index = try prefixed_integer.decode(constants.indexed_prefix_bits, &block.reader);
        // RFC 7541 §6.1: the index value of 0 is a decoding error in an indexed field.
        if (index == 0) return error.IndexZero;
        const field = try block.resolve(index);
        block.fields += 1;
        return .{ .name = field.name, .value = field.value, .never_indexed = false };
    }

    fn literal(block: *Block, kind: Literal, comptime prefix_bits: u4) Error!FieldLine {
        // RFC 9113 §4.3.1: after a lowered limit, the block must start with a size update.
        if (block.is_first() and block.decoder.lowered_limit != null) return error.SizeUpdateMissing;
        const decoder = block.decoder;
        // The cursor moves once, when the whole representation has been read.
        var cursor = block.reader;
        const name_index = try prefixed_integer.decode(prefix_bits, &cursor);
        var name = Writer.init(&decoder.name_scratch);
        if (name_index == 0) {
            // RFC 7541 §6.2.1: a value 0 in place of the index means a literal name follows.
            try string(&cursor, &name);
        } else {
            // RFC 7541 §4.4: the entry this name refers to may be evicted by this very insert, so
            // the name is copied before the table changes.
            const field = try block.resolve(name_index);
            name.write_bytes(field.name) catch unreachable;
        }
        var value = Writer.init(&decoder.value_scratch);
        try string(&cursor, &value);
        block.reader = cursor;
        // RFC 7541 §3.2: a literal with incremental indexing is inserted at the beginning of the
        // dynamic table; the other two literals leave the table alone.
        if (kind == .incremental) decoder.table.insert(name.written(), value.written());
        block.fields += 1;
        return .{
            .name = name.written(),
            .value = value.written(),
            .never_indexed = kind == .never_indexed,
        };
    }

    fn size_update(block: *Block) Error!void {
        const decoder = block.decoder;
        // RFC 7541 §4.2: at most two updates, "resulting in at most two dynamic table size updates".
        if (block.updates == constants.size_updates_per_block_max) return error.SizeUpdateTooMany;
        // RFC 7541 §4.2: an update "MUST occur at the beginning" of the block.
        if (block.fields > 0) return error.SizeUpdateNotFirst;
        const capacity = try prefixed_integer.decode(constants.size_update_prefix_bits, &block.reader);
        // RFC 7541 §6.3: a size above the protocol's limit is a decoding error.
        if (capacity > decoder.capacity_limit) return error.SizeUpdateTooLarge;
        if (decoder.lowered_limit) |lowered| {
            // RFC 9113 §4.3.1: the update must set a size at or below the lowered limit.
            if (capacity > lowered) return error.SizeUpdateMissing;
            decoder.lowered_limit = null;
        }
        decoder.table.resize(capacity);
        block.updates += 1;
    }

    /// One string literal from `cursor` into `output`, which is sized to the implementation limit.
    fn string(cursor: *Reader, output: *Writer) Error!void {
        _ = string_literal.decode(constants.string_prefix_bits, cursor, output) catch |failure| {
            // RFC 7541 §7.4: a string past the implementation's length limit is refused.
            if (failure == error.NoSpaceLeft) return error.StringTooLong;
            return failure;
        };
    }

    /// The entry at `index` in the fused address space (RFC 7541 §2.3.3).
    fn resolve(block: *const Block, index: u64) Error!Field {
        assert(index > 0);
        if (index <= constants.static_table_len) {
            const entry = static_table.entries[index - 1];
            return .{ .name = entry.name, .value = entry.value };
        }
        // RFC 7541 §2.3.3: an index past both tables is a decoding error.
        return block.decoder.table.get(index - constants.static_table_len) orelse error.IndexOutOfRange;
    }

    fn is_first(block: *const Block) bool {
        return block.fields == 0 and block.updates == 0;
    }
};

const testing = std.testing;
const expect_lines = decoder_module.expect_lines;
const expect_refused = decoder_module.expect_refused;

test "an indexed field with index 0 is refused; a literal with name index 0 is a new name" {
    decoder_module.test_decoder.init(4096);
    try expect_refused("\x80", error.IndexZero);
    try expect_lines("\x40\x01a\x01b", &.{.{ .name = "a", .value = "b" }});
    try expect_lines("\x00\x01c\x01d\x10\x01e\x01f", &.{
        .{ .name = "c", .value = "d" },
        .{ .name = "e", .value = "f" },
    });
    try testing.expectEqual(1, decoder_module.test_decoder.table.len());
}

test "only the never-indexed literal carries the flag an intermediary must honour (§6.2.3)" {
    decoder_module.test_decoder.init(4096);
    var block = decoder_module.test_decoder.block("\x10\x01a\x01b\x00\x01c\x01d\x40\x01e\x01f\x82");
    try testing.expect((try block.next()).?.never_indexed);
    try testing.expect(!(try block.next()).?.never_indexed);
    try testing.expect(!(try block.next()).?.never_indexed);
    try testing.expect(!(try block.next()).?.never_indexed);
    try testing.expectEqual(null, try block.next());
}

test "an index past both tables is refused, in an indexed field and as a literal's name" {
    decoder_module.test_decoder.init(4096);
    try expect_lines("\xbd", &.{.{ .name = "www-authenticate", .value = "" }});
    try expect_refused("\xbe", error.IndexOutOfRange);
    try expect_refused("\x7e\x01v", error.IndexOutOfRange);
    try expect_lines("\x40\x01a\x01b\xbe", &.{
        .{ .name = "a", .value = "b" },
        .{ .name = "a", .value = "b" },
    });
    try expect_refused("\xbf", error.IndexOutOfRange);
}

test "an insert larger than the capacity empties the table and the next index past it fails" {
    decoder_module.test_decoder.init(40);
    try expect_lines("\x40\x01a\x01b\xbe", &.{
        .{ .name = "a", .value = "b" },
        .{ .name = "a", .value = "b" },
    });
    try expect_refused("\x40\x01c\x08dddddddd\xbe", error.IndexOutOfRange);
    try testing.expectEqual(0, decoder_module.test_decoder.table.len());
}

/// A value long enough that fourteen entries of it nearly fill the octet buffer, so the next
/// insert moves the live octets over the evicted ones (RFC 7541 §4.4's caution). A literal
/// carrying it is the value, its length, a name of a few octets and the pattern octet.
const crowding_value_len = 1100;
const crowding_literal_framing = 16;
const crowding_literal_len_max = crowding_value_len + crowding_literal_framing;

test "a name referenced from the entry this insert evicts is returned intact (§4.4)" {
    decoder_module.test_decoder.init(constants.dynamic_table_capacity_max);
    const value: [crowding_value_len]u8 = @splat('v');
    var block_buffer: [crowding_literal_len_max]u8 = @splat(0);
    var output = Writer.init(&block_buffer);
    try wire.string_literal.encode(8, &output, 0, &value, .raw);
    const encoded_value = output.written();
    // Fourteen literals with new names fill the buffer to within one entry of its end.
    for (0..14) |index| {
        var name_buffer: [5]u8 = "name?".*;
        name_buffer[4] = @intCast('a' + index);
        var field_buffer: [crowding_literal_len_max]u8 = @splat(0);
        var field = Writer.init(&field_buffer);
        try field.write_byte(constants.incremental_pattern);
        try wire.string_literal.encode(8, &field, 0, &name_buffer, .raw);
        try field.write_bytes(encoded_value);
        try expect_lines(field.written(), &.{.{ .name = &name_buffer, .value = &value }});
    }
    try testing.expectEqual(14, decoder_module.test_decoder.table.len());
    // A literal whose name is the oldest entry's, index 61 + 14, and whose insert evicts it.
    var field_buffer: [crowding_literal_len_max]u8 = @splat(0);
    var field = Writer.init(&field_buffer);
    try wire.prefixed_integer.encode(6, &field, constants.incremental_pattern, constants.static_table_len + 14);
    try field.write_bytes(encoded_value);
    try expect_lines(field.written(), &.{.{ .name = "namea", .value = &value }});
    try testing.expectEqual(14, decoder_module.test_decoder.table.len());
    try testing.expectEqualStrings("namea", decoder_module.test_decoder.table.get(1).?.name);
}

test "a size update resizes the table, and is refused above the limit, after a field, or third" {
    decoder_module.test_decoder.init(4096);
    try expect_lines("\x40\x01a\x01b", &.{.{ .name = "a", .value = "b" }});
    try expect_lines("\x20", &.{});
    try testing.expectEqual(0, decoder_module.test_decoder.table.capacity);
    try testing.expectEqual(0, decoder_module.test_decoder.table.len());
    try expect_lines("\x3f\xe1\x1f\x3f\xe1\x1f\x82", &.{.{ .name = ":method", .value = "GET" }});
    try testing.expectEqual(4096, decoder_module.test_decoder.table.capacity);
    try expect_refused("\x3f\xe2\x1f", error.SizeUpdateTooLarge);
    try expect_refused("\x82\x20", error.SizeUpdateNotFirst);
    try expect_refused("\x20\x20\x20", error.SizeUpdateTooMany);
}

test "after the limit is lowered the next block must open with an update at or below it" {
    decoder_module.test_decoder.init(4096);
    try expect_lines("\x40\x01a\x01b", &.{.{ .name = "a", .value = "b" }});
    decoder_module.test_decoder.set_capacity_limit(100);
    try expect_refused("\x82", error.SizeUpdateMissing);
    try expect_refused("\x40\x01c\x01d", error.SizeUpdateMissing);
    try expect_refused("\x3f\x46\x82", error.SizeUpdateTooLarge);
    try expect_lines("\x3f\x45\x82", &.{.{ .name = ":method", .value = "GET" }});
    try testing.expectEqual(100, decoder_module.test_decoder.table.capacity);
    try testing.expectEqual(1, decoder_module.test_decoder.table.len());
    try expect_lines("\x82", &.{.{ .name = ":method", .value = "GET" }});
    decoder_module.test_decoder.set_capacity_limit(4096);
    try expect_lines("\x82", &.{.{ .name = ":method", .value = "GET" }});
    try testing.expectEqual(100, decoder_module.test_decoder.table.capacity);
}

test "two lowerings before a block require an update at or below the smaller" {
    decoder_module.test_decoder.init(4096);
    decoder_module.test_decoder.set_capacity_limit(200);
    decoder_module.test_decoder.set_capacity_limit(300);
    try expect_refused("\x3f\xd5\x01\x82", error.SizeUpdateMissing);
    try expect_lines("\x3f\xa9\x01\x82", &.{.{ .name = ":method", .value = "GET" }});
}

test "a literal cut after its name moves nothing, and decodes once the rest arrives" {
    decoder_module.test_decoder.init(4096);
    const whole = "\x82\x40\x0acustom-key\x0ccustom-value";
    const cut = whole[0 .. whole.len - 5];
    var block = decoder_module.test_decoder.block(cut);
    try testing.expectEqualStrings(":method", (try block.next()).?.name);
    try testing.expectError(error.Truncated, block.next());
    try testing.expectEqual(1, block.consumed_len());
    try testing.expectEqual(0, decoder_module.test_decoder.table.len());
    var rest = decoder_module.test_decoder.block(whole[block.consumed_len()..]);
    try testing.expectEqualStrings("custom-key", (try rest.next()).?.name);
    try testing.expectEqual(null, try rest.next());
    try testing.expectEqual(1, decoder_module.test_decoder.table.len());
}

test "a string past the implementation limit, and a block cut inside a string, are refused" {
    decoder_module.test_decoder.init(4096);
    // A raw name one octet longer than `name_len_max`, every octet present.
    const too_long = "\x40\x7f\x82\x01" ++ [_]u8{'a'} ** (constants.name_len_max + 1);
    try expect_refused(too_long, error.StringTooLong);
    try expect_refused(too_long[0 .. too_long.len - 1], error.Truncated);
    try expect_refused("\x40\x03ab", error.Truncated);
    try expect_refused("\x40\x01a\x81\xff", error.HuffmanPaddingTooLong);
    try expect_refused("\x40\x01a\x81\x00", error.HuffmanPaddingNotEos);
    try expect_refused("\x40\x01a\x84\xff\xff\xff\xff", error.HuffmanEosInData);
    try expect_refused("\x40", error.Truncated);
}

/// The capacity a fuzzed decoder starts with: RFC 7541 Appendix C.5's, so evictions happen.
const fuzz_capacity = 256;

fn fuzz_block(_: void, smith: *testing.Smith) anyerror!void {
    var input: [constants.fuzz_block_len_max]u8 = @splat(0);
    const octets = input[0..smith.slice(&input)];
    decoder_module.test_decoder.init(fuzz_capacity);
    var block = decoder_module.test_decoder.block(octets);
    for (0..octets.len + 1) |_| {
        const line = block.next() catch return;
        if (line == null) {
            try testing.expectEqual(octets.len, block.consumed_len());
            return;
        }
        try testing.expect(line.?.name.len <= constants.name_len_max);
        try testing.expect(decoder_module.test_decoder.table.size <= decoder_module.test_decoder.table.capacity);
    }
    return error.TestUnexpectedResult;
}

test "fuzz: a block decodes wholly or is refused, and the table stays under its capacity" {
    try testing.fuzz({}, fuzz_block, .{ .corpus = &.{
        core.fuzz.input("\x82\x86\x84\x41\x0fwww.example.com"),
        core.fuzz.input("\x3f\xe1\x1f\x82"),
        core.fuzz.input("\x80"),
        core.fuzz.input("\x40\x81\xff"),
    } });
    try core.fuzz.sweep(fuzz_block, null);
}
