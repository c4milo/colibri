//! The representation reader of the HPACK decoder, split off decoder.zig for length: one
//! `Block` decodes one complete field block over a `Decoder`, reading the size updates the block
//! opens with and then one field-line representation of RFC 7541 §6 per call to `next`. The order of the checks on each representation is listed
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

    /// The next field line, or null when the block is consumed. An indexed field line, which a
    /// block that repeats lines the table holds is made of, is read here, and `next_other` reads
    /// the rest.
    pub fn next(block: *Block) Error!?FieldLine {
        if (block.reader.remaining_len() > 0) {
            const first = block.reader.peek_byte() catch unreachable;
            // RFC 7541 §6.1: a first octet whose high bit is set starts an indexed field line.
            if (first & constants.indexed_pattern != 0) return try block.indexed();
        }
        return block.next_other();
    }

    /// The next field line of any representation, the size updates a block opens with included.
    /// It is out of line, so that `next` stays small enough to inline where it is called.
    noinline fn next_other(block: *Block) Error!?FieldLine {
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

    inline fn indexed(block: *Block) Error!FieldLine {
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
            // RFC 7541 §4.4: the entry this name refers to may be evicted by this insert, so
            // the name is copied before the table changes.
            const field = try block.resolve(name_index);
            name.write_bytes(field.name) catch unreachable;
        }
        var value = Writer.init(&decoder.value_scratch);
        try string(&cursor, &value);
        block.reader = cursor;
        // RFC 7541 §3.2: a literal with incremental indexing is inserted at the beginning of the
        // dynamic table; the other two literals do not change the table.
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

// The tests below hold `next` to `next_other`, which is `next` as it was before the indexed field
// line was read first: on two decoders that start alike, each call must return the same line or
// refusal, consume the same octets and leave the same table.

/// The decoder `next_other` runs on, beside `decoder_module.test_decoder`. Test-only.
threadlocal var reference_decoder: Decoder align(@alignOf(Decoder)) = undefined;

/// What one call returned, in a form two calls compare by: the line's octets, the refusal, or the
/// end of the block.
const Outcome = union(enum) { line: FieldLine, refused: Error, end };

fn outcome_of(result: Error!?FieldLine) Outcome {
    const line = result catch |failure| return .{ .refused = failure };
    return if (line) |found| .{ .line = found } else .end;
}

fn same_outcome(first: Outcome, second: Outcome) bool {
    return switch (first) {
        .end => second == .end,
        .refused => |failure| second == .refused and second.refused == failure,
        .line => |line| second == .line and std.mem.eql(u8, line.name, second.line.name) and
            std.mem.eql(u8, line.value, second.line.value) and line.never_indexed == second.line.never_indexed,
    };
}

/// Whether the two decoders' tables hold the same entries at the same size and capacity.
fn same_tables() bool {
    const changed = &decoder_module.test_decoder.table;
    const reference = &reference_decoder.table;
    if (changed.len() != reference.len() or changed.size != reference.size) return false;
    if (changed.capacity != reference.capacity) return false;
    for (1..changed.len() + 1) |index| {
        const one = changed.get(index).?;
        const other = reference.get(index).?;
        if (!std.mem.eql(u8, one.name, other.name) or !std.mem.eql(u8, one.value, other.value)) return false;
    }
    return true;
}

/// The limit a test lowers to, below `fuzz_capacity`, so that a block must open with a size update.
const lowered_capacity = 100;

/// Whether the two decoders wait for the same size update: none, or one at or below one limit.
fn same_lowered_limits() bool {
    const changed = decoder_module.test_decoder.lowered_limit;
    const reference = reference_decoder.lowered_limit;
    if (changed == null or reference == null) return changed == null and reference == null;
    return changed.? == reference.?;
}

/// Starts both decoders alike: `capacity`, two entries in the table, and a lowered limit when
/// `lowered` is set.
fn start_both(capacity: u64, lowered: bool) !void {
    for ([_]*Decoder{ &decoder_module.test_decoder, &reference_decoder }) |decoder| {
        decoder.init(capacity);
        var seed = decoder.block("\x40\x01a\x01b\x41\x0fwww.example.com");
        _ = try seed.next_other();
        _ = try seed.next_other();
        if (lowered) decoder.set_capacity_limit(lowered_capacity);
    }
}

/// Fails, printing both, when `next` and `next_other` differ anywhere in `octets`.
fn expect_same_block(octets: []const u8, lowered: bool) !void {
    try start_both(fuzz_capacity, lowered);
    var changed = decoder_module.test_decoder.block(octets);
    var reference = reference_decoder.block(octets);
    for (0..octets.len + 1) |call| {
        const changed_outcome = outcome_of(changed.next());
        const reference_outcome = outcome_of(reference.next_other());
        const same = same_outcome(changed_outcome, reference_outcome) and
            changed.consumed_len() == reference.consumed_len() and same_tables() and
            changed.fields == reference.fields and changed.updates == reference.updates and
            same_lowered_limits();
        if (!same) {
            std.debug.print("first difference: block {x}, call {d}: next {any}, next_other {any}\n", .{ octets, call, changed_outcome, reference_outcome });
            return error.TestUnexpectedResult;
        }
        if (changed_outcome != .line) return;
    }
}

/// The octet values, 0 to 255.
const octet_values = std.math.maxInt(u8) + 1;

test "next returns what next_other returns for every block of up to two octets" {
    for ([_]bool{ false, true }) |lowered| {
        try expect_same_block("", lowered);
        for (0..octet_values) |first| {
            try expect_same_block(&.{@intCast(first)}, lowered);
            for (0..octet_values) |second| try expect_same_block(&.{ @intCast(first), @intCast(second) }, lowered);
        }
    }
}

test "next returns what next_other returns for each cut of blocks that mix every representation" {
    const blocks = [_][]const u8{
        // RFC 7541 Appendix C.3 and C.4: indexed lines, static and dynamic, and literals.
        "\x82\x86\x84\x41\x0fwww.example.com",
        "\x82\x86\x84\xbe\x58\x08no-cache",
        "\x82\x87\x85\xbf\x40\x0acustom-key\x0ccustom-value",
        // A size update, then an indexed line; two updates; an update after a line.
        "\x3f\x45\x82\xbe",
        "\x20\x3f\xe1\x1f\x82",
        "\x82\x20",
        // A never-indexed literal, an index past both tables, and an index of 0.
        "\x10\x01a\x01b\xc0",
        "\xbf\x80",
    };
    for (blocks) |octets| {
        for (0..octets.len + 1) |len| {
            for ([_]bool{ false, true }) |lowered| try expect_same_block(octets[0..len], lowered);
        }
    }
}
