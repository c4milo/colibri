//! The HPACK encoder: field lines in, one field block out (RFC 7541 §3, §6).
//!
//! An `Encoder` is one endpoint's encoding context (§2.2): a dynamic table that mirrors the
//! peer's decoder, and the limit the peer set on it, which in h2 is the peer's
//! `SETTINGS_HEADER_TABLE_SIZE`. A block is written as `begin_block`, then one `write_field` per
//! line, into a `core.Writer` the caller owns. Each call writes all of its octets or none.
//!
//! The strategy is the one RFC 7541 Appendix C's examples follow, and the tests hold the encoder
//! to those examples byte for byte:
//!
//! - a line found whole in either table is an indexed field (§6.1), the static table's index
//!   preferred because a line the static table holds is never inserted into the mirror;
//! - otherwise a literal, with the name by index when either table holds it (§6.2), and with
//!   incremental indexing (§6.2.1) unless the caller asked for another representation or the
//!   entry would not fit the table at all, in which case indexing it would only empty the table
//!   (§4.4);
//! - a string is Huffman-coded as `huffman` says: always, as the RFC's examples do; never; or only
//!   when that is strictly shorter, as nghttp2 does.
//!
//! The capacity the encoder declares is the smaller of the peer's limit and
//! `dynamic_table_capacity_max` (§4.2 lets an encoder use less than the limit). A change is
//! signalled at the start of the next block, with the smallest capacity of the interval first and
//! the final one second when it differs from the capacity last declared (§4.2), and the mirror is resized as each is written,
//! which is when the peer's decoder resizes.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const constants = @import("constants.zig");
const static_table = @import("static_table.zig");
const dynamic_table = @import("dynamic_table.zig");

const Writer = core.Writer;
const DynamicTable = dynamic_table.DynamicTable;
const Match = dynamic_table.Match;
const prefixed_integer = wire.prefixed_integer;
const string_literal = wire.string_literal;
const entry_size = wire.table_size.entry_size;

pub const Error = core.writer.Error;

/// How a line may be represented. `incremental` lets the encoder index it; `without_indexing`
/// keeps it out of the table; `never_indexed` also tells every intermediary to do the same
/// (RFC 7541 §6.2.3, §7.1.3).
pub const Indexing = enum { incremental, without_indexing, never_indexed };

/// When a string is Huffman-coded (RFC 7541 §5.2 leaves the choice to the encoder).
pub const HuffmanUse = enum { never, always, when_shorter };

pub const Encoder = struct {
    table: DynamicTable,
    /// The limit the peer set (RFC 7541 §4.2, §6.3).
    capacity_limit: u64,
    /// The capacity this encoder has chosen under the limit, declared at the next block's start.
    chosen: u64,
    /// The capacity last declared to the peer: what its decoder's table holds now.
    declared: u64,
    /// The smallest capacity chosen since the last declaration (RFC 7541 §4.2).
    chosen_min: u64,
    huffman: HuffmanUse,

    /// An encoder whose table's capacity and limit are both `capacity`: the protocol's initial
    /// value, 4,096 in h2 (RFC 9113 §6.5.2).
    pub fn init(encoder: *Encoder, capacity: u64, huffman: HuffmanUse) void {
        assert(capacity <= constants.dynamic_table_capacity_max);
        encoder.table.init(capacity);
        encoder.capacity_limit = capacity;
        encoder.chosen = capacity;
        encoder.declared = capacity;
        encoder.chosen_min = capacity;
        encoder.huffman = huffman;
    }

    /// The peer changed its limit and this endpoint has acknowledged it.
    pub fn set_capacity_limit(encoder: *Encoder, limit: u64) void {
        encoder.capacity_limit = limit;
        encoder.chosen = @min(limit, constants.dynamic_table_capacity_max);
        encoder.chosen_min = @min(encoder.chosen_min, encoder.chosen);
        assert(encoder.chosen <= encoder.capacity_limit);
    }

    /// Opens a block: writes the size updates a capacity change owes (RFC 7541 §4.2), or nothing.
    /// The capacity is not declared until `commit_block`, because a block the caller abandons
    /// never reaches the peer and owes its updates again.
    pub fn begin_block(encoder: *Encoder, output: *Writer) Error!void {
        var cursor = output.*;
        // RFC 7541 §4.2: the smallest maximum of the interval first, then the final one.
        if (encoder.chosen_min < encoder.declared and encoder.chosen_min < encoder.chosen) {
            try write_size_update(&cursor, encoder.chosen_min);
        }
        if (encoder.chosen != encoder.declared) try write_size_update(&cursor, encoder.chosen);
        output.* = cursor;
        encoder.table.resize(encoder.chosen_min);
        encoder.table.resize(encoder.chosen);
    }

    /// Declares the block the caller finished: the capacity its size updates named is what the
    /// peer's decoder holds from here on (RFC 7541 §4.2). A caller that abandons a block never
    /// calls this, so the next block writes the same updates again and the two tables stay the
    /// same size.
    pub fn commit_block(encoder: *Encoder) void {
        encoder.declared = encoder.chosen;
        encoder.chosen_min = encoder.chosen;
        assert(encoder.table.capacity == encoder.declared);
    }

    /// Writes one field line in the representation `indexing` allows.
    pub fn write_field(
        encoder: *Encoder,
        output: *Writer,
        name: []const u8,
        value: []const u8,
        indexing: Indexing,
    ) Error!void {
        assert(name.len <= constants.name_len_max and value.len <= constants.value_len_max);
        var cursor = output.*;
        const match = encoder.find(name, value);
        if (indexing != .never_indexed) {
            if (match.exact) |index| {
                // RFC 7541 §6.1: a line both tables hold is sent as its index.
                try prefixed_integer.encode(constants.indexed_prefix_bits, &cursor, constants.indexed_pattern, index);
                output.* = cursor;
                return;
            }
        }
        // RFC 7541 §4.4: an entry larger than the capacity would only empty the table.
        const fits = entry_size(name.len, value.len) <= encoder.table.capacity;
        const kind: Indexing = if (indexing == .incremental and !fits) .without_indexing else indexing;
        const name_index = match.name orelse 0;
        switch (kind) {
            .incremental => try prefixed_integer.encode(
                constants.incremental_prefix_bits,
                &cursor,
                constants.incremental_pattern,
                name_index,
            ),
            .without_indexing => try prefixed_integer.encode(
                constants.literal_prefix_bits,
                &cursor,
                constants.without_indexing_pattern,
                name_index,
            ),
            .never_indexed => try prefixed_integer.encode(
                constants.literal_prefix_bits,
                &cursor,
                constants.never_indexed_pattern,
                name_index,
            ),
        }
        if (name_index == 0) try encoder.write_string(&cursor, name);
        try encoder.write_string(&cursor, value);
        output.* = cursor;
        if (kind == .incremental) encoder.table.insert(name, value);
    }

    /// The indices of the fused address space (RFC 7541 §2.3.3) holding the line and its name.
    /// The static table's index is preferred for both: it is the lower one, and a line the static
    /// table holds is never in the mirror, since this encoder indexes it instead of inserting it.
    fn find(encoder: *const Encoder, name: []const u8, value: []const u8) Match {
        const static = find_static(name, value);
        const dynamic = encoder.table.find(name, value);
        var match: Match = static;
        if (match.exact == null) {
            if (dynamic.exact) |index| match.exact = index + constants.static_table_len;
        }
        if (match.name == null) {
            if (dynamic.name) |index| match.name = index + constants.static_table_len;
        }
        return match;
    }

    fn write_string(encoder: *const Encoder, output: *Writer, octets: []const u8) Error!void {
        const coding: string_literal.Coding = switch (encoder.huffman) {
            .never => .raw,
            .always => .huffman,
            .when_shorter => if (wire.huffman.encoded_len(octets) < octets.len) .huffman else .raw,
        };
        try string_literal.encode(constants.string_prefix_bits, output, 0, octets, coding);
    }
};

/// A size update (RFC 7541 §6.3).
fn write_size_update(output: *Writer, capacity: u64) Error!void {
    try prefixed_integer.encode(constants.size_update_prefix_bits, output, constants.size_update_pattern, capacity);
}

/// The lowest static indices holding the line and its name (RFC 7541 Appendix A).
fn find_static(name: []const u8, value: []const u8) Match {
    var match: Match = .{};
    for (static_table.entries, 1..) |entry, index| {
        if (!std.mem.eql(u8, entry.name, name)) continue;
        if (match.name == null) match.name = @intCast(index);
        if (std.mem.eql(u8, entry.value, value)) {
            match.exact = @intCast(index);
            return match;
        }
    }
    return match;
}

const testing = std.testing;
const Field = dynamic_table.Field;

/// The encoder the tests run in, placed outside any stack frame.
var test_encoder: Encoder = undefined;

/// Octets of block the tests write. Test-only.
const test_block_len_max = 256;

fn expect_block(lines: []const Field, expected: []const u8) !void {
    var buffer: [test_block_len_max]u8 = @splat(0);
    var output = Writer.init(&buffer);
    try test_encoder.begin_block(&output);
    for (lines) |line| try test_encoder.write_field(&output, line.name, line.value, .incremental);
    test_encoder.commit_block();
    try testing.expectEqualSlices(u8, expected, output.written());
}

const example_request_lines = [_]Field{
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":scheme", .value = "http" },
    .{ .name = ":path", .value = "/" },
    .{ .name = ":authority", .value = "www.example.com" },
};

const second_request_lines = example_request_lines ++ [_]Field{
    .{ .name = "cache-control", .value = "no-cache" },
};

const third_request_lines = [_]Field{
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":path", .value = "/index.html" },
    .{ .name = ":authority", .value = "www.example.com" },
    .{ .name = "custom-key", .value = "custom-value" },
};

test "RFC 7541 Appendix C.3: the encoder writes the three requests byte for byte, no Huffman" {
    test_encoder.init(4096, .never);
    try expect_block(&example_request_lines, "\x82\x86\x84\x41\x0fwww.example.com");
    try expect_block(&second_request_lines, "\x82\x86\x84\xbe\x58\x08no-cache");
    try expect_block(&third_request_lines, "\x82\x87\x85\xbf\x40\x0acustom-key\x0ccustom-value");
    try testing.expectEqual(164, test_encoder.table.size);
}

test "RFC 7541 Appendix C.4: with Huffman coding the encoder writes the same requests" {
    test_encoder.init(4096, .always);
    try expect_block(&example_request_lines, "\x82\x86\x84\x41\x8c\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff");
    try expect_block(&second_request_lines, "\x82\x86\x84\xbe\x58\x86\xa8\xeb\x10\x64\x9c\xbf");
    try expect_block(&third_request_lines, "\x82\x87\x85\xbf\x40\x88\x25\xa8\x49\xe9\x5b\xa9\x7d\x7f\x89\x25\xa8\x49\xe9\x5b\xb8\xe8\xb4\xbf");
}

const first_response_lines = [_]Field{
    .{ .name = ":status", .value = "302" },
    .{ .name = "cache-control", .value = "private" },
    .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:21 GMT" },
    .{ .name = "location", .value = "https://www.example.com" },
};

const second_response_lines = [_]Field{
    .{ .name = ":status", .value = "307" },
    .{ .name = "cache-control", .value = "private" },
    .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:21 GMT" },
    .{ .name = "location", .value = "https://www.example.com" },
};

const third_response_lines = [_]Field{
    .{ .name = ":status", .value = "200" },
    .{ .name = "cache-control", .value = "private" },
    .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:22 GMT" },
    .{ .name = "location", .value = "https://www.example.com" },
    .{ .name = "content-encoding", .value = "gzip" },
    .{ .name = "set-cookie", .value = "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1" },
};

test "RFC 7541 Appendix C.5: the responses at capacity 256, evictions included, no Huffman" {
    test_encoder.init(256, .never);
    try expect_block(&first_response_lines, "\x48\x03" ++ "302" ++ "\x58\x07private\x61\x1dMon, 21 Oct 2013 20:13:21 GMT\x6e\x17https://www.example.com");
    try expect_block(&second_response_lines, "\x48\x03" ++ "307" ++ "\xc1\xc0\xbf");
    try expect_block(&third_response_lines, "\x88\xc1\x61\x1dMon, 21 Oct 2013 20:13:22 GMT\xc0\x5a\x04gzip\x77\x38foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1");
    try testing.expectEqual(215, test_encoder.table.size);
}

test "RFC 7541 Appendix C.6: the same responses with Huffman coding" {
    test_encoder.init(256, .always);
    try expect_block(&first_response_lines, "\x48\x82\x64\x02\x58\x85\xae\xc3\x77\x1a\x4b\x61\x96\xd0\x7a\xbe\x94\x10\x54\xd4\x44\xa8\x20\x05\x95\x04\x0b\x81\x66\xe0\x82\xa6\x2d\x1b\xff\x6e\x91\x9d\x29\xad\x17\x18\x63\xc7\x8f\x0b\x97\xc8\xe9\xae\x82\xae\x43\xd3");
    try expect_block(&second_response_lines, "\x48\x83\x64\x0e\xff\xc1\xc0\xbf");
    try expect_block(&third_response_lines, "\x88\xc1\x61\x96\xd0\x7a\xbe\x94\x10\x54\xd4\x44\xa8\x20\x05\x95\x04\x0b\x81\x66\xe0\x84\xa6\x2d\x1b\xff\xc0\x5a\x83\x9b\xd9\xab\x77\xad\x94\xe7\x82\x1d\xd7\xf2\xe6\xc7\xb3\x35\xdf\xdf\xcd\x5b\x39\x60\xd5\xaf\x27\x08\x7f\x36\x72\xc1\xab\x27\x0f\xb5\x29\x1f\x95\x87\x31\x60\x65\xc0\x03\xed\x4e\xe5\xb1\x06\x3d\x50\x07");
}

test "when_shorter codes 302 with Huffman, which saves an octet, and not 307, which saves none" {
    test_encoder.init(256, .when_shorter);
    var buffer: [test_block_len_max]u8 = @splat(0);
    var output = Writer.init(&buffer);
    try test_encoder.begin_block(&output);
    try test_encoder.write_field(&output, ":status", "302", .without_indexing);
    try test_encoder.write_field(&output, ":status", "307", .without_indexing);
    test_encoder.commit_block();
    try testing.expectEqualSlices(u8, "\x08\x82\x64\x02\x08\x03" ++ "307", output.written());
}

test "never-indexed and without-indexing lines leave the table alone, and keep a name index" {
    test_encoder.init(4096, .never);
    var buffer: [test_block_len_max]u8 = @splat(0);
    var output = Writer.init(&buffer);
    try test_encoder.begin_block(&output);
    try test_encoder.write_field(&output, "authorization", "secret", .never_indexed);
    try test_encoder.write_field(&output, "x-trace", "1", .without_indexing);
    try test_encoder.write_field(&output, ":method", "GET", .never_indexed);
    test_encoder.commit_block();
    try testing.expectEqualSlices(u8, "\x1f\x08\x06secret\x00\x07x-trace\x011\x12\x03GET", output.written());
    try testing.expectEqual(0, test_encoder.table.len());
}

test "a line too large for the table is sent without indexing rather than emptying it" {
    test_encoder.init(40, .never);
    var buffer: [test_block_len_max]u8 = @splat(0);
    var output = Writer.init(&buffer);
    try test_encoder.begin_block(&output);
    try test_encoder.write_field(&output, "a", "b", .incremental);
    try test_encoder.write_field(&output, "c", "dddddddd", .incremental);
    test_encoder.commit_block();
    try testing.expectEqualSlices(u8, "\x40\x01a\x01b\x00\x01c\x08dddddddd", output.written());
    try testing.expectEqual(1, test_encoder.table.len());
}

test "a line that exactly fills the table is indexed" {
    test_encoder.init(34, .never);
    var buffer: [test_block_len_max]u8 = @splat(0);
    var output = Writer.init(&buffer);
    try test_encoder.begin_block(&output);
    try test_encoder.write_field(&output, "a", "b", .incremental);
    test_encoder.commit_block();
    try testing.expectEqualSlices(u8, "\x40\x01a\x01b", output.written());
    try testing.expectEqual(1, test_encoder.table.len());
}

test "a lowered then raised limit opens the next block with the smallest size, then the final" {
    test_encoder.init(4096, .never);
    var buffer: [test_block_len_max]u8 = @splat(0);
    var output = Writer.init(&buffer);
    try test_encoder.begin_block(&output);
    try test_encoder.write_field(&output, "a", "b", .incremental);
    try test_encoder.write_field(&output, "c", "d", .incremental);
    test_encoder.commit_block();
    test_encoder.set_capacity_limit(40);
    test_encoder.set_capacity_limit(100);
    output = Writer.init(&buffer);
    try test_encoder.begin_block(&output);
    test_encoder.commit_block();
    try testing.expectEqualSlices(u8, "\x3f\x09\x3f\x45", output.written());
    try testing.expectEqual(100, test_encoder.table.capacity);
    try testing.expectEqual(1, test_encoder.table.len());
    output = Writer.init(&buffer);
    try test_encoder.begin_block(&output);
    test_encoder.commit_block();
    try testing.expectEqual(0, output.offset);
    test_encoder.set_capacity_limit(constants.dynamic_table_capacity_max * 2);
    output = Writer.init(&buffer);
    try test_encoder.begin_block(&output);
    test_encoder.commit_block();
    try testing.expectEqualSlices(u8, "\x3f\xe1\x7f", output.written());
    try testing.expectEqual(constants.dynamic_table_capacity_max, test_encoder.table.capacity);
}

test "a field that does not fit the output is not written at all, and not inserted" {
    test_encoder.init(4096, .never);
    var buffer: [4]u8 = @splat(0);
    var output = Writer.init(&buffer);
    try test_encoder.begin_block(&output);
    try testing.expectError(error.NoSpaceLeft, test_encoder.write_field(&output, "a", "bcdef", .incremental));
    test_encoder.commit_block();
    try testing.expectEqual(0, output.offset);
    try testing.expectEqual(0, test_encoder.table.len());
}

test "a block the caller abandons owes its size update again" {
    test_encoder.init(4096, .never);
    test_encoder.set_capacity_limit(100);
    var buffer: [test_block_len_max]u8 = @splat(0);
    var output = Writer.init(&buffer);
    try test_encoder.begin_block(&output);
    try testing.expectEqualSlices(u8, "\x3f\x45", output.written());
    // The caller found no room for a field line and threw the block away, so the peer never read
    // the update. RFC 7541 §4.2: the decoder's table holds the capacity last declared to it, so
    // the next block owes the same update.
    output = Writer.init(&buffer);
    try test_encoder.begin_block(&output);
    test_encoder.commit_block();
    try testing.expectEqualSlices(u8, "\x3f\x45", output.written());
    // A block that was committed does not repeat it.
    output = Writer.init(&buffer);
    try test_encoder.begin_block(&output);
    test_encoder.commit_block();
    try testing.expectEqual(0, output.offset);
}
