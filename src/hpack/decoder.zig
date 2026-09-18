//! The HPACK decoder: a field block in, its field lines out, one at a time (RFC 7541 §3).
//!
//! A `Decoder` is one endpoint's decoding context (§2.2): its dynamic table and the limit the
//! protocol set on it, which in h2 is this endpoint's own `SETTINGS_HEADER_TABLE_SIZE`. A
//! `Block` decodes one complete field block over it, and each call to `next` reads one
//! representation (§6) and returns the field line it produced, or null at the end. The caller
//! places the decoder and reads the lines as they come, which is the "minimal transitory memory"
//! of §3.1: no line is held past the next call.
//!
//! `Block` is in decoder_block.zig and reads one representation per call. Each is checked in
//! this order (invariant 7):
//!   1. its pattern, from the first octet's high bits (§6);
//!   2. a size update: it comes before every field line in the block (§4.2), at most twice
//!      (§4.2), at or below the protocol's limit (§6.3), and, after the limit was lowered, at or
//!      below the lowered limit (RFC 9113 §4.3.1);
//!   3. an index: not 0 in an indexed field (§6.1), and inside the address space (§2.3.3);
//!   4. a string: an integer and octets `wire.string_literal` accepts, decoding to at most
//!      `name_len_max` or `value_len_max` octets, or `error.StringTooLong` (§7.4).
//! An error refuses the whole block. The block's first error is its verdict, and the decoder's
//! table is left as the representations before it left it; the protocol module ends the
//! connection on any of them (RFC 9113 §4.3), so nothing decodes over that table again.
//!
//! The decoder never checks a name or a value against RFC 9110: the protocol module does, with
//! the `http` validators, once it has the line (decision 15).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const constants = @import("constants.zig");
const static_table = @import("static_table.zig");
const dynamic_table = @import("dynamic_table.zig");

const Reader = core.Reader;
const Writer = core.Writer;
const DynamicTable = dynamic_table.DynamicTable;
pub const Field = dynamic_table.Field;

/// The representation reader, split off this file for length: `decoder_block.zig`.
pub const Block = @import("decoder_block.zig").Block;

pub const Error = error{
    /// An indexed field with index 0 (RFC 7541 §6.1).
    IndexZero,
    /// An index past both tables (RFC 7541 §2.3.3).
    IndexOutOfRange,
    /// A size update above the protocol's limit (RFC 7541 §6.3).
    SizeUpdateTooLarge,
    /// A size update after a field line of the same block (RFC 7541 §4.2).
    SizeUpdateNotFirst,
    /// A third size update in one block (RFC 7541 §4.2).
    SizeUpdateTooMany,
    /// A block after a lowered limit that does not start with a size update at or below it
    /// (RFC 9113 §4.3.1).
    SizeUpdateMissing,
    /// A name or value longer than the implementation limit (RFC 7541 §7.4).
    StringTooLong,
    /// The block ended inside a representation.
    Truncated,
} || wire.prefixed_integer.DecodeError || wire.huffman.DecodeError;

/// One decoded field line. `never_indexed` is set for the representation of RFC 7541 §6.2.3,
/// which an intermediary must forward in the same representation. The slices are valid until
/// the next call on the block.
pub const FieldLine = struct {
    name: []const u8,
    value: []const u8,
    never_indexed: bool,
};

pub const Decoder = struct {
    table: DynamicTable,
    /// The limit the protocol set: the largest capacity a size update may declare (RFC 7541
    /// §6.3). In h2, this endpoint's own `SETTINGS_HEADER_TABLE_SIZE`, once acknowledged.
    capacity_limit: u64,
    /// The smallest limit set since the peer's capacity last fit under it, if any. The next block
    /// must start with a size update at or below it (RFC 9113 §4.3.1).
    lowered_limit: ?u64,
    name_scratch: [constants.name_len_max]u8,
    value_scratch: [constants.value_len_max]u8,

    /// A decoder whose table's capacity and limit are both `capacity`: the protocol's initial
    /// value, 4,096 in h2 (RFC 9113 §6.5.2).
    pub fn init(decoder: *Decoder, capacity: u64) void {
        assert(capacity <= constants.dynamic_table_capacity_max);
        decoder.table.init(capacity);
        decoder.capacity_limit = capacity;
        decoder.lowered_limit = null;
        assert(decoder.table.capacity == decoder.capacity_limit);
    }

    /// The protocol changed the limit, and the peer has acknowledged it. A lower limit than the
    /// table's capacity obliges the peer to open its next block with a size update.
    pub fn set_capacity_limit(decoder: *Decoder, limit: u64) void {
        assert(limit <= constants.dynamic_table_capacity_max);
        decoder.capacity_limit = limit;
        if (limit < decoder.table.capacity) {
            decoder.lowered_limit = @min(decoder.lowered_limit orelse limit, limit);
        }
    }

    /// A pass over one complete field block.
    pub fn block(decoder: *Decoder, octets: []const u8) Block {
        return .{ .decoder = decoder, .reader = Reader.init(octets) };
    }
};

const testing = std.testing;

/// The decoder the tests of this file and of decoder_block.zig run in, placed outside any stack
/// frame. Test-only.
pub var test_decoder: Decoder = undefined;

/// Requires `octets` to decode over `test_decoder` to exactly `expected`. Test-only.
pub fn expect_lines(octets: []const u8, expected: []const Field) !void {
    var block = test_decoder.block(octets);
    for (expected) |field| {
        const line = (try block.next()) orelse return error.TestUnexpectedResult;
        try testing.expectEqualStrings(field.name, line.name);
        try testing.expectEqualStrings(field.value, line.value);
    }
    try testing.expectEqual(null, try block.next());
    try testing.expectEqual(octets.len, block.consumed_len());
}

/// Requires `octets` to be refused with `expected`, after any lines it yields first. Test-only.
pub fn expect_refused(octets: []const u8, expected: Error) !void {
    var block = test_decoder.block(octets);
    // The refusal may come after accepted lines; a block of n octets holds at most n of them.
    for (0..octets.len + 1) |_| {
        const line = block.next() catch |failure| return testing.expectEqual(expected, failure);
        if (line == null) return error.TestUnexpectedResult;
    }
    return error.TestUnexpectedResult;
}

const example_request_lines = [_]Field{
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":scheme", .value = "http" },
    .{ .name = ":path", .value = "/" },
    .{ .name = ":authority", .value = "www.example.com" },
};

test "RFC 7541 Appendix C.3: three requests without Huffman coding share one table" {
    test_decoder.init(4096);
    try expect_lines("\x82\x86\x84\x41\x0fwww.example.com", &example_request_lines);
    try testing.expectEqual(57, test_decoder.table.size);
    try expect_lines("\x82\x86\x84\xbe\x58\x08no-cache", &(example_request_lines ++ [_]Field{
        .{ .name = "cache-control", .value = "no-cache" },
    }));
    try testing.expectEqual(110, test_decoder.table.size);
    try expect_lines("\x82\x87\x85\xbf\x40\x0acustom-key\x0ccustom-value", &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/index.html" },
        .{ .name = ":authority", .value = "www.example.com" },
        .{ .name = "custom-key", .value = "custom-value" },
    });
    try testing.expectEqual(164, test_decoder.table.size);
    try testing.expectEqual(3, test_decoder.table.len());
}

test "RFC 7541 Appendix C.4: the same requests with Huffman coding decode to the same lines" {
    test_decoder.init(4096);
    try expect_lines("\x82\x86\x84\x41\x8c\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff", &example_request_lines);
    try expect_lines("\x82\x86\x84\xbe\x58\x86\xa8\xeb\x10\x64\x9c\xbf", &(example_request_lines ++ [_]Field{
        .{ .name = "cache-control", .value = "no-cache" },
    }));
    try expect_lines("\x82\x87\x85\xbf\x40\x88\x25\xa8\x49\xe9\x5b\xa9\x7d\x7f\x89\x25\xa8\x49\xe9\x5b\xb8\xe8\xb4\xbf", &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/index.html" },
        .{ .name = ":authority", .value = "www.example.com" },
        .{ .name = "custom-key", .value = "custom-value" },
    });
    try testing.expectEqual(164, test_decoder.table.size);
}

const first_response = "\x48\x03" ++ "302" ++ "\x58\x07private\x61\x1dMon, 21 Oct 2013 20:13:21 GMT\x6e\x17https://www.example.com";
const third_response = "\x88\xc1\x61\x1dMon, 21 Oct 2013 20:13:22 GMT\xc0\x5a\x04gzip\x77\x38foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1";

test "RFC 7541 Appendix C.5: responses at capacity 256 evict as the table fills" {
    test_decoder.init(256);
    try expect_lines(first_response, &.{
        .{ .name = ":status", .value = "302" },
        .{ .name = "cache-control", .value = "private" },
        .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:21 GMT" },
        .{ .name = "location", .value = "https://www.example.com" },
    });
    try testing.expectEqual(222, test_decoder.table.size);
    try expect_lines("\x48\x03" ++ "307" ++ "\xc1\xc0\xbf", &.{
        .{ .name = ":status", .value = "307" },
        .{ .name = "cache-control", .value = "private" },
        .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:21 GMT" },
        .{ .name = "location", .value = "https://www.example.com" },
    });
    try testing.expectEqual(222, test_decoder.table.size);
    try expect_lines(third_response, &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "cache-control", .value = "private" },
        .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:22 GMT" },
        .{ .name = "location", .value = "https://www.example.com" },
        .{ .name = "content-encoding", .value = "gzip" },
        .{ .name = "set-cookie", .value = "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1" },
    });
    try testing.expectEqual(215, test_decoder.table.size);
    try testing.expectEqual(3, test_decoder.table.len());
}

test "RFC 7541 Appendix C.6: the Huffman-coded responses reach the same table" {
    test_decoder.init(256);
    try expect_lines("\x48\x82\x64\x02\x58\x85\xae\xc3\x77\x1a\x4b\x61\x96\xd0\x7a\xbe\x94\x10\x54\xd4\x44\xa8\x20\x05\x95\x04\x0b\x81\x66\xe0\x82\xa6\x2d\x1b\xff\x6e\x91\x9d\x29\xad\x17\x18\x63\xc7\x8f\x0b\x97\xc8\xe9\xae\x82\xae\x43\xd3", &.{
        .{ .name = ":status", .value = "302" },
        .{ .name = "cache-control", .value = "private" },
        .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:21 GMT" },
        .{ .name = "location", .value = "https://www.example.com" },
    });
    try expect_lines("\x48\x83\x64\x0e\xff\xc1\xc0\xbf", &.{
        .{ .name = ":status", .value = "307" },
        .{ .name = "cache-control", .value = "private" },
        .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:21 GMT" },
        .{ .name = "location", .value = "https://www.example.com" },
    });
    try expect_lines("\x88\xc1\x61\x96\xd0\x7a\xbe\x94\x10\x54\xd4\x44\xa8\x20\x05\x95\x04\x0b\x81\x66\xe0\x84\xa6\x2d\x1b\xff\xc0\x5a\x83\x9b\xd9\xab\x77\xad\x94\xe7\x82\x1d\xd7\xf2\xe6\xc7\xb3\x35\xdf\xdf\xcd\x5b\x39\x60\xd5\xaf\x27\x08\x7f\x36\x72\xc1\xab\x27\x0f\xb5\x29\x1f\x95\x87\x31\x60\x65\xc0\x03\xed\x4e\xe5\xb1\x06\x3d\x50\x07", &.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "cache-control", .value = "private" },
        .{ .name = "date", .value = "Mon, 21 Oct 2013 20:13:22 GMT" },
        .{ .name = "location", .value = "https://www.example.com" },
        .{ .name = "content-encoding", .value = "gzip" },
        .{ .name = "set-cookie", .value = "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1" },
    });
    try testing.expectEqual(215, test_decoder.table.size);
}
