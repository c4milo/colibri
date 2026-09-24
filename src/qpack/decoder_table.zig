//! The decoder's side of the encoder stream (RFC 9204 §4.3): each instruction the encoder sends,
//! applied to the decoder's dynamic table. Part of design §8 step 11.
//!
//! Every failure here is RFC 9204 §6's QPACK_ENCODER_STREAM_ERROR, a connection error: the table
//! the encoder describes and the one the decoder holds would no longer agree. An instruction cut
//! short is not a failure. It stays unread, and the caller presents it again with more octets,
//! up to `encoder_instruction_len_max` (decision 74).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("constants.zig");
const instruction = @import("instruction.zig");
const static_table = @import("static_table.zig");
const decoder_module = @import("decoder.zig");

const Reader = core.Reader;
const Writer = core.Writer;
const Decoder = decoder_module.Decoder;
const Error = decoder_module.Error;

/// Applies every whole instruction in `reader`, and leaves a partial one unread.
pub fn read(decoder: *Decoder, reader: *Reader) Error!void {
    // Bounded by the octets the caller gave, since every instruction consumes at least one.
    while (reader.remaining_len() > 0) {
        var strings = Writer.init(&decoder.scratch);
        const held = instruction.read_encoder(reader, &strings) catch |failure| switch (failure) {
            error.Truncated => {
                // RFC 9204 §7.4: an implementation sets a limit on what it accepts, and one
                // encoder instruction this long never completes within colibri's.
                if (reader.remaining_len() >= constants.encoder_instruction_len_max) return Error.EncoderStreamError;
                return;
            },
            // A string that does not decode, or decodes past the scratch, which is as large as
            // the largest table, so the entry could never fit.
            else => return Error.EncoderStreamError,
        };
        try apply(decoder, held, &strings);
    }
}

fn apply(decoder: *Decoder, held: instruction.Encoder, strings: *Writer) Error!void {
    const table = &decoder.table;
    switch (held) {
        // RFC 9204 §4.3.1: a capacity above the limit the decoder advertised is
        // QPACK_ENCODER_STREAM_ERROR.
        .set_capacity => |capacity| table.set_capacity(capacity) catch return Error.EncoderStreamError,
        .insert_name_reference => |insert| {
            const name = try referenced_name(decoder, insert, strings);
            try insert_entry(decoder, name, insert.value);
        },
        .insert_literal => |insert| try insert_entry(decoder, insert.name, insert.value),
        .duplicate => |relative| {
            // RFC 9204 §2.2.3: a reference in an encoder instruction to an entry already
            // evicted is QPACK_ENCODER_STREAM_ERROR, and one never inserted names nothing.
            const entry = table.get_relative_to_insertion(relative) orelse return Error.EncoderStreamError;
            // §3.2.2: the insert may evict the entry it copies, so its octets move out first.
            const name = copy(strings, entry.name) catch return Error.EncoderStreamError;
            const value = copy(strings, entry.value) catch return Error.EncoderStreamError;
            try insert_entry(decoder, name, value);
        },
    }
}

/// The name an Insert with Name Reference names (RFC 9204 §4.3.2), somewhere the insert cannot
/// overwrite.
fn referenced_name(decoder: *Decoder, insert: instruction.Encoder.InsertNameReference, strings: *Writer) Error![]const u8 {
    if (insert.table == .static) {
        // RFC 9204 §3.1: an invalid static table index received on the encoder stream is
        // QPACK_ENCODER_STREAM_ERROR.
        if (insert.name_index >= constants.static_table_entries) return Error.EncoderStreamError;
        return static_table.entries[@intCast(insert.name_index)].name;
    }
    // RFC 9204 §2.2.3: a reference to an entry already evicted is QPACK_ENCODER_STREAM_ERROR.
    const entry = decoder.table.get_relative_to_insertion(insert.name_index) orelse return Error.EncoderStreamError;
    // §3.2.2: "A new entry can reference an entry in the dynamic table that will be evicted when
    // adding this new entry", so the name is copied before the insert evicts it.
    return copy(strings, entry.name) catch Error.EncoderStreamError;
}

fn insert_entry(decoder: *Decoder, name: []const u8, value: []const u8) Error!void {
    // RFC 9204 §3.2.2: an entry larger than the capacity is QPACK_ENCODER_STREAM_ERROR.
    decoder.table.insert(name, value) catch return Error.EncoderStreamError;
    assert(decoder.table.size <= decoder.table.capacity);
}

fn copy(strings: *Writer, octets: []const u8) core.writer.Error![]const u8 {
    const start = strings.written().len;
    try strings.write_bytes(octets);
    return strings.written()[start..];
}

const testing = std.testing;

/// A table that holds two entries of a one-octet name and a one-octet value, each §3.2.1's
/// 32-octet overhead and two octets. Test-only.
const small_entries: u64 = 2;
const small_line_len: u64 = 2;
const small_capacity: u64 = small_entries * (constants.entry_overhead_len + small_line_len);

/// The decoder the tests drive, placed outside any stack frame. Test-only.
var test_decoder: Decoder = undefined;
/// Room for the tests' encoded instructions. Test-only.
const test_room: usize = 256;

/// Reads `octets` as encoder stream octets, and returns how many stayed unread. Test-only.
fn feed(octets: []const u8) Error!usize {
    var reader = Reader.init(octets);
    try read(&test_decoder, &reader);
    return reader.remaining_len();
}

/// A decoder that permits a table of `capacity` octets, with the table set to all of it.
/// Test-only.
fn use_capacity(capacity: u64) !void {
    test_decoder.init(.{ .max_table_capacity = capacity });
    var octets: [test_room]u8 = undefined;
    var writer = Writer.init(&octets);
    try instruction.write_encoder(&writer, .{ .set_capacity = capacity });
    try testing.expectEqual(0, try feed(writer.written()));
}

fn expect_entry(absolute: u64, name: []const u8, value: []const u8) !void {
    const entry = test_decoder.table.get_absolute(absolute).?;
    try testing.expectEqualStrings(name, entry.name);
    try testing.expectEqualStrings(value, entry.value);
}

test "§4.3.1: a capacity above what the decoder advertised is an encoder stream error" {
    test_decoder.init(.{ .max_table_capacity = 220 });
    // 0x3f 0xbd 0x01 is Set Dynamic Table Capacity 220, Appendix B.2's first instruction.
    try testing.expectEqual(0, try feed(&.{ 0x3f, 0xbd, 0x01 }));
    try testing.expectEqual(220, test_decoder.table.capacity);
    // 221 is one past the limit.
    try testing.expectError(Error.EncoderStreamError, feed(&.{ 0x3f, 0xbe, 0x01 }));
    // With no dynamic table permitted, only a capacity of zero is below the limit.
    test_decoder.init(.{});
    try testing.expectEqual(0, try feed(&.{0x20}));
    try testing.expectError(Error.EncoderStreamError, feed(&.{0x21}));
}

test "§3.1: an insert naming a static index past Appendix A is an encoder stream error" {
    try use_capacity(220);
    // 0xff fills the 6-bit prefix with 63 and 0x23 adds 35: static index 98, the last, then the
    // value "v". 0x24 would add 36, one past the end.
    try testing.expectEqual(0, try feed(&.{ 0xff, 0x23, 0x01, 'v' }));
    try expect_entry(0, "x-frame-options", "v");
    try testing.expectError(Error.EncoderStreamError, feed(&.{ 0xff, 0x24, 0x01, 'v' }));
}

test "§2.2.3: an instruction naming an entry never inserted, or evicted, is refused" {
    try use_capacity(small_capacity);
    // Duplicate and a dynamic name reference, relative index 0, with an empty table.
    try testing.expectError(Error.EncoderStreamError, feed(&.{0x00}));
    try testing.expectError(Error.EncoderStreamError, feed(&.{ 0x80, 0x01, 'v' }));
    // Two literal inserts fill the small table, and relative 1 names the older one.
    try testing.expectEqual(0, try feed(&.{ 0x41, 'a', 0x01, 'x', 0x41, 'b', 0x01, 'y' }));
    try testing.expectEqual(0, try feed(&.{0x01}));
    try expect_entry(2, "a", "x");
    // The duplicate evicted absolute 0, so relative 2 names no live entry.
    try testing.expectError(Error.EncoderStreamError, feed(&.{0x02}));
}

test "§3.2.2: an insert that evicts the entry it names still copies its name" {
    try use_capacity(small_capacity);
    try testing.expectEqual(0, try feed(&.{ 0x41, 'a', 0x01, 'x', 0x41, 'b', 0x01, 'y' }));
    // A name reference to relative 1, absolute 0, evicts absolute 0 to make room for itself.
    try testing.expectEqual(0, try feed(&.{ 0x81, 0x01, 'z' }));
    try testing.expect(test_decoder.table.get_absolute(0) == null);
    try expect_entry(2, "a", "z");
    // A duplicate of the oldest entry does the same.
    try testing.expectEqual(0, try feed(&.{0x01}));
    try testing.expect(test_decoder.table.get_absolute(1) == null);
    try expect_entry(3, "b", "y");
}

test "§3.2.2: copying the only entry of a full table evicts it first and still copies it" {
    // A table that holds one entry of a one-octet name and value.
    try use_capacity(constants.entry_overhead_len + small_line_len);
    try testing.expectEqual(0, try feed(&.{ 0x41, 'a', 0x01, 'x' }));
    // A Duplicate of relative 0, then a name reference to it: each evicts the entry it copies.
    try testing.expectEqual(0, try feed(&.{0x00}));
    try expect_entry(1, "a", "x");
    try testing.expectEqual(0, try feed(&.{ 0x80, 0x01, 'z' }));
    try expect_entry(2, "a", "z");
    try testing.expectEqual(1, test_decoder.table.count);
}

test "§3.2.2: an entry larger than the capacity is an encoder stream error" {
    try use_capacity(small_capacity);
    var octets: [test_room]u8 = undefined;
    var writer = Writer.init(&octets);
    const long: [small_capacity]u8 = @splat('v');
    try instruction.write_encoder(&writer, .{ .insert_literal = .{ .name = "n", .name_coding = .raw, .value = &long, .value_coding = .raw } });
    try testing.expectError(Error.EncoderStreamError, feed(writer.written()));
}

test "decision 74: a partial instruction stays unread, and one too long to wait for is refused" {
    try use_capacity(220);
    // An Insert with Literal Name whose value has not arrived: all five octets stay unread.
    try testing.expectEqual(5, try feed(&.{ 0x41, 'a', 0x03, 'x', 'y' }));
    try testing.expectEqual(0, test_decoder.table.insert_count());
    // RFC 9204 §7.4: an instruction the limit cannot hold is refused once the limit's worth of
    // octets has arrived without it completing.
    var octets: [constants.encoder_instruction_len_max]u8 = @splat('x');
    // A literal name of 16,385 octets: 0x5f fills the 5-bit prefix with 31, and 0xe2 0x7f add
    // 98 and 127 * 128.
    octets[0] = 0x5f;
    octets[1] = 0xe2;
    octets[2] = 0x7f;
    try testing.expectError(Error.EncoderStreamError, feed(&octets));
    try testing.expectEqual(constants.encoder_instruction_len_max - 1, try feed(octets[0 .. octets.len - 1]));
}

test "a string that is not valid Huffman is an encoder stream error" {
    try use_capacity(220);
    // An Insert with Literal Name, Huffman flag set, one octet of all ones: RFC 7541 §5.2 refuses
    // padding longer than seven bits.
    try testing.expectError(Error.EncoderStreamError, feed(&.{ 0x61, 0xff, 0x01, 'x' }));
}
