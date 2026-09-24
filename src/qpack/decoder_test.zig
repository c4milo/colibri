//! The tests of `decoder.zig`, and RFC 9204 Appendix B's examples run through the whole decoder:
//! the field sections, the encoder stream and the decoder stream together.
const std = @import("std");
const core = @import("core");
const http = @import("http");
const constants = @import("constants.zig");
const decoder_module = @import("decoder.zig");
const encoder_module = @import("encoder.zig");
const representation_write = @import("representation_write.zig");
const instruction = @import("instruction.zig");

const testing = std.testing;
const Reader = core.Reader;
const Writer = core.Writer;
const FieldSection = http.field_section.FieldSection;
const Decoder = decoder_module.Decoder;
const Error = decoder_module.Error;
const Outcome = decoder_module.Outcome;

/// The decoder the tests drive, the section it fills, and room for what they write.
var test_decoder: Decoder = undefined;
var test_section: FieldSection = undefined;
const test_room: usize = 1024;
var test_strings: [test_room]u8 = undefined;
var test_octets: [test_room]u8 = undefined;

/// Appendix B's table capacity, and room for one blocked stream. Test-only.
const example_capacity: u64 = 220;
const example_blocked_streams: u64 = 1;
const example_settings: decoder_module.Settings = .{
    .max_table_capacity = example_capacity,
    .blocked_streams = example_blocked_streams,
};
/// Appendix B's request streams. Test-only.
const stream_four: u64 = 4;
const stream_eight: u64 = 8;

/// Decodes one field section from `stream_id` into `test_section`. Test-only.
fn decode_on(stream_id: u64, octets: []const u8) !Outcome {
    test_section.init();
    var reader = Reader.init(octets);
    var strings = Writer.init(&test_strings);
    const outcome = try test_decoder.read_section(stream_id, &reader, &strings, &test_section);
    // A section is consumed whole when it decodes, and not at all otherwise.
    const consumed: usize = if (outcome == .decoded) octets.len else 0;
    try testing.expectEqual(octets.len - consumed, reader.remaining_len());
    return outcome;
}

/// Decodes a section with a decoder that permits no dynamic table. Test-only.
fn decode(octets: []const u8) !void {
    test_decoder.init(.{});
    try testing.expectEqual(Outcome.decoded, try decode_on(0, octets));
}

fn encoder_stream(octets: []const u8) !void {
    var reader = Reader.init(octets);
    try test_decoder.read_encoder_stream(&reader);
    try testing.expectEqual(0, reader.remaining_len());
}

fn expect_decoder_stream(expected: []const u8) !void {
    var writer = Writer.init(&test_octets);
    test_decoder.write_decoder_stream(&writer);
    try testing.expectEqualSlices(u8, expected, writer.written());
}

fn expect_line(index: u32, name: []const u8, value: []const u8) !void {
    try testing.expectEqualStrings(name, test_section.get(index).name);
    try testing.expectEqualStrings(value, test_section.get(index).value);
}

test "B.1: the RFC's own field section decodes to the field line it names" {
    try decode(&([_]u8{ 0x00, 0x00, 0x51, 0x0b } ++ "/index.html".*));
    try testing.expectEqual(1, test_section.len());
    try expect_line(0, ":path", "/index.html");
}

test "B.2 to B.5: the RFC's examples, in order, through one decoder" {
    test_decoder.init(example_settings);
    // B.2: the capacity, then two inserts naming static entries 0 and 1.
    try encoder_stream(&([_]u8{ 0x3f, 0xbd, 0x01, 0xc0, 0x0f } ++ "www.example.com".* ++ [_]u8{ 0xc1, 0x0c } ++ "/sample/path".*));
    try testing.expectEqual(106, test_decoder.table.size);
    // Required Insert Count 2, Base 0, and two post-Base references.
    try testing.expectEqual(Outcome.decoded, try decode_on(stream_four, &.{ 0x03, 0x81, 0x10, 0x11 }));
    try expect_line(0, ":authority", "www.example.com");
    try expect_line(1, ":path", "/sample/path");
    // The acknowledgment raises the Known Received Count to 2, so no increment follows it.
    try expect_decoder_stream(&.{0x84});
    // B.3: an insert with a literal name, and the increment that reports it.
    try encoder_stream(&([_]u8{0x4a} ++ "custom-key".* ++ [_]u8{0x0c} ++ "custom-value".*));
    try testing.expectEqual(160, test_decoder.table.size);
    try expect_decoder_stream(&.{0x01});
    // B.4: the section on stream 8 arrives before the Duplicate it needs, so the stream blocks.
    const section_eight = [_]u8{ 0x05, 0x00, 0x80, 0xc1, 0x81 };
    try testing.expectEqual(Outcome.blocked, try decode_on(stream_eight, &section_eight));
    try testing.expectEqual(null, test_decoder.ready_stream());
    // The stream is cancelled before the Duplicate arrives.
    try testing.expectEqual(decoder_module.Abandoned.cancelled, test_decoder.abandon_stream(stream_eight));
    try testing.expectEqual(0, test_decoder.blocked_len);
    try expect_decoder_stream(&.{0x48});
    try encoder_stream(&.{0x02});
    try testing.expectEqual(217, test_decoder.table.size);
    // B.5: an insert naming dynamic relative 1, which evicts the oldest entry.
    try encoder_stream(&([_]u8{ 0x81, 0x0d } ++ "custom-value2".*));
    try testing.expectEqual(215, test_decoder.table.size);
    try testing.expectEqual(null, test_decoder.table.get_absolute(0));
    // The RFC stops here, and the two entries B.4 and B.5 added are still unreported.
    try expect_decoder_stream(&.{0x02});
}

test "§2.2.1: a blocked stream is decoded once the entries it needs arrive" {
    test_decoder.init(example_settings);
    try encoder_stream(&.{ 0x3f, 0xbd, 0x01 });
    // Required Insert Count 1, Base 1, relative index 0: the first entry, not yet inserted.
    const section = [_]u8{ 0x02, 0x00, 0x80 };
    try testing.expectEqual(Outcome.blocked, try decode_on(stream_four, &section));
    // Asking again before the entry arrives neither decodes nor counts the stream twice.
    try testing.expectEqual(Outcome.blocked, try decode_on(stream_four, &section));
    try testing.expectEqual(1, test_decoder.blocked_len);
    try testing.expectEqual(null, test_decoder.ready_stream());
    try encoder_stream(&.{ 0xc0, 0x01, 'a' });
    try testing.expectEqual(stream_four, test_decoder.ready_stream().?);
    try testing.expectEqual(Outcome.decoded, try decode_on(stream_four, &section));
    try expect_line(0, ":authority", "a");
    try testing.expectEqual(null, test_decoder.ready_stream());
    try testing.expectEqual(0, test_decoder.blocked_len);
}

test "§2.1.2: one blocked stream more than the decoder advertised fails the section" {
    test_decoder.init(example_settings);
    try encoder_stream(&.{ 0x3f, 0xbd, 0x01 });
    const section = [_]u8{ 0x02, 0x00, 0x80 };
    try testing.expectEqual(Outcome.blocked, try decode_on(stream_four, &section));
    try testing.expectError(Error.DecompressionFailed, decode_on(stream_eight, &section));
    // A decoder that advertised no blocked streams fails the first.
    test_decoder.init(.{ .max_table_capacity = example_capacity });
    try encoder_stream(&.{ 0x3f, 0xbd, 0x01 });
    try testing.expectError(Error.DecompressionFailed, decode_on(stream_four, &section));
}

test "§2.2.3: a reference at or above the Required Insert Count, or evicted, fails" {
    test_decoder.init(example_settings);
    try encoder_stream(&([_]u8{ 0x3f, 0xbd, 0x01, 0xc0, 0x01, 'a', 0xc0, 0x01, 'b' }));
    // Required Insert Count 1 and Base 1: relative 0 is absolute 0, and post-Base 0 is
    // absolute 1, at the Required Insert Count.
    try testing.expectEqual(Outcome.decoded, try decode_on(stream_four, &.{ 0x02, 0x00, 0x80 }));
    try testing.expectError(Error.DecompressionFailed, decode_on(stream_four, &.{ 0x02, 0x00, 0x10 }));
    // A relative index at or past the Base names no entry below it.
    try testing.expectError(Error.DecompressionFailed, decode_on(stream_four, &.{ 0x02, 0x00, 0x81 }));
    // Setting the capacity to 0 evicts both, so a reference to absolute 0 fails.
    try encoder_stream(&.{ 0x20, 0x3f, 0xbd, 0x01 });
    try testing.expectError(Error.DecompressionFailed, decode_on(stream_four, &.{ 0x02, 0x00, 0x80 }));
}

test "§2.2.1: a Required Insert Count larger than the references need is refused" {
    test_decoder.init(example_settings);
    try encoder_stream(&([_]u8{ 0x3f, 0xbd, 0x01, 0xc0, 0x01, 'a', 0xc0, 0x01, 'b' }));
    // Required Insert Count 2 and Base 1, but the only reference is absolute 0.
    try testing.expectError(Error.DecompressionFailed, decode_on(stream_four, &.{ 0x03, 0x80, 0x80 }));
    // Required Insert Count 2 with no dynamic reference at all.
    try testing.expectError(Error.DecompressionFailed, decode_on(stream_four, &.{ 0x03, 0x00, 0xd1 }));
}

test "§4.4.1: only a section with a non-zero Required Insert Count is acknowledged" {
    test_decoder.init(example_settings);
    try encoder_stream(&.{ 0x3f, 0xbd, 0x01 });
    try testing.expectEqual(Outcome.decoded, try decode_on(stream_four, &.{ 0x00, 0x00, 0xd1 }));
    try expect_decoder_stream(&.{});
}

test "decision 74: a full queue of owed instructions stops the reading until it is written" {
    test_decoder.init(example_settings);
    try encoder_stream(&.{ 0x3f, 0xbd, 0x01, 0xc0, 0x01, 'a' });
    const section = [_]u8{ 0x02, 0x00, 0x80 };
    for (0..constants.decoder_instructions_owed_max) |_| {
        try testing.expectEqual(Outcome.decoded, try decode_on(stream_four, &section));
    }
    try testing.expectEqual(Outcome.owes_instructions, try decode_on(stream_four, &section));
    try testing.expectEqual(decoder_module.Abandoned.owes_instructions, test_decoder.abandon_stream(stream_eight));
    var writer = Writer.init(&test_octets);
    test_decoder.write_decoder_stream(&writer);
    try testing.expectEqual(constants.decoder_instructions_owed_max, writer.written().len);
    try testing.expectEqual(Outcome.decoded, try decode_on(stream_four, &section));
}

test "§2.2.2.2: a decoder that permits no dynamic table owes no cancellation" {
    test_decoder.init(.{});
    try testing.expectEqual(decoder_module.Abandoned.cancelled, test_decoder.abandon_stream(stream_four));
    try expect_decoder_stream(&.{});
}

test "§7.4: a name or value longer than colibri accepts fails the section, not the process" {
    var octets: [test_room]u8 = undefined;
    // A literal name of field_name_len_max + 1 octets: 0x27 fills the 3-bit prefix with 7, and
    // 0xfa 0x01 add 122 and 128.
    const name_len = core.constants.field_name_len_max + 1;
    octets[0] = 0x00;
    octets[1] = 0x00;
    octets[2] = 0x27;
    octets[3] = 0xfa;
    octets[4] = 0x01;
    @memset(octets[5..][0..name_len], 'n');
    octets[5 + name_len] = 0x01;
    octets[6 + name_len] = 'v';
    try testing.expectError(Error.FieldTooLong, decode(octets[0 .. 7 + name_len]));
    // One octet shorter is accepted.
    octets[3] = 0xf9;
    octets[4 + name_len] = 0x01;
    octets[5 + name_len] = 'v';
    try decode(octets[0 .. 6 + name_len]);
    try testing.expectEqual(core.constants.field_name_len_max, test_section.get(0).name.len);
}

/// Room for a literal value one octet past `field_value_len_max`, and its framing. Test-only.
const long_value_room: usize = core.constants.field_value_len_max + test_room;
var long_octets: [long_value_room]u8 = undefined;
var long_strings: [long_value_room]u8 = undefined;

test "§7.4: a value longer than colibri accepts fails the section" {
    var writer = Writer.init(&long_octets);
    try writer.write_bytes(&.{ 0x00, 0x00 });
    // A literal with a name reference to static `:path`, and a value one octet too long.
    const value: [core.constants.field_value_len_max + 1]u8 = @splat('v');
    try representation_write.write(&writer, .{ .literal_name_reference = .{
        .never_indexed = false,
        .table = .static,
        .name_index = 1,
        .value = &value,
        .value_coding = .raw,
    } });
    test_decoder.init(.{});
    test_section.init();
    var reader = Reader.init(writer.written());
    var strings = Writer.init(&long_strings);
    try testing.expectError(Error.FieldTooLong, test_decoder.read_section(0, &reader, &strings, &test_section));
}

test "a line decoded from the dynamic table outlives the entry it came from" {
    // A table that holds one entry of a one-octet name and value.
    const one_entry: u64 = constants.entry_overhead_len + 2;
    test_decoder.init(.{ .max_table_capacity = one_entry, .blocked_streams = example_blocked_streams });
    var capacity: [test_room]u8 = undefined;
    var writer = Writer.init(&capacity);
    try instruction.write_encoder(&writer, .{ .set_capacity = one_entry });
    try encoder_stream(writer.written());
    try encoder_stream(&.{ 0x41, 'a', 0x01, 'x' });
    try testing.expectEqual(Outcome.decoded, try decode_on(stream_four, &.{ 0x02, 0x00, 0x80 }));
    // The next insert evicts `a` and writes `b` where its octets were.
    try encoder_stream(&.{ 0x41, 'b', 0x01, 'y' });
    try testing.expectEqualStrings("b", test_decoder.table.get_absolute(1).?.name);
    try expect_line(0, "a", "x");
}

test "§3.1: an indexed line resolves against Appendix A, and past its end is refused" {
    // 0xd1 is static index 17, Appendix A's `:method GET`; 0xd7 is 23, `:scheme https`.
    try decode(&.{ 0x00, 0x00, 0xd1, 0xd7 });
    try testing.expectEqual(2, test_section.len());
    try expect_line(0, ":method", "GET");
    // Entry 98 is the last, so 98 resolves and 99 does not.
    try decode(&.{ 0x00, 0x00, 0xff, 0x23 });
    try testing.expectEqualStrings("x-frame-options", test_section.get(0).name);
    try testing.expectError(Error.DecompressionFailed, decode(&.{ 0x00, 0x00, 0xff, 0x24 }));
}

test "§2.2.3: with no dynamic table, every dynamic reference is refused" {
    try testing.expectError(Error.DecompressionFailed, decode(&.{ 0x00, 0x00, 0x81 }));
    try testing.expectError(Error.DecompressionFailed, decode(&.{ 0x00, 0x00, 0x41, 0x01, 'a' }));
    try testing.expectError(Error.DecompressionFailed, decode(&.{ 0x00, 0x00, 0x11 }));
    try testing.expectError(Error.DecompressionFailed, decode(&.{ 0x00, 0x00, 0x01, 0x01, 'a' }));
    // A literal names no table at all, so it decodes.
    try decode(&.{ 0x00, 0x00, 0x23, 'a', 'b', 'c', 0x01, 'd' });
    try expect_line(0, "abc", "d");
}

test "§4.5.1: with no dynamic table, a prefix naming dynamic state is refused" {
    try testing.expectError(Error.DecompressionFailed, decode(&.{ 0x01, 0x00, 0xd1 }));
    // §4.5.1.2: a Sign bit of 1 with a Required Insert Count of zero puts the Base below zero.
    try testing.expectError(Error.DecompressionFailed, decode(&.{ 0x00, 0x80, 0xd1 }));
    // A Sign bit of 0 with any Delta Base is fine for a section with no dynamic reference.
    try decode(&.{ 0x00, 0x7f, 0x00, 0xd1 });
    try expect_line(0, ":method", "GET");
}

test "§6: an encoder stream failure has its own code, and every other failure one code" {
    try testing.expectEqual(constants.error_encoder_stream, decoder_module.error_code(Error.EncoderStreamError));
    try testing.expectEqual(constants.error_decompression_failed, decoder_module.error_code(Error.DecompressionFailed));
    try testing.expectEqual(constants.error_decompression_failed, decoder_module.error_code(Error.FieldTooLong));
    try testing.expectEqual(constants.error_decompression_failed, decoder_module.error_code(Error.Truncated));
    try testing.expectEqual(0x0200, constants.error_decompression_failed);
    try testing.expectEqual(0x0201, constants.error_encoder_stream);
}

test "what the encoder writes is what the decoder reads, coded and not" {
    for ([_]encoder_module.HuffmanUse{ .never, .always, .when_shorter }) |use| {
        var held: encoder_module.Encoder = undefined;
        held.init(use);
        var section: FieldSection = undefined;
        section.init();
        try section.append(":method", "GET");
        try section.append(":scheme", "https");
        try section.append(":path", "/index.html");
        try section.append("x-colibri", "a value that is long enough to be worth coding");
        var writer = Writer.init(&test_octets);
        try held.write_section(&writer, &section);
        try decode(writer.written());
        try testing.expectEqual(section.len(), test_section.len());
        var walk = section.iterator();
        var index: u32 = 0;
        // Bounded by the section, whose line count is a named limit of `http`.
        while (walk.next()) |line| : (index += 1) try expect_line(index, line.name, line.value);
    }
}

test "a field section cut short is refused rather than half accepted" {
    try decode(&.{ 0x00, 0x00 });
    try testing.expectEqual(0, test_section.len());
    test_decoder.init(.{});
    try testing.expectError(Error.Truncated, decode_on(0, &.{ 0x00, 0x00, 0xd1, 0x51 }));
    try testing.expectError(Error.Truncated, decode_on(0, &.{0x00}));
}
