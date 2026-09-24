//! The tests of `encoder.zig` and `encoder_plan.zig`: the static table first, then the dynamic
//! table's rules one at a time, and then round trips through colibri's decoder with the decoder
//! stream flowing back.
const std = @import("std");
const core = @import("core");
const http = @import("http");
const constants = @import("constants.zig");
const encoder_module = @import("encoder.zig");
const decoder_module = @import("decoder.zig");

const testing = std.testing;
const Reader = core.Reader;
const Writer = core.Writer;
const FieldSection = http.field_section.FieldSection;
const Encoder = encoder_module.Encoder;
const Indexing = encoder_module.Indexing;

/// The pair the tests drive, and room for what they write. Test-only.
var test_encoder: Encoder = undefined;
var test_decoder: decoder_module.Decoder = undefined;
var test_section: FieldSection = undefined;
var decoded_section: FieldSection = undefined;
const test_room: usize = 1024;
var section_octets: [test_room]u8 = undefined;
var stream_octets: [test_room]u8 = undefined;
var decoder_octets: [test_room]u8 = undefined;
var strings: [test_room]u8 = undefined;
/// What the last `write` wrote. Test-only.
var written_section: []const u8 = &.{};
var written_stream: []const u8 = &.{};

/// Appendix B's table capacity, which holds entries of up to 55 octets under decision 76.
const example_capacity: u64 = 220;
const stream_zero: u64 = 0;
const stream_four: u64 = 4;

/// One field line as the tests write it: a name and a value. Test-only.
const pair_len: usize = 2;
const Line = [pair_len][]const u8;
/// A static-only section's prefix, §4.5.1's two zero octets. Test-only.
const static_prefix_len: usize = 2;

/// Writes one section of the given lines, each with the same indexing. Test-only.
fn write(stream_id: u64, lines: []const Line, indexing: Indexing) !void {
    test_section.init();
    for (lines) |line| try test_section.append(line[0], line[1]);
    var choices: [core.constants.field_count_max]Indexing = undefined;
    @memset(choices[0..lines.len], indexing);
    var output = Writer.init(&section_octets);
    var encoder_stream = Writer.init(&stream_octets);
    try test_encoder.write_section(stream_id, &output, &encoder_stream, &test_section, choices[0..lines.len]);
    written_section = output.written();
    written_stream = encoder_stream.written();
}

/// Writes a one-line section with a static-only encoder, and returns the line's octets, past
/// the two-octet prefix. Test-only.
fn write_one(name: []const u8, value: []const u8, indexing: Indexing) ![]const u8 {
    try write(stream_zero, &.{.{ name, value }}, indexing);
    return written_section[static_prefix_len..];
}

/// An encoder and a decoder that agree on `settings`. Test-only.
fn start_pair(settings: decoder_module.Settings) void {
    test_encoder.init(.never);
    test_encoder.on_settings(.{ .max_table_capacity = settings.max_table_capacity, .blocked_streams = settings.blocked_streams });
    test_decoder.init(settings);
}

/// Hands the last write to the decoder, the encoder stream first, and requires the section it
/// decodes to be the one written. Test-only.
fn deliver(stream_id: u64) !void {
    var instructions = Reader.init(written_stream);
    try test_decoder.read_encoder_stream(&instructions);
    try testing.expectEqual(0, instructions.remaining_len());
    decoded_section.init();
    var reader = Reader.init(written_section);
    var writer = Writer.init(&strings);
    try testing.expectEqual(decoder_module.Outcome.decoded, try test_decoder.read_section(stream_id, &reader, &writer, &decoded_section));
    try testing.expectEqual(test_section.len(), decoded_section.len());
    for (0..test_section.len()) |index| {
        try testing.expectEqualStrings(test_section.get(@intCast(index)).name, decoded_section.get(@intCast(index)).name);
        try testing.expectEqualStrings(test_section.get(@intCast(index)).value, decoded_section.get(@intCast(index)).value);
    }
}

/// Carries what the decoder owes back to the encoder. Test-only.
fn acknowledge() !void {
    var writer = Writer.init(&decoder_octets);
    test_decoder.write_decoder_stream(&writer);
    var reader = Reader.init(writer.written());
    try test_encoder.read_decoder_stream(&reader);
}

test "B.1: the encoder produces the RFC's own octets for its own example" {
    test_encoder.init(.never);
    try write(stream_zero, &.{.{ ":path", "/index.html" }}, .may_insert);
    try testing.expectEqualSlices(u8, &([_]u8{ 0x00, 0x00, 0x51, 0x0b } ++ "/index.html".*), written_section);
}

test "§4.5.2: a line the static table holds whole is one octet" {
    test_encoder.init(.never);
    try testing.expectEqualSlices(u8, &.{0xd1}, try write_one(":method", "GET", .may_insert));
    try testing.expectEqualSlices(u8, &.{0xc1}, try write_one(":path", "/", .may_insert));
    try testing.expectEqualSlices(u8, &.{0xc0}, try write_one(":authority", "", .may_insert));
}

test "§4.5.4: a name the static table holds is a name reference, and the lowest is taken" {
    test_encoder.init(.never);
    // Appendix A holds `:method` at 15 through 21; a 4-bit prefix makes 15 `0x5f 0x00`.
    try testing.expectEqualSlices(u8, &([_]u8{ 0x5f, 0x00, 0x05 } ++ "PATCH".*), try write_one(":method", "PATCH", .may_insert));
    // A name the table does not hold is a literal on both halves: 0x27 fills the 3-bit prefix.
    const literal = try write_one("x-colibri", "1", .may_insert);
    try testing.expectEqual(0x27, literal[0]);
    try testing.expectEqual(0x02, literal[1]);
    try testing.expectEqualStrings("x-colibri", literal[2..11]);
}

test "§7.1.3: a never-indexed line is a literal carrying the N bit, and is not inserted" {
    start_pair(.{ .max_table_capacity = example_capacity, .blocked_streams = 1 });
    // `:method GET` is a whole static line, but the N bit exists only on a literal.
    const octets = try write_one(":method", "GET", .never_indexed);
    try testing.expectEqual(0x7f, octets[0]);
    try testing.expectEqualStrings("GET", octets[3..]);
    const both = try write_one("x-secret", "s", .never_indexed);
    try testing.expectEqual(0x37, both[0]);
    try testing.expectEqualStrings("x-secret", both[2..10]);
    try testing.expectEqual(0, written_stream.len);
    try testing.expectEqual(0, test_encoder.table.insert_count());
}

test "§7.2: a string is Huffman coded only where the coding is shorter" {
    test_encoder.init(.never);
    const raw_len = (try write_one("x-colibri", "aaaaaaaa", .may_insert)).len;
    test_encoder.init(.always);
    const coded = try write_one("x-colibri", "aaaaaaaa", .may_insert);
    try testing.expect(coded.len < raw_len);
    try testing.expect(coded[0] & 0x08 != 0);
    test_encoder.init(.when_shorter);
    try testing.expect((try write_one("x-colibri", "aaaaaaaa", .may_insert)).len < raw_len);
    const short = try write_one("x-colibri", "!", .may_insert);
    try testing.expectEqualStrings("!", short[short.len - 1 ..]);
}

test "§3.2.3: before the peer's settings the encoder inserts nothing and writes no encoder stream" {
    test_encoder.init(.never);
    try write(stream_zero, &.{.{ "x-a", "1" }}, .may_insert);
    try testing.expectEqual(0, written_stream.len);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x00 }, written_section[0..2]);
}

test "decision 76: an inserted line is referenced, after Set Dynamic Table Capacity" {
    start_pair(.{ .max_table_capacity = example_capacity, .blocked_streams = 1 });
    try write(stream_zero, &.{.{ "x-a", "1" }}, .may_insert);
    // 0x3f 0xbd 0x01 sets the capacity to 220 (§4.3.1), then 0x43 inserts the literal name.
    try testing.expectEqualSlices(u8, &([_]u8{ 0x3f, 0xbd, 0x01, 0x43 } ++ "x-a".* ++ [_]u8{ 0x01, '1' }), written_stream);
    // Required Insert Count 1 encodes as 2, the Base is 1, and relative 0 names the entry.
    try testing.expectEqualSlices(u8, &.{ 0x02, 0x00, 0x80 }, written_section);
    try deliver(stream_zero);
    // The capacity goes out once, and a line already in the table is not inserted again.
    try write(stream_four, &.{ .{ "x-a", "1" }, .{ "x-b", "2" } }, .may_insert);
    try testing.expectEqualSlices(u8, &([_]u8{0x43} ++ "x-b".* ++ [_]u8{ 0x01, '2' }), written_stream);
    try testing.expectEqual(2, test_encoder.table.insert_count());
}

test "§2.1.2: a stream that may not block inserts the line but writes it as a literal" {
    start_pair(.{ .max_table_capacity = example_capacity });
    try write(stream_zero, &.{.{ "x-a", "1" }}, .may_insert);
    try testing.expectEqual(1, test_encoder.table.insert_count());
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x00 }, written_section[0..2]);
    try deliver(stream_zero);
    // Until the decoder's increment arrives the entry is not referenced, and not inserted twice.
    try write(stream_four, &.{.{ "x-a", "1" }}, .may_insert);
    try testing.expectEqual(0, written_stream.len);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x00 }, written_section[0..2]);
    try deliver(stream_four);
    try acknowledge();
    try testing.expectEqual(1, test_encoder.state.known_received);
    // Acknowledged, it is referenced, and the section still cannot block.
    try write(stream_zero, &.{.{ "x-a", "1" }}, .may_insert);
    try testing.expectEqualSlices(u8, &.{ 0x02, 0x00, 0x80 }, written_section);
    try deliver(stream_zero);
}

test "§2.1.2: past the peer's blocked-stream limit, a section references only acknowledged entries" {
    start_pair(.{ .max_table_capacity = example_capacity, .blocked_streams = 1 });
    try write(stream_zero, &.{.{ "x-a", "1" }}, .may_insert);
    try testing.expectEqual(1, test_encoder.state.blocked_count());
    // Stream 0 could block, so stream 4 may not: its new line is a literal, and stream 0's
    // unacknowledged entry is not referenced either.
    try write(stream_four, &.{ .{ "x-a", "1" }, .{ "x-b", "2" } }, .may_insert);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x00 }, written_section[0..2]);
    try testing.expectEqual(2, test_encoder.table.insert_count());
}

test "decision 76: no_insert references what the table holds and inserts nothing" {
    start_pair(.{ .max_table_capacity = example_capacity, .blocked_streams = 1 });
    try write(stream_zero, &.{.{ "x-a", "1" }}, .may_insert);
    try deliver(stream_zero);
    try acknowledge();
    try write(stream_four, &.{ .{ "x-a", "1" }, .{ "x-b", "2" } }, .no_insert);
    try testing.expectEqual(0, written_stream.len);
    try testing.expectEqual(1, test_encoder.table.insert_count());
    try testing.expectEqualSlices(u8, &.{ 0x02, 0x00, 0x80 }, written_section[0..3]);
    try deliver(stream_four);
}

test "decision 76: an entry larger than a quarter of the capacity is not inserted" {
    start_pair(.{ .max_table_capacity = example_capacity, .blocked_streams = 1 });
    // 32 octets of overhead, 3 of name and 20 of value make 55, a quarter of 220; one more is not.
    try write(stream_zero, &.{.{ "x-a", "aaaaaaaaaaaaaaaaaaaaa" }}, .may_insert);
    try testing.expectEqual(0, test_encoder.table.insert_count());
    try write(stream_zero, &.{.{ "x-a", "aaaaaaaaaaaaaaaaaaaa" }}, .may_insert);
    try testing.expectEqual(1, test_encoder.table.insert_count());
}

test "§2.1.3: an insert the encoder stream's credit cannot hold is not made" {
    start_pair(.{ .max_table_capacity = example_capacity, .blocked_streams = 1 });
    test_section.init();
    try test_section.append("x-a", "1");
    var output = Writer.init(&section_octets);
    // Room for Set Dynamic Table Capacity but not for the insert behind it.
    var encoder_stream = Writer.init(stream_octets[0..4]);
    try test_encoder.write_section(stream_zero, &output, &encoder_stream, &test_section, &.{});
    try testing.expectEqual(0, encoder_stream.written().len);
    try testing.expectEqual(0, test_encoder.table.insert_count());
    try testing.expect(!test_encoder.capacity_sent);
}

test "§2.1.1: an insert never evicts an entry the decoder has not acknowledged or still needs" {
    start_pair(.{ .max_table_capacity = example_capacity, .blocked_streams = 1 });
    // Four entries of 52 octets fill 208 of 220.
    const lines = [_]Line{ .{ "x-a", "11111111111111111" }, .{ "x-b", "22222222222222222" }, .{ "x-c", "33333333333333333" }, .{ "x-d", "44444444444444444" } };
    try write(stream_zero, &lines, .may_insert);
    try deliver(stream_zero);
    try testing.expectEqual(4, test_encoder.table.insert_count());
    // A fifth needs entry 0 evicted, and entry 0 is referenced by an unacknowledged section.
    try write(stream_four, &.{.{ "x-e", "55555555555555555" }}, .may_insert);
    try testing.expectEqual(4, test_encoder.table.insert_count());
    try deliver(stream_four);
    // Acknowledged, and referenced by nothing outstanding, entry 0 may go.
    try acknowledge();
    try write(stream_four, &.{.{ "x-e", "55555555555555555" }}, .may_insert);
    try testing.expectEqual(5, test_encoder.table.insert_count());
    try testing.expectEqual(null, test_encoder.table.get_absolute(0));
    try deliver(stream_four);
    // A section that references entry 1 keeps it: the next insert would evict it, so it waits.
    try acknowledge();
    try write(stream_zero, &.{.{ "x-b", "22222222222222222" }}, .may_insert);
    try write(stream_four, &.{.{ "x-f", "66666666666666666" }}, .may_insert);
    try testing.expectEqual(5, test_encoder.table.insert_count());
}

test "§4.4: the decoder stream is checked, and a partial instruction waits" {
    start_pair(.{ .max_table_capacity = example_capacity, .blocked_streams = 1 });
    // §4.4.1: an acknowledgment for a stream with nothing outstanding.
    var unknown = Reader.init(&.{0x84});
    try testing.expectError(error.DecoderStreamError, test_encoder.read_decoder_stream(&unknown));
    // §4.4.3: an Increment of zero, and one past what the encoder inserted.
    var zero = Reader.init(&.{0x00});
    try testing.expectError(error.DecoderStreamError, test_encoder.read_decoder_stream(&zero));
    var past = Reader.init(&.{0x01});
    try testing.expectError(error.DecoderStreamError, test_encoder.read_decoder_stream(&past));
    // A Section Acknowledgment whose stream ID has not all arrived stays unread.
    var partial = Reader.init(&.{0xff});
    try test_encoder.read_decoder_stream(&partial);
    try testing.expectEqual(1, partial.remaining_len());
}

test "a section that does not fit writes nothing, and its inserts are still owed" {
    start_pair(.{ .max_table_capacity = example_capacity, .blocked_streams = 1 });
    test_section.init();
    try test_section.append("x-a", "1");
    var tight = Writer.init(section_octets[0..2]);
    var encoder_stream = Writer.init(&stream_octets);
    try testing.expectError(error.NoSpaceLeft, test_encoder.write_section(stream_zero, &tight, &encoder_stream, &test_section, &.{}));
    try testing.expectEqual(0, tight.written().len);
    try testing.expect(encoder_stream.written().len > 0);
    try testing.expectEqual(0, test_encoder.state.len);
}

test "colibri's bound on outstanding sections: past it a section references nothing dynamic" {
    start_pair(.{ .max_table_capacity = example_capacity, .blocked_streams = constants.blocked_streams_max });
    try write(stream_zero, &.{.{ "x-a", "1" }}, .may_insert);
    for (0..constants.outstanding_sections_max - 1) |step| try write(step + 1, &.{.{ "x-a", "1" }}, .may_insert);
    try testing.expectEqual(constants.outstanding_sections_max, test_encoder.state.len);
    try write(stream_zero, &.{.{ "x-a", "1" }}, .may_insert);
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x00 }, written_section[0..2]);
}

test "sections round trip through the decoder, with its acknowledgments flowing back" {
    start_pair(.{ .max_table_capacity = example_capacity, .blocked_streams = 1 });
    const request = [_]Line{ .{ ":method", "GET" }, .{ ":authority", "www.example.com" }, .{ ":path", "/sample/path" }, .{ "custom-key", "custom-value" } };
    var sizes: [3]usize = undefined;
    for (&sizes, 0..) |*size, index| {
        try write(index * stream_four, &request, .may_insert);
        size.* = written_section.len + written_stream.len;
        try deliver(index * stream_four);
        try acknowledge();
    }
    // The first section's encoder stream carries the values, and the next sections reference
    // them and write no encoder stream at all.
    try testing.expect(sizes[1] < sizes[0]);
    try testing.expectEqual(sizes[1], sizes[2]);
    try testing.expectEqual(0, test_encoder.state.len);
    try testing.expectEqual(test_encoder.table.insert_count(), test_encoder.state.known_received);
}

/// Four entries of 52 octets, which fill 208 of `example_capacity`. Test-only.
const four_entries = [_]Line{ .{ "x-a", "11111111111111111" }, .{ "x-b", "22222222222222222" }, .{ "x-c", "33333333333333333" }, .{ "x-d", "44444444444444444" } };

test "decision 76: a static name is referenced rather than a dynamic one" {
    start_pair(.{ .max_table_capacity = example_capacity, .blocked_streams = 1 });
    try write(stream_zero, &.{.{ ":authority", "a.example" }}, .may_insert);
    try testing.expectEqual(1, test_encoder.table.insert_count());
    try deliver(stream_zero);
    try acknowledge();
    // The dynamic table holds `:authority` too, but static entry 0 is the one named.
    const octets = try write_one(":authority", "other.example", .no_insert);
    try testing.expectEqual(0x50, octets[0]);
}

test "decision 76: a name the line's own insert evicted is not referenced" {
    start_pair(.{ .max_table_capacity = example_capacity });
    try write(stream_zero, &four_entries, .may_insert);
    try deliver(stream_zero);
    try acknowledge();
    // A new value for `x-a` evicts entry 0, the only other `x-a`. The stream may not block, so
    // the line is a literal, and it cannot name the entry just evicted.
    try write(stream_four, &.{.{ "x-a", "55555555555555555" }}, .may_insert);
    try testing.expectEqual(null, test_encoder.table.get_absolute(0));
    try deliver(stream_four);
}

test "§2.1.1: an insert never evicts an entry the same section references" {
    start_pair(.{ .max_table_capacity = example_capacity, .blocked_streams = 1 });
    try write(stream_zero, &four_entries, .may_insert);
    try deliver(stream_zero);
    try acknowledge();
    // The section references entry 0 first, so its second line may not evict entry 0.
    try write(stream_four, &.{ four_entries[0], .{ "x-e", "55555555555555555" } }, .may_insert);
    try testing.expectEqual(4, test_encoder.table.insert_count());
    try deliver(stream_four);
}

test "§4.5.1.1: the Required Insert Count is encoded against the peer's maximum, not colibri's" {
    // A peer maximum of 32,768 gives MaxEntries 1,024 and a full range of 2,048, where colibri's
    // own 16,384 would give 1,024.
    test_encoder.init(.never);
    test_encoder.on_settings(.{ .max_table_capacity = 2 * constants.dynamic_table_capacity_max, .blocked_streams = 1 });
    try testing.expectEqual(constants.dynamic_table_capacity_max, test_encoder.capacity());
    var value: [8]u8 = undefined;
    // Bounded: one insert per section, each acknowledged at once.
    for (0..insert_count_past_range) |step| {
        const text = try std.fmt.bufPrint(&value, "{d}", .{step});
        try write(stream_zero, &.{.{ "x-n", text }}, .may_insert);
        var acknowledgment = Reader.init(&.{0x80});
        try test_encoder.read_decoder_stream(&acknowledgment);
    }
    // The last section's Required Insert Count is 1,025: encoded against 2,048 it is 1,026,
    // which an 8-bit prefix writes as 0xff 0x83 0x06. Against 1,024 it would be 2.
    try testing.expectEqualSlices(u8, &.{ 0xff, 0x83, 0x06 }, written_section[0..3]);
}

/// One more insert than the full range colibri's own capacity would give. Test-only.
const insert_count_past_range: usize = 1025;

test "§2.1.1: an entry is not evicted before its insertion is acknowledged, referenced or not" {
    // With no blocked streams the four inserts are speculative: nothing references them.
    start_pair(.{ .max_table_capacity = example_capacity });
    try write(stream_zero, &four_entries, .may_insert);
    try testing.expectEqual(4, test_encoder.table.insert_count());
    try testing.expectEqual(null, test_encoder.state.referenced_floor());
    try deliver(stream_zero);
    // A fifth needs entry 0 evicted, which the decoder has not acknowledged.
    try write(stream_four, &.{.{ "x-e", "55555555555555555" }}, .may_insert);
    try testing.expectEqual(4, test_encoder.table.insert_count());
    try deliver(stream_four);
    try acknowledge();
    try write(stream_four, &.{.{ "x-e", "55555555555555555" }}, .may_insert);
    try testing.expectEqual(5, test_encoder.table.insert_count());
}
