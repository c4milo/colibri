//! The decode step of the field-block slot, split off field_block.zig for length: one call runs
//! hpack's block reader over a fragment where it lies, or over the buffer that finishes a line the
//! last fragment cut, measures and stores or discards each line, and the octets the reader could
//! not finish are copied into the buffer (decision 40 as amended, design §8 step 61a).
//! field_block.zig's header lists the slot's check order, and the tests of the decoding refusals are
//! here, beside the code that refuses.
//!
//! The block reader counts the field lines and size updates it has read, and RFC 7541 §4.2
//! places a size update before every field line of a block: the whole block, not one fragment.
//! `decode_slice` carries both counts from one fragment to the next, whether the fragment ends
//! between representations or inside one, so a size update that opens a CONTINUATION frame after
//! a field line is refused as it would be in one frame (RFC 9113 §4.3: a field block is logically
//! equivalent to a single frame).
//!
//! A section that refuses a line does not stop the decoding: `too_large` is set, every later
//! octet still goes through the decoder, and its lines are discarded, so the dynamic table stays
//! synchronized with the peer's (invariant 10, RFC 9113 §10.5.1).
//!
//! The lines are stored without validation, which departs from `FieldSection.append`'s documented
//! contract that the caller validated each name and value first. The validation is the
//! connection's, on the section after `Done` and before any line is interpreted (invariant 7): a
//! malformed line is a stream error (RFC 9113 §8.1.1), and this slot names connection errors only.
//! The two assertions `append` makes hold without it, because the decoder refuses a name or a value
//! past core's field-length limits, and the comptime block below pins that.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const hpack = @import("hpack");
const wire = @import("wire");
const constants = @import("../constants.zig");
const field_block = @import("field_block.zig");
const field_block_limit = @import("field_block_limit.zig");

const FieldBlock = field_block.FieldBlock;
const Error = field_block.Error;

comptime {
    // A decoded name or value fits the lengths `FieldSection.append` asserts.
    assert(hpack.constants.limits.name_len_max <= core.constants.limits.field_name_len_max);
    assert(hpack.constants.limits.value_len_max <= core.constants.limits.field_value_len_max);
}

/// The longest run of octets one call decodes: a fragment, or the buffer.
const decoded_len_max = @max(constants.limits.frame_size_max, constants.limits.field_block_buffer_len);

/// Decodes every whole representation of `octets`, the block's octets after those decoded so far,
/// counts them as decoded, and returns how many they were.
pub fn decode_slice(block: *FieldBlock, decoder: *hpack.Decoder, octets: []const u8) Error!usize {
    assert(block.is_in_progress());
    assert(octets.len <= decoded_len_max);
    var walk = decoder.block(octets);
    walk.fields = block.lines_decoded;
    walk.updates = block.size_updates;
    // A run of n octets holds at most n representations, and one more call finds the end.
    for (0..decoded_len_max + 1) |_| {
        const line = walk.next() catch |failure| {
            if (failure == error.Truncated) break;
            // RFC 9113 §4.3: a decoding error in a field block is a connection error of type
            // COMPRESSION_ERROR.
            return error.DecodeFailed;
        };
        const field_line = line orelse break;
        field_block_limit.record_line_end(block, block.octets_decoded + walk.consumed_len());
        store(block, field_line);
    } else unreachable; // Each line takes at least one octet, so the buffer ends first.
    block.lines_decoded = walk.fields;
    block.size_updates = walk.updates;
    assert(walk.consumed_len() <= octets.len);
    block.octets_decoded += walk.consumed_len();
    return walk.consumed_len();
}

/// The runs one call of `decode_fragment` decodes, at most: the buffer that finishes a line the
/// last fragment cut, then the rest of the fragment where it lies.
const runs_max = 2;

/// Decodes `fragment`. If the last fragment cut a line, the fragment's first octets are appended to
/// it, at most up to `representation_len_max`, and the buffer is decoded first. The rest of the
/// fragment is decoded where it lies, and the line it cuts is copied into the buffer. One call
/// site of `decode_slice` serves both runs, so the compiler keeps one copy of the decoding loop.
pub fn decode_fragment(block: *FieldBlock, decoder: *hpack.Decoder, fragment: []const u8) Error!void {
    const kept: usize = block.buffer_len;
    var in_buffer = kept > 0;
    const taken = if (in_buffer) @min(fragment.len, constants.limits.representation_len_max - kept) else 0;
    if (taken > 0) block.append(fragment[0..taken]);
    var octets: []const u8 = if (in_buffer) block.buffer[0..block.buffer_len] else fragment;
    for (0..runs_max) |_| {
        const consumed = try decode_slice(block, decoder, octets);
        if (!in_buffer) return keep(block, octets[consumed..]);
        if (consumed == 0) {
            // RFC 7541 §7.4: the cut line's octets fed so far are past the longest line accepted.
            if (taken < fragment.len) return error.RepresentationTooLong;
            // The line is still cut, and the buffer keeps every octet of the fragment with it.
            assert(block.octets_decoded + block.buffer_len == block.octets_fed);
            return;
        }
        // The cut line came first in the buffer, so the reader took all of it before anything else.
        assert(consumed >= kept);
        block.buffer_len = 0;
        octets = fragment[consumed - kept ..];
        in_buffer = false;
    } else unreachable; // The second run decodes in place, and returns.
}

comptime {
    // A tail is part of one fragment, so the buffer always holds it. `measure_cut_line` refuses a
    // cut line that grows past the longest line across fragments.
    assert(constants.limits.frame_size_max <= constants.limits.field_block_buffer_len);
}

/// Copies `tail`, the representation the fragment cut, into the buffer.
pub fn keep(block: *FieldBlock, tail: []const u8) void {
    assert(block.buffer_len == 0);
    assert(tail.len <= constants.limits.frame_size_max);
    block.append(tail);
    // Invariant 10: every octet fed was consumed by the decoder or is kept for the next fragment.
    assert(block.octets_decoded + block.buffer_len == block.octets_fed);
}

/// Stores one decoded line, or discards it once the section has refused one. The file's header
/// says why the line is not validated first.
fn store(block: *FieldBlock, line: hpack.FieldLine) void {
    if (block.too_large) return;
    block.section.append(line.name, line.value) catch {
        // RFC 9113 §10.5.1: the field block MUST be processed to keep the connection state
        // consistent, so the refusal is noted and the decoding goes on (invariant 10).
        block.too_large = true;
    };
}

const testing = std.testing;
const Writer = core.Writer;
const support = @import("field_block_test_support.zig");
const test_block = &support.test_block;
const test_decoder = &support.test_decoder;
const test_encoder = &support.test_encoder;
const long_value = support.long_value;
const request_raw = support.request_raw;
const request_lines = support.request_lines;
const start = support.start;
const expect_section = support.expect_section;
const expect_done = support.expect_done;
const expect_cleared = support.expect_cleared;

test "a representation cut by a fragment is kept as the tail, at the front, and decoded whole later" {
    start(1, .headers, false);
    try testing.expectEqual(null, try test_block.feed(test_decoder, request_raw[0..10], false));
    try testing.expectEqual(3, test_block.section.len());
    try testing.expectEqual(7, test_block.buffer_len);
    try testing.expectEqualStrings(request_raw[3..10], test_block.buffer[0..7]);
    try testing.expectEqual(0, test_decoder.table.len());
    const done = try test_block.feed(test_decoder, request_raw[10..], true);
    try expect_done(done, .{ .stream_id = 1, .origin = .headers, .end_stream = false, .too_large = false });
    try expect_section(&request_lines);
    try testing.expectEqual(1, test_decoder.table.len());
}

test "one literal cut twice, in its name and in its value, decodes once whole and is inserted once" {
    start(1, .headers, false);
    test_encoder.init(constants.protocol.header_table_size_initial, .never);
    var output = Writer.init(&support.test_frame);
    try test_encoder.write_field(&output, "custom-key", long_value[0..300], .incremental);
    const literal = output.written();
    try testing.expectEqual(null, try test_block.feed(test_decoder, literal[0..5], false));
    try testing.expectEqual(5, test_block.buffer_len);
    try testing.expectEqual(null, try test_block.feed(test_decoder, literal[5..100], false));
    try testing.expectEqual(100, test_block.buffer_len);
    try testing.expectEqualStrings(literal[0..100], test_block.buffer[0..100]);
    try testing.expectEqual(0, test_block.section.len());
    const done = try test_block.feed(test_decoder, literal[100..], true);
    try expect_done(done, .{ .stream_id = 1, .origin = .headers, .end_stream = false, .too_large = false });
    try expect_section(&.{.{ .name = "custom-key", .value = long_value[0..300] }});
    try testing.expectEqual(1, test_decoder.table.len());
    try testing.expectEqual(1, test_block.lines_decoded);
}

/// Blocks hpack refuses, each a COMPRESSION_ERROR through this slot: index 0 (hpack/6.1/1), an
/// index past both tables in an indexed field and in a literal's name (hpack/2.3.3/1, /2), a size
/// update after a field line (hpack/4.2/1), one above the limit (hpack/6.3/1), a third one, a
/// name past the length limit, the three Huffman refusals (hpack/5.2/1 to /3), an index encoded in
/// more octets than `integer_len_max`, and an index past `integer_value_max` (RFC 7541 §5.1).
const refused_blocks = [_][]const u8{
    "\x80",
    "\xbe",
    "\x7e\x01v",
    "\x82\x20",
    "\x3f\xe2\x1f",
    "\x20\x20\x20",
    "\x40\x7f\x82\x01" ++ [_]u8{'a'} ** (hpack.constants.limits.name_len_max + 1),
    "\x40\x01a\x81\xff",
    "\x40\x01a\x81\x00",
    "\x40\x01a\x84\xff\xff\xff\xff",
    "\xff" ++ "\x80" ** (wire.constants.protocol.integer_len_max - 1),
    "\xff" ** (wire.constants.protocol.integer_len_max - 1) ++ "\x7f",
};

test "every decoding error is refused as DecodeFailed and clears the slot" {
    for (refused_blocks) |octets| {
        start(1, .headers, false);
        try testing.expectError(error.DecodeFailed, test_block.feed(test_decoder, octets, true));
        try expect_cleared();
    }
    // RFC 9113 §4.3.1: after a lowered limit, a block that does not open with an update.
    start(1, .headers, false);
    test_decoder.set_capacity_limit(100);
    try testing.expectError(error.DecodeFailed, test_block.feed(test_decoder, "\x82", false));
    try expect_cleared();
}

test "a size update that opens a CONTINUATION after a field line is refused as in one frame (RFC 7541 §4.2)" {
    start(1, .headers, false);
    try testing.expectEqual(null, try test_block.feed(test_decoder, "\x82", false));
    try testing.expectError(error.DecodeFailed, test_block.feed(test_decoder, "\x20\x86", true));
    start(1, .headers, false);
    try testing.expectEqual(null, try test_block.feed(test_decoder, "\x20\x20", false));
    try testing.expectEqual(2, test_block.size_updates);
    try testing.expectError(error.DecodeFailed, test_block.feed(test_decoder, "\x20\x82", true));
    // The legal case: the update opens the block, and the field lines follow in the next frame.
    start(1, .headers, false);
    try testing.expectEqual(null, try test_block.feed(test_decoder, "\x20", false));
    try testing.expectEqual(1, test_block.size_updates);
    const done = try test_block.feed(test_decoder, "\x82\x86", true);
    try expect_done(done, .{ .stream_id = 1, .origin = .headers, .end_stream = false, .too_large = false });
    try expect_section(request_lines[0..2]);
    try testing.expectEqual(0, test_decoder.table.capacity);
}

test "both counts are carried when a fragment ends inside a representation (RFC 7541 §4.2)" {
    // One update, then a second cut inside its integer; the next fragment finishes it and adds
    // a third, which the carried count refuses.
    start(1, .headers, false);
    try testing.expectEqual(null, try test_block.feed(test_decoder, "\x20\x3f", false));
    try testing.expectEqual(1, test_block.size_updates);
    try testing.expectError(error.DecodeFailed, test_block.feed(test_decoder, "\xe1\x1f\x20", true));
    // A field line, then a literal cut in its name: the line count is carried with it.
    start(1, .headers, false);
    try testing.expectEqual(null, try test_block.feed(test_decoder, "\x82\x40\x01", false));
    try testing.expectEqual(1, test_block.lines_decoded);
    const done = try test_block.feed(test_decoder, "a\x01b", true);
    try expect_done(done, .{ .stream_id = 1, .origin = .headers, .end_stream = false, .too_large = false });
    try testing.expectEqual(2, test_block.lines_decoded);
}

test "a section past its size keeps decoding, and the later inserts are made in the dynamic table (invariant 10)" {
    start(1, .headers, false);
    test_encoder.init(constants.protocol.header_table_size_initial, .never);
    var output = Writer.init(&support.test_frame);
    try test_encoder.write_field(&output, "a", &long_value, .incremental);
    try testing.expectEqual(null, try test_block.feed(test_decoder, output.written(), false));
    try testing.expect(!test_block.too_large);
    output = Writer.init(&support.test_frame);
    try test_encoder.write_field(&output, "b", &long_value, .incremental);
    try test_encoder.write_field(&output, "custom-key", "custom-value", .incremental);
    try test_encoder.write_field(&output, "custom-key-2", "custom-value-2", .incremental);
    const done = try test_block.feed(test_decoder, output.written(), true);
    try expect_done(done, .{ .stream_id = 1, .origin = .headers, .end_stream = false, .too_large = true });
    try expect_section(&.{.{ .name = "a", .value = &long_value }});
    try testing.expectEqual(4, test_block.lines_decoded);
    try testing.expectEqual(2, test_decoder.table.len());
    // The next block names both discarded lines by index, and the decoder still holds them.
    test_block.begin(3, .headers, true);
    const second = try test_block.feed(test_decoder, "\xbe\xbf", true);
    try expect_done(second, .{ .stream_id = 3, .origin = .headers, .end_stream = true, .too_large = false });
    try expect_section(&.{
        .{ .name = "custom-key-2", .value = "custom-value-2" },
        .{ .name = "custom-key", .value = "custom-value" },
    });
}

test "a section past its line count keeps decoding and reports too_large" {
    start(1, .headers, false);
    var output = Writer.init(&support.test_frame);
    // Three lines past the limit: the first is refused, and the two after it are still decoded.
    for (0..core.constants.limits.field_count_max + 3) |_| try output.write_bytes("\x00\x01n\x01v");
    const done = try test_block.feed(test_decoder, output.written(), true);
    try expect_done(done, .{ .stream_id = 1, .origin = .headers, .end_stream = false, .too_large = true });
    try testing.expectEqual(core.constants.limits.field_count_max, test_block.section.len());
    try testing.expectEqual(core.constants.limits.field_count_max + 3, test_block.lines_decoded);
}

/// Where the cut tests write their block, and the section, line count and table length of that block
/// fed whole, which every cut of it must give. Test-only.
threadlocal var cut_block: [cut_block_len_max]u8 = undefined;
threadlocal var whole_section: @TypeOf(support.test_block.section) align(@alignOf(@TypeOf(support.test_block.section))) = undefined;
threadlocal var whole_lines: u32 = 0;
threadlocal var whole_table_len: u32 = 0;
const cut_block_len_max = 4096;
/// A value of printable octets, some of which Huffman codes in more octets than they take raw.
/// Test-only.
const mixed_len = 2000;
/// The step between the cuts of the test that cuts a block in three. Test-only.
const cut_step = 53;
/// The stride that spreads `mixed_len` octets over the printable ones, and the length of the
/// literal the block inserts and then names by index. Test-only.
const mixed_stride = 7;
const literal_len = 300;

/// Writes the block the cut tests feed: indexed and literal lines, Huffman-coded and raw strings, a
/// value of `mixed_len` octets, and a line that names the dynamic table. Test-only.
fn write_cut_block(output: *Writer) ![]const u8 {
    var mixed: [mixed_len]u8 = undefined;
    for (&mixed, 0..) |*octet, index| octet.* = @intCast(' ' + (index * mixed_stride) % ('~' - ' '));
    test_encoder.init(constants.protocol.header_table_size_initial, .when_shorter);
    try test_encoder.write_field(output, ":method", "GET", .incremental);
    try test_encoder.write_field(output, ":path", "/apis/admissionregistration.k8s.io/v1/webhooks", .incremental);
    try test_encoder.write_field(output, "custom-key", long_value[0..literal_len], .incremental);
    try test_encoder.write_field(output, "x-mixed", &mixed, .without_indexing);
    try test_encoder.write_field(output, "custom-key", long_value[0..literal_len], .incremental);
    return output.written();
}

/// Feeds `octets` as one fragment and keeps what it gives as the reference. Test-only.
fn feed_whole(octets: []const u8) !void {
    start(1, .headers, false);
    _ = (try test_block.feed(test_decoder, octets, true)) orelse return error.TestUnexpectedResult;
    whole_section = test_block.section;
    whole_lines = test_block.lines_decoded;
    whole_table_len = test_decoder.table.len();
}

/// Feeds `octets` cut at each place of `cuts`, and requires what the whole block gave. Test-only.
fn expect_cut_as_whole(octets: []const u8, cuts: []const usize) !void {
    start(1, .headers, false);
    var from: usize = 0;
    for (cuts) |cut| {
        try testing.expectEqual(null, try test_block.feed(test_decoder, octets[from..cut], false));
        from = cut;
    }
    _ = (try test_block.feed(test_decoder, octets[from..], true)) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(whole_lines, test_block.lines_decoded);
    try testing.expectEqual(whole_table_len, test_decoder.table.len());
    try testing.expectEqual(whole_section.len(), test_block.section.len());
    for (0..whole_section.len()) |index| {
        const expected = whole_section.get(@intCast(index));
        const line = test_block.section.get(@intCast(index));
        try testing.expectEqualStrings(expected.name, line.name);
        try testing.expectEqualStrings(expected.value, line.value);
    }
}

test "design §8 step 61a: a block cut in two at each octet decodes as the block fed whole" {
    var output = Writer.init(&cut_block);
    const octets = try write_cut_block(&output);
    try feed_whole(octets);
    try testing.expectEqual(5, whole_lines);
    for (0..octets.len + 1) |cut| try expect_cut_as_whole(octets, &.{cut});
}

test "design §8 step 61a: a block cut in three decodes as the block fed whole" {
    var output = Writer.init(&cut_block);
    const octets = try write_cut_block(&output);
    try feed_whole(octets);
    for (0..octets.len / cut_step + 1) |first| {
        for (first..octets.len / cut_step + 1) |second| {
            try expect_cut_as_whole(octets, &.{ first * cut_step, second * cut_step });
        }
    }
}
