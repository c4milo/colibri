//! The decode step of the field-block slot, split off field_block.zig for length: one call runs
//! hpack's block reader over the slot's buffer, measures and stores or discards each line, and the
//! octets the reader could not finish are kept at the buffer's front (decision 40). field_block.zig's
//! header lists the slot's check order, and the tests of the decoding refusals are here, beside the
//! code that refuses.
//!
//! The block reader counts the field lines and size updates it has read, and RFC 7541 §4.2
//! places a size update before every field line of a block: the whole block, not one fragment.
//! `decode_whole` carries both counts from one fragment to the next, whether the fragment ends
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
const constants = @import("constants.zig");
const field_block = @import("field_block.zig");
const field_block_limit = @import("field_block_limit.zig");

const FieldBlock = field_block.FieldBlock;
const Error = field_block.Error;

comptime {
    // A decoded name or value fits the lengths `FieldSection.append` asserts.
    assert(hpack.constants.name_len_max <= core.constants.field_name_len_max);
    assert(hpack.constants.value_len_max <= core.constants.field_value_len_max);
}

/// Decodes every whole representation in the buffer and returns the octets they took.
pub fn decode_whole(block: *FieldBlock, decoder: *hpack.Decoder) Error!usize {
    assert(block.is_in_progress());
    var walk = decoder.block(block.buffer[0..block.buffer_len]);
    walk.fields = block.lines_decoded;
    walk.updates = block.size_updates;
    // A buffer of n octets holds at most n representations, and one more call finds the end.
    for (0..constants.field_block_buffer_len + 1) |_| {
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
    assert(walk.consumed_len() <= block.buffer_len);
    return walk.consumed_len();
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

/// Counts the `consumed` octets as decoded and moves the octets after them, the cut
/// representation, to the buffer's front.
pub fn keep_tail(block: *FieldBlock, consumed: usize) void {
    assert(consumed <= block.buffer_len);
    const tail_len: usize = block.buffer_len - consumed;
    std.mem.copyForwards(u8, block.buffer[0..tail_len], block.buffer[consumed..block.buffer_len]);
    block.buffer_len = @intCast(tail_len);
    block.octets_decoded += consumed;
    // Invariant 10: every octet fed was consumed by the decoder or is kept for the next fragment.
    assert(block.octets_decoded + block.buffer_len == block.octets_fed);
}

const testing = std.testing;
const Writer = core.Writer;
const test_block = &field_block.test_block;
const test_decoder = &field_block.test_decoder;
const test_encoder = &field_block.test_encoder;
const long_value = field_block.long_value;
const request_raw = field_block.request_raw;
const request_lines = field_block.request_lines;
const start = field_block.start;
const expect_section = field_block.expect_section;
const expect_done = field_block.expect_done;
const expect_cleared = field_block.expect_cleared;

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
    test_encoder.init(constants.header_table_size_initial, .never);
    var output = Writer.init(&field_block.test_frame);
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
    "\x40\x7f\x82\x01" ++ [_]u8{'a'} ** (hpack.constants.name_len_max + 1),
    "\x40\x01a\x81\xff",
    "\x40\x01a\x81\x00",
    "\x40\x01a\x84\xff\xff\xff\xff",
    "\xff" ++ "\x80" ** (wire.constants.integer_len_max - 1),
    "\xff" ** (wire.constants.integer_len_max - 1) ++ "\x7f",
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
    test_encoder.init(constants.header_table_size_initial, .never);
    var output = Writer.init(&field_block.test_frame);
    try test_encoder.write_field(&output, "a", &long_value, .incremental);
    try testing.expectEqual(null, try test_block.feed(test_decoder, output.written(), false));
    try testing.expect(!test_block.too_large);
    output = Writer.init(&field_block.test_frame);
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
    var output = Writer.init(&field_block.test_frame);
    // Three lines past the limit: the first is refused, and the two after it are still decoded.
    for (0..core.constants.field_count_max + 3) |_| try output.write_bytes("\x00\x01n\x01v");
    const done = try test_block.feed(test_decoder, output.written(), true);
    try expect_done(done, .{ .stream_id = 1, .origin = .headers, .end_stream = false, .too_large = true });
    try testing.expectEqual(core.constants.field_count_max, test_block.section.len());
    try testing.expectEqual(core.constants.field_count_max + 3, test_block.lines_decoded);
}
