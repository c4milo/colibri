//! The limits of the field-block slot, split off field_block.zig for length: the CONTINUATION
//! count and the encoded length of a field line. field_block.zig's header lists the slot's check
//! order, where the count is step 1 and the length of a cut line is step 3. The tests of each
//! limit are here, beside the code that refuses.
//!
//! A line's length is measured from the block offset where the line before it ended, so the
//! verdict depends on the block's octets and not on where its fragments were cut (RFC 9113 §4.3:
//! a field block is logically equivalent to a single frame). `representation_len_max` is the
//! longest line the decoder accepts, so a decoded line is asserted to fit, and only a line the
//! last fragment cut can be refused. Its octets fed so far are measured, which is what bounds the
//! octets the slot keeps to `representation_len_max` (decision 40).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const hpack = @import("hpack");
const constants = @import("constants.zig");
const field_block = @import("field_block.zig");

const FieldBlock = field_block.FieldBlock;
const Error = field_block.Error;
const Done = field_block.Done;

/// Counts one fragment: the first is the opening frame's, each later one a CONTINUATION frame's.
pub fn count_fragment(block: *FieldBlock, fragment_len: usize) Error!void {
    assert(fragment_len <= constants.frame_size_max);
    if (block.fragments > 0) {
        // RFC 9113 §6.10 lets any number of CONTINUATION frames follow, and §10.5 asks the
        // implementation to set limits and treat excess as ENHANCE_YOUR_CALM.
        if (block.continuations == constants.continuation_count_max) return error.TooManyContinuations;
        block.continuations += 1;
    }
    block.fragments += 1;
    block.octets_fed += fragment_len;
    assert(block.continuations + 1 == block.fragments);
    // Invariant 14: the byte count never exceeds the fragments allowed, each at most a frame.
    assert(block.octets_fed <= @as(u64, constants.continuation_count_max + 1) * constants.frame_size_max);
}

/// Records the end of a decoded line whose representation ends at `line_end`, a block offset, by
/// moving `line_end_offset` to it.
pub fn record_line_end(block: *FieldBlock, line_end: u64) void {
    assert(line_end > block.line_end_offset);
    assert(line_end <= block.octets_fed);
    // The decoder accepts no line longer than `representation_len_max`, which is derived from its
    // integer and string limits (RFC 7541 §7.4).
    assert(line_end - block.line_end_offset <= constants.representation_len_max);
    block.line_end_offset = line_end;
}

/// Measures the line the last fragment cut, by its octets fed so far, before another fragment is
/// appended to the octets the slot keeps of it.
pub fn measure_cut_line(block: *const FieldBlock) Error!void {
    assert(block.line_end_offset <= block.octets_decoded);
    assert(block.octets_decoded + block.buffer_len == block.octets_fed);
    // RFC 7541 §7.4: the cut line is already longer than any line the decoder's limits admit.
    if (block.octets_fed - block.line_end_offset > constants.representation_len_max) return error.RepresentationTooLong;
}

const testing = std.testing;
const Writer = core.Writer;
const test_block = &field_block.test_block;
const test_decoder = &field_block.test_decoder;
const test_frame = &field_block.test_frame;
const start = field_block.start;
const expect_section = field_block.expect_section;
const expect_done = field_block.expect_done;
const expect_cleared = field_block.expect_cleared;

fn feed_continuations(count: u32) !void {
    for (0..count) |_| try testing.expectEqual(null, try test_block.feed(test_decoder, "\x86", false));
    try testing.expectEqual(count, test_block.continuations);
}

test "the CONTINUATION at continuation_count_max ends a block, and one past it is refused" {
    start(1, .headers, false);
    try testing.expectEqual(null, try test_block.feed(test_decoder, "", false));
    try feed_continuations(constants.continuation_count_max - 1);
    const done = try test_block.feed(test_decoder, "\x84", true);
    try expect_done(done, .{ .stream_id = 1, .origin = .headers, .end_stream = false, .too_large = false });
    try testing.expectEqual(constants.continuation_count_max, test_block.continuations);
    try testing.expectEqual(constants.continuation_count_max, test_block.section.len());
    start(1, .headers, false);
    try testing.expectEqual(null, try test_block.feed(test_decoder, "\x82", false));
    try feed_continuations(constants.continuation_count_max);
    try testing.expectError(error.TooManyContinuations, test_block.feed(test_decoder, "\x84", true));
    try expect_cleared();
}

test "the CONTINUATION count is checked before the fragment is decoded or changes the table" {
    // Step 1 before step 2: the frame past the count carries index 0, a decoding error.
    start(1, .headers, false);
    try testing.expectEqual(null, try test_block.feed(test_decoder, "", false));
    try feed_continuations(constants.continuation_count_max);
    try testing.expectError(error.TooManyContinuations, test_block.feed(test_decoder, "\x80", true));
    // The frame past the count carries an insert, and the dynamic table stays empty.
    start(1, .headers, false);
    try testing.expectEqual(null, try test_block.feed(test_decoder, "", false));
    try feed_continuations(constants.continuation_count_max);
    try testing.expectError(error.TooManyContinuations, test_block.feed(test_decoder, "\x40\x01a\x01b", true));
    try testing.expectEqual(0, test_decoder.table.len());
}

test "a block of continuation_count_max + 1 full frames decodes, invariant 14's byte bound" {
    // Every octet is an indexed field, so the section refuses the lines past its count and the
    // decoder still reads all of them.
    @memset(test_frame, 0x82);
    start(1, .headers, false);
    try testing.expectEqual(null, try test_block.feed(test_decoder, test_frame, false));
    for (0..constants.continuation_count_max - 1) |_| {
        try testing.expectEqual(null, try test_block.feed(test_decoder, test_frame, false));
    }
    const done = try test_block.feed(test_decoder, test_frame, true);
    try expect_done(done, .{ .stream_id = 1, .origin = .headers, .end_stream = false, .too_large = true });
    const fed: u64 = (constants.continuation_count_max + 1) * constants.frame_size_max;
    try testing.expectEqual(fed, test_block.octets_fed);
    try testing.expectEqual(fed, test_block.octets_decoded);
    try testing.expect(test_block.octets_fed > constants.continuation_count_max * constants.frame_size_max);
}

/// Writes into `test_frame` the head of a raw literal whose value claims `value_len` octets. The
/// rest of the frame is value octets. Test-only.
fn write_literal_head(value_len: u64) !void {
    var output = Writer.init(test_frame);
    try output.write_bytes("\x00\x01a");
    try wire.prefixed_integer.encode(hpack.constants.string_prefix_bits - 1, &output, 0, value_len);
}

test "a cut line is refused once its octets fed pass representation_len_max, before END_HEADERS is read" {
    // The value claims more octets than the buffer holds, so the literal stays cut.
    try write_literal_head(constants.field_block_buffer_len);
    const rest = constants.representation_len_max - constants.frame_size_max;
    // The octets past the limit arrive as a full frame, which fills `field_block_buffer_len`, and
    // as one octet with END_HEADERS, which step 3 refuses before step 4 reads the flag.
    const past_limit = [_][]const u8{ test_frame, "v" };
    for (past_limit, [_]bool{ false, true }) |fragment, end_headers| {
        start(1, .headers, false);
        try testing.expectEqual(null, try test_block.feed(test_decoder, test_frame, false));
        try testing.expectEqual(null, try test_block.feed(test_decoder, test_frame[0..rest], false));
        try testing.expectEqual(constants.representation_len_max, test_block.buffer_len);
        try testing.expectError(error.RepresentationTooLong, test_block.feed(test_decoder, fragment, end_headers));
        try expect_cleared();
    }
    // A size update that opens the block counts toward the line after it.
    start(1, .headers, false);
    try testing.expectEqual(null, try test_block.feed(test_decoder, "\x20", false));
    try testing.expectEqual(null, try test_block.feed(test_decoder, test_frame, false));
    try testing.expectError(error.RepresentationTooLong, test_block.feed(test_decoder, test_frame[0..rest], false));
    try expect_cleared();
}

/// Where the longest line and one indexed field after it are written before they are cut into
/// fragments. Test-only.
var test_line: [constants.representation_len_max + 1]u8 = undefined;

/// An octet RFC 7541 Appendix B codes in `huffman_code_bits_max` bits, the longest code, and one
/// RFC 9113 §8.2.1 allows in a field value. Test-only.
const longest_code_octet: u8 = 22;

/// The continuation flag of a prefixed integer's octet and the value bits below it (RFC 7541
/// §5.1), and the H flag of a string literal's first octet (§5.2). Test-only.
const continuation_flag: u8 = 0x80;
const continuation_value_mask: u8 = 0x7f;
const huffman_flag: u8 = 0x80;

/// Writes `value` as a prefixed integer of `integer_len_max` octets: the prefix full of ones, then
/// continuation octets, the last of them carrying zeros, which RFC 7541 §5.1 does not forbid.
/// Test-only.
fn write_integer_longest(output: *Writer, comptime prefix_bits: u4, pattern: u8, value: u64) !void {
    const prefix_max: u8 = @intCast((@as(u16, 1) << prefix_bits) - 1);
    try output.write_byte(pattern | prefix_max);
    var rest = value - prefix_max;
    for (1..wire.constants.integer_len_max) |octets_written| {
        const last = octets_written + 1 == wire.constants.integer_len_max;
        const flag: u8 = if (last) 0 else continuation_flag;
        try output.write_byte(@as(u8, @intCast(rest & continuation_value_mask)) | flag);
        rest >>= @intCast(wire.constants.integer_continuation_bits);
    }
    assert(rest == 0);
}

/// Writes `octets` as a Huffman-coded string literal whose length takes `integer_len_max` octets.
/// Test-only.
fn write_string_longest(output: *Writer, octets: []const u8) !void {
    const prefix_bits = hpack.constants.string_prefix_bits - 1;
    try write_integer_longest(output, prefix_bits, huffman_flag, wire.huffman.encoded_len(octets));
    try wire.huffman.encode(octets, output);
}

/// Writes into `test_line` the longest line the decoder accepts, the shape
/// `representation_len_max` counts: two size updates, then a literal without indexing with a
/// literal name (RFC 7541 §6.2.2), whose name and value are `longest_code_octet`, written into
/// `test_frame`, at their length limits. Returns the line. Test-only.
fn write_longest_line() ![]const u8 {
    var output = Writer.init(&test_line);
    for (0..hpack.constants.size_updates_per_block_max) |_| {
        const pattern = hpack.constants.size_update_pattern;
        try write_integer_longest(&output, hpack.constants.size_update_prefix_bits, pattern, constants.header_table_size_initial);
    }
    try output.write_byte(hpack.constants.without_indexing_pattern);
    const value = test_frame[0..hpack.constants.value_len_max];
    @memset(value, longest_code_octet);
    try write_string_longest(&output, value[0..hpack.constants.name_len_max]);
    try write_string_longest(&output, value);
    return output.written();
}

/// Feeds `line` as a first fragment of `first_len` octets, fewer than the line's, then frames of
/// `frame_size_max` octets, the last with END_HEADERS. Test-only.
fn feed_cut(line: []const u8, first_len: usize) Error!?Done {
    assert(first_len < line.len);
    start(1, .headers, false);
    assert(try test_block.feed(test_decoder, line[0..first_len], false) == null);
    var fed = first_len;
    for (0..constants.continuation_count_max) |_| {
        if (fed == line.len) break;
        const end = @min(fed + constants.frame_size_max, line.len);
        const done = try test_block.feed(test_decoder, line[fed..end], end == line.len);
        fed = end;
        if (done != null) return done;
    }
    return null;
}

test "the longest line the decoder accepts is representation_len_max octets, and decodes under every cut" {
    const line = try write_longest_line();
    try testing.expectEqual(constants.representation_len_max, line.len);
    try testing.expectEqual(31_721, constants.representation_len_max);
    // An indexed field follows in the last fragment, which step 2 decodes before step 3 measures
    // what is left.
    test_line[line.len] = 0x82;
    const value = test_frame[0..hpack.constants.value_len_max];
    const firsts = [_]usize{ 1, 20, 21, 8000, constants.frame_size_max - 1, constants.frame_size_max };
    for (firsts) |first_len| {
        const done = try feed_cut(&test_line, first_len);
        try expect_done(done, .{ .stream_id = 1, .origin = .headers, .end_stream = false, .too_large = false });
        const name = value[0..hpack.constants.name_len_max];
        try expect_section(&.{ .{ .name = name, .value = value }, .{ .name = ":method", .value = "GET" } });
        try testing.expectEqual(test_line.len, test_block.line_end_offset);
    }
}
