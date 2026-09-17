//! The field-block reassembly slot of invariant 14 and decision 40: the one place on an h2
//! connection where a field block is decoded, fragment by fragment, as its HEADERS or
//! PUSH_PROMISE frame and any CONTINUATION frames arrive (RFC 9113 §4.3).
//!
//! The connection calls `begin` when a HEADERS or PUSH_PROMISE frame opens a block, and `feed`
//! once per fragment: the first from that frame, each later one from a CONTINUATION frame (§6.2,
//! §6.6, §6.10). `feed` appends the fragment after the octets the last fragment left and runs
//! hpack's block reader over the buffer, in `field_block_decode.zig`. That reader is
//! all-or-nothing per representation, so on `error.Truncated` the octets from the cut
//! representation's first octet are kept, moved to the buffer's front. The kept octets are at most
//! one line, so the slot holds one line and one fragment and never a whole block (decision 40). The
//! decoded lines go into `section`, and the fragment carrying END_HEADERS returns `Done`, after
//! which the connection reads the section from the block.
//!
//! `feed` checks each fragment in this order (invariant 7):
//!   1. the CONTINUATION count: one past `continuation_count_max` is
//!      `error.TooManyContinuations` (§6.10 allows any number, §10.5 asks for a limit);
//!   2. each whole representation, through the decoder: any refusal but a cut representation is
//!      `error.DecodeFailed` (§4.3);
//!   3. the cut line's octets fed so far: longer than `representation_len_max`, the longest line
//!      the decoder accepts, is `error.RepresentationTooLong` (RFC 7541 §7.4);
//!   4. END_HEADERS with octets kept: `error.BlockCutInsideRepresentation` (§4.3).
//! Every error is a connection error and leaves the slot cleared, so no later call sees a
//! half-fed block.
//!
//! A section that refuses a line, for its size or its line count, does not stop the decoding:
//! `too_large` is set, every later octet still goes through the decoder, and its lines are
//! discarded, so the dynamic table stays in step with the peer's (invariant 10, §10.5.1).
//!
//! Nothing here validates a name or a value, and nothing here names a stream error: a malformed
//! line is a stream error (§8.1.1) the connection finds on the section once the block is done,
//! while everything this slot refuses ends the connection. `field_block_decode.zig` says where
//! that departs from `FieldSection.append`'s documented contract.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");
const http = @import("http");
const hpack = @import("hpack");
const constants = @import("constants.zig");
const field_block_decode = @import("field_block_decode.zig");
const field_block_limit = @import("field_block_limit.zig");

/// Which frame opened the block: a HEADERS frame (RFC 9113 §6.2) or a PUSH_PROMISE frame (§6.6).
pub const Origin = enum { headers, push_promise };

/// The block being reassembled: invariant 14's one `?{stream_id, origin}` slot, with the
/// END_STREAM flag of the HEADERS frame carried to the end (§6.2: the CONTINUATION frames are
/// logically part of the HEADERS frame).
pub const InProgress = struct {
    /// The stream the opening frame names.
    stream_id: u32,
    /// The frame that opened the block.
    origin: Origin,
    /// The opening HEADERS frame's END_STREAM flag; always false for PUSH_PROMISE.
    end_stream: bool,
};

/// What `feed` returns for the fragment that ends the block. The section is read from the block
/// after this and stays until the next `begin`, `abandon` or `init`.
pub const Done = struct {
    /// The stream the opening frame named.
    stream_id: u32,
    /// The frame that opened the block.
    origin: Origin,
    /// The opening HEADERS frame's END_STREAM flag.
    end_stream: bool,
    /// The section refused a line, so it is incomplete; every octet was still decoded.
    too_large: bool,
};

/// Every error is a connection error (RFC 9113 §5.4.1). The connection maps each to the code its
/// doc comment names; this file writes no code (invariant 28).
pub const Error = error{
    /// One CONTINUATION frame past `continuation_count_max`. RFC 9113 §6.10 lets any number
    /// follow and §10.5 asks the implementation to set limits: `error_enhance_your_calm`.
    TooManyContinuations,
    /// The decoder refused a representation. RFC 9113 §4.3: a decoding error in a field block
    /// is a connection error of type COMPRESSION_ERROR: `error_compression_error`.
    DecodeFailed,
    /// A line the last fragment cut, whose octets fed so far are longer than
    /// `representation_len_max`, the longest line the decoder accepts. It would fail the
    /// implementation limits RFC 7541 §7.4 asks for once whole: `error_compression_error`.
    RepresentationTooLong,
    /// END_HEADERS arrived with a representation still cut, so the block did not decompress.
    /// RFC 9113 §4.3: `error_compression_error`.
    BlockCutInsideRepresentation,
};

/// One connection's slot, in storage the caller places.
pub const FieldBlock = struct {
    /// The block being reassembled, or null when the slot is free (invariant 14).
    in_progress: ?InProgress,
    /// The octets kept from the line the last fragment cut, then the fragment being decoded;
    /// `buffer[0..buffer_len]` is in use.
    buffer: [constants.field_block_buffer_len]u8,
    /// Octets of `buffer` in use.
    buffer_len: u32,
    /// The decoded lines, in arrival order.
    section: http.FieldSection,
    /// Set once the section refuses a line for its size or its line count. Later lines are still
    /// decoded, and discarded (invariant 10).
    too_large: bool,
    /// CONTINUATION frames fed so far, at most `continuation_count_max`.
    continuations: u32,
    /// Fragments fed so far: the opening frame's, then one per CONTINUATION frame.
    fragments: u32,
    /// Every fragment octet fed: invariant 14's byte count, a counter and not a buffer.
    octets_fed: u64,
    /// Every octet the decoder consumed, over all fragments. At `Done` it equals `octets_fed`,
    /// whether or not the section refused a line (invariant 10).
    octets_decoded: u64,
    /// The block offset at which the last decoded line's representation ended, or 0 before the
    /// first line. `representation_len_max` measures the next line from here.
    line_end_offset: u64,
    /// Field lines the decoder produced, stored or discarded: the block reader's count, carried
    /// across fragments (RFC 7541 §4.2, `field_block_decode.zig`).
    lines_decoded: u32,
    /// Size updates the decoder read: the block reader's count, carried across fragments the
    /// same way.
    size_updates: u32,

    /// Makes the slot empty, with nothing in progress.
    pub fn init(block: *FieldBlock) void {
        block.clear();
        assert(!block.is_in_progress());
        assert(block.buffer_len == 0);
    }

    /// Whether a block has begun and not yet returned `Done` or been cleared.
    pub fn is_in_progress(block: *const FieldBlock) bool {
        return block.in_progress != null;
    }

    /// The stream whose block is in progress, or null when none is.
    pub fn stream_id(block: *const FieldBlock) ?u32 {
        const progress = block.in_progress orelse return null;
        return progress.stream_id;
    }

    /// Opens a block. Nothing may be in progress: the connection refused an interleaved HEADERS
    /// or PUSH_PROMISE frame before calling (RFC 9113 §4.3, invariant 24), so this is asserted.
    pub fn begin(block: *FieldBlock, identifier: u32, origin: Origin, end_stream: bool) void {
        assert(!block.is_in_progress());
        block.clear();
        block.in_progress = .{ .stream_id = identifier, .origin = origin, .end_stream = end_stream };
        assert(block.is_in_progress());
    }

    /// Clears the slot without a section, for a connection that is ending.
    pub fn abandon(block: *FieldBlock) void {
        block.clear();
        assert(!block.is_in_progress());
    }

    /// Feeds one fragment, whose length the connection checked against `frame_size_max`, and
    /// returns `Done` when `end_headers` ends the block. An error leaves the slot cleared.
    pub fn feed(
        block: *FieldBlock,
        decoder: *hpack.Decoder,
        fragment: []const u8,
        end_headers: bool,
    ) Error!?Done {
        assert(block.is_in_progress());
        assert(fragment.len <= constants.frame_size_max);
        errdefer block.abandon();
        try field_block_limit.count_fragment(block, fragment.len);
        block.append(fragment);
        const consumed = try field_block_decode.decode_whole(block, decoder);
        field_block_decode.keep_tail(block, consumed);
        try field_block_limit.measure_cut_line(block);
        if (!end_headers) return null;
        // RFC 9113 §4.3: a receiver that does not decompress a field block ends the connection
        // with COMPRESSION_ERROR, and END_HEADERS with a representation still cut is such a block.
        if (block.buffer_len != 0) return error.BlockCutInsideRepresentation;
        return block.finish();
    }

    fn clear(block: *FieldBlock) void {
        block.in_progress = null;
        block.buffer_len = 0;
        block.section.init();
        block.too_large = false;
        block.continuations = 0;
        block.fragments = 0;
        block.octets_fed = 0;
        block.octets_decoded = 0;
        block.line_end_offset = 0;
        block.lines_decoded = 0;
        block.size_updates = 0;
    }

    /// Appends the fragment after the kept octets. Those are at most `representation_len_max` and
    /// the fragment at most `frame_size_max`, which is how `field_block_buffer_len` was sized.
    fn append(block: *FieldBlock, fragment: []const u8) void {
        assert(block.buffer_len <= constants.representation_len_max);
        const offset: usize = block.buffer_len;
        const end = offset + fragment.len;
        assert(end <= block.buffer.len);
        @memcpy(block.buffer[offset..end], fragment);
        block.buffer_len = @intCast(end);
    }

    fn finish(block: *FieldBlock) Done {
        const progress = block.in_progress.?;
        // Invariant 10: the decoder consumed every octet of the block, and every line it produced
        // is in the section unless the section refused one.
        assert(block.octets_decoded == block.octets_fed);
        assert(block.lines_decoded == block.section.len() or block.too_large);
        block.in_progress = null;
        return .{
            .stream_id = progress.stream_id,
            .origin = progress.origin,
            .end_stream = progress.end_stream,
            .too_large = block.too_large,
        };
    }
};

const testing = std.testing;
const Writer = core.Writer;

/// The slot the tests of this file and of `field_block_decode.zig` run on, placed outside any
/// stack frame. Test-only.
pub var test_block: FieldBlock = undefined;
/// The decoder those tests run on. Test-only.
pub var test_decoder: hpack.Decoder = undefined;
/// The encoder those tests build fragments with. Test-only.
pub var test_encoder: hpack.Encoder = undefined;
/// One frame of octets the tests write fragments into. Test-only.
pub var test_frame: [constants.frame_size_max]u8 = @splat('v');
/// A value as long as a value may be. Test-only.
pub const long_value: [core.constants.field_value_len_max]u8 = @splat('v');

/// RFC 7541 Appendix C.3.1: the first request, raw. Test-only.
pub const request_raw = "\x82\x86\x84\x41\x0fwww.example.com";
/// RFC 7541 Appendix C.4.1: the same request, Huffman-coded. Test-only.
pub const request_huffman = "\x82\x86\x84\x41\x8c\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff";
/// The field lines both encodings of the first request decode to. Test-only.
pub const request_lines = [_]hpack.Field{
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":scheme", .value = "http" },
    .{ .name = ":path", .value = "/" },
    .{ .name = ":authority", .value = "www.example.com" },
};

/// Begins a block on a fresh slot over a fresh decoder. Test-only.
pub fn start(identifier: u32, origin: Origin, end_stream: bool) void {
    test_decoder.init(constants.header_table_size_initial);
    test_block.init();
    test_block.begin(identifier, origin, end_stream);
}

/// Requires the slot's section to hold exactly `expected`, in order. Test-only.
pub fn expect_section(expected: []const hpack.Field) !void {
    try testing.expectEqual(expected.len, test_block.section.len());
    for (expected, 0..) |field, index| {
        const line = test_block.section.get(@intCast(index));
        try testing.expectEqualStrings(field.name, line.name);
        try testing.expectEqualStrings(field.value, line.value);
    }
}

/// Requires `result` to be `expected` and the slot to be free with nothing kept. Test-only.
pub fn expect_done(result: ?Done, expected: Done) !void {
    const done = result orelse return error.TestUnexpectedResult;
    try testing.expectEqual(expected, done);
    try testing.expect(!test_block.is_in_progress());
    try testing.expectEqual(null, test_block.stream_id());
    try testing.expectEqual(0, test_block.buffer_len);
}

/// Requires the slot to be as `abandon` and a refusal leave it. Test-only.
pub fn expect_cleared() !void {
    try testing.expect(!test_block.is_in_progress());
    try testing.expectEqual(0, test_block.buffer_len);
    try testing.expectEqual(0, test_block.section.len());
    try testing.expectEqual(0, test_block.octets_fed);
}

test "a block in one HEADERS frame decodes to the request, and an empty block to no lines" {
    start(1, .headers, true);
    try testing.expectEqual(1, test_block.stream_id());
    const done = try test_block.feed(&test_decoder, request_raw, true);
    try expect_done(done, .{ .stream_id = 1, .origin = .headers, .end_stream = true, .too_large = false });
    try expect_section(&request_lines);
    try testing.expectEqual(0, test_block.continuations);
    try testing.expectEqual(request_raw.len, test_block.octets_fed);
    try testing.expectEqual(1, test_decoder.table.len());
    test_block.begin(3, .headers, true);
    const empty = try test_block.feed(&test_decoder, "", true);
    try expect_done(empty, .{ .stream_id = 3, .origin = .headers, .end_stream = true, .too_large = false });
    try expect_section(&.{});
}

test "a block cut between representations decodes across two and three fragments (generic/3.10/1, /2)" {
    start(3, .headers, false);
    try testing.expectEqual(null, try test_block.feed(&test_decoder, request_raw[0..3], false));
    try testing.expectEqual(0, test_block.buffer_len);
    try testing.expectEqual(3, test_block.section.len());
    const done = try test_block.feed(&test_decoder, request_raw[3..], true);
    try expect_done(done, .{ .stream_id = 3, .origin = .headers, .end_stream = false, .too_large = false });
    try expect_section(&request_lines);
    try testing.expectEqual(1, test_block.continuations);
    try testing.expectEqual(request_raw.len, test_block.octets_fed);
    start(5, .headers, true);
    try testing.expectEqual(null, try test_block.feed(&test_decoder, request_huffman[0..1], false));
    try testing.expectEqual(null, try test_block.feed(&test_decoder, request_huffman[1..3], false));
    const three = try test_block.feed(&test_decoder, request_huffman[3..], true);
    try expect_done(three, .{ .stream_id = 5, .origin = .headers, .end_stream = true, .too_large = false });
    try expect_section(&request_lines);
    try testing.expectEqual(2, test_block.continuations);
}

test "END_HEADERS with a representation still cut is refused and clears the slot (http2/4.3/1)" {
    start(1, .headers, true);
    try testing.expectError(error.BlockCutInsideRepresentation, test_block.feed(&test_decoder, "\x40", true));
    try expect_cleared();
    start(1, .headers, true);
    try testing.expectEqual(null, try test_block.feed(&test_decoder, "\x82\x40\x0acustom-key", false));
    try testing.expectError(error.BlockCutInsideRepresentation, test_block.feed(&test_decoder, "\x0ccustom", true));
    try expect_cleared();
}

test "a HEADERS fragment and a 4000-octet CONTINUATION decode to one section (http2/6.10/1)" {
    start(1, .headers, true);
    try testing.expectEqual(null, try test_block.feed(&test_decoder, "\x82\x86\x84", false));
    var output = Writer.init(&test_frame);
    try output.write_bytes("\x00\x07x-dummy");
    try wire.prefixed_integer.encode(hpack.constants.string_prefix_bits - 1, &output, 0, 3988);
    try output.write_bytes(long_value[0..3988]);
    try testing.expectEqual(4000, output.written().len);
    const done = try test_block.feed(&test_decoder, output.written(), true);
    try expect_done(done, .{ .stream_id = 1, .origin = .headers, .end_stream = true, .too_large = false });
    try expect_section(&(request_lines[0..3].* ++ [_]hpack.Field{.{ .name = "x-dummy", .value = long_value[0..3988] }}));
    try testing.expectEqual(4003, test_block.octets_fed);
}

test "Done carries the stream, the origin and END_STREAM the block began with" {
    start(8, .push_promise, false);
    try testing.expectEqual(8, test_block.stream_id());
    const promise = try test_block.feed(&test_decoder, request_raw, true);
    try expect_done(promise, .{ .stream_id = 8, .origin = .push_promise, .end_stream = false, .too_large = false });
    test_block.begin(9, .headers, true);
    try testing.expectEqual(null, try test_block.feed(&test_decoder, "", false));
    try testing.expectEqual(9, test_block.stream_id());
    const trailers = try test_block.feed(&test_decoder, "\xbe", true);
    try expect_done(trailers, .{ .stream_id = 9, .origin = .headers, .end_stream = true, .too_large = false });
    try expect_section(request_lines[3..]);
}

test "abandon clears a half-fed block, and the slot takes a new one" {
    start(1, .headers, true);
    try testing.expectEqual(null, try test_block.feed(&test_decoder, request_raw[0..10], false));
    try testing.expectEqual(7, test_block.buffer_len);
    test_block.abandon();
    try expect_cleared();
    try testing.expectEqual(0, test_block.continuations);
    test_block.begin(3, .headers, false);
    const done = try test_block.feed(&test_decoder, request_raw, true);
    try expect_done(done, .{ .stream_id = 3, .origin = .headers, .end_stream = false, .too_large = false });
    try expect_section(&request_lines);
}

/// A second slot, fed each fuzzed block in one fragment. Test-only.
var whole_block: FieldBlock = undefined;
/// The decoder `whole_block` runs on. Test-only.
var whole_decoder: hpack.Decoder = undefined;

/// Feeds a fuzzed block once whole and once cut in two where the fuzzer says, and requires the
/// two to end the same way (RFC 9113 §4.3: a field block is logically equivalent to one frame).
fn fuzz_feed(_: void, smith: *testing.Smith) anyerror!void {
    const cut_wanted = smith.valueRangeAtMost(u32, 0, hpack.constants.fuzz_block_len_max);
    var input: [hpack.constants.fuzz_block_len_max]u8 = @splat(0);
    const octets = input[0..smith.slice(&input)];
    const cut = @min(cut_wanted, octets.len);
    whole_decoder.init(constants.header_table_size_initial);
    whole_block.init();
    whole_block.begin(1, .headers, false);
    const whole = whole_block.feed(&whole_decoder, octets, true);
    start(1, .headers, false);
    const first = test_block.feed(&test_decoder, octets[0..cut], false) catch |failure| {
        // A representation the first fragment holds whole was refused, and so was the block.
        try testing.expectError(failure, whole);
        return expect_cleared();
    };
    try testing.expectEqual(null, first);
    try testing.expect(test_block.buffer_len <= constants.representation_len_max);
    try expect_same(whole, test_block.feed(&test_decoder, octets[cut..], true), octets.len);
}

fn expect_same(whole: Error!?Done, split: Error!?Done, octets_len: usize) !void {
    const whole_done = whole catch |failure| {
        try testing.expectError(failure, split);
        return expect_cleared();
    };
    try testing.expectEqual(whole_done, try split);
    try testing.expectEqual(octets_len, test_block.octets_decoded);
    try testing.expectEqual(whole_decoder.table.len(), test_decoder.table.len());
    try testing.expectEqual(whole_block.section.len(), test_block.section.len());
    for (0..whole_block.section.len()) |index| {
        const expected = whole_block.section.get(@intCast(index));
        const line = test_block.section.get(@intCast(index));
        try testing.expectEqualStrings(expected.name, line.name);
        try testing.expectEqualStrings(expected.value, line.value);
    }
}

test "fuzz: a block cut in two fragments ends as it does in one" {
    try testing.fuzz({}, fuzz_feed, .{ .corpus = &.{
        core.fuzz.input_with_value(10, request_raw),
        core.fuzz.input_with_value(4, request_huffman),
        core.fuzz.input_with_value(1, "\x40"),
        core.fuzz.input_with_value(2, "\x3f\xe1\x1f\x82"),
        core.fuzz.input_with_value(1, "\x20\x3f\xe1\x1f\x20"),
        core.fuzz.input_with_value(1, "\x82\x20"),
        core.fuzz.input_with_value(3, "\xff\x80\x80\x80\x80\x80\x80\x80\x80\x80"),
    } });
    try core.fuzz.sweep(fuzz_feed, .{ .min = 0, .max = core.fuzz.sweep_len_max });
}
