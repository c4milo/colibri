//! The Huffman code of RFC 7541 Appendix B, shared by HPACK and QPACK: RFC 9204 §4.1.2 uses the
//! table "without modification" (decision 11). One table, generated from the RFC text into
//! `huffman_table.zig`, and one coder.
//!
//! Decoding rejects the three errors RFC 7541 §5.2 names, in this order (invariant 7):
//!   1. a complete EOS symbol inside the data, or `error.HuffmanEosInData`;
//!   2. padding strictly longer than 7 bits, or `error.HuffmanPaddingTooLong`;
//!   3. padding that is not the most significant bits of EOS, or `error.HuffmanPaddingNotEos`.
//!
//! Check 1 happens at a symbol boundary inside the decode loop, never by scanning for a run of
//! ones (invariant 12). A run of thirty ones is legal without EOS: symbol 204 ends in five ones and
//! symbol 22 begins with twenty-nine, so the octets 204 and 22 encode to a run of thirty-four.
//!
//! The decoder walks the code bit by bit using the table's canonical order, which the comptime
//! block below proves rather than assumes: at each length, the codes of that length are one
//! contiguous range, so a partial code is a complete symbol exactly when it falls inside its
//! length's range.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("constants.zig");
const table = @import("huffman_table.zig");

const Writer = core.Writer;

pub const DecodeError = core.writer.Error || error{
    /// A complete EOS symbol appeared inside the data.
    HuffmanEosInData,
    /// The data ended with more than seven bits of an incomplete code.
    HuffmanPaddingTooLong,
    /// The data ended with bits that are not the most significant bits of EOS.
    HuffmanPaddingNotEos,
};

const eos_code: u32 = (1 << constants.huffman_code_bits_max) - 1;

/// The canonical form of the table, indexed by code length in bits.
const Canonical = struct {
    /// The numerically smallest code of each length.
    first_code: [constants.huffman_code_bits_max + 1]u32,
    /// How many codes have each length.
    count: [constants.huffman_code_bits_max + 1]u16,
    /// Where each length's symbols start in `symbols`.
    first_index: [constants.huffman_code_bits_max + 1]u16,
    /// Every symbol, ordered by code length and then by code.
    symbols: [constants.huffman_symbol_count]u16,
};

const canonical: Canonical = build_canonical();

/// Branches the comptime build of the canonical table may take: 257 rows placed and checked.
const canonical_eval_branch_quota = 65_536;

fn build_canonical() Canonical {
    @setEvalBranchQuota(canonical_eval_branch_quota);
    var result: Canonical = .{
        .first_code = @splat(std.math.maxInt(u32)),
        .count = @splat(0),
        .first_index = @splat(0),
        .symbols = @splat(0),
    };
    for (table.codes) |row| {
        result.count[row.bit_count] += 1;
        result.first_code[row.bit_count] = @min(result.first_code[row.bit_count], row.code);
    }
    var next_index: u16 = 0;
    for (&result.first_index, result.count) |*first_index, count| {
        first_index.* = next_index;
        next_index += count;
    }
    var placed: [constants.huffman_symbol_count]bool = @splat(false);
    for (table.codes, 0..) |row, symbol| {
        const offset = row.code - result.first_code[row.bit_count];
        // Contiguity: every code of a length lies inside that length's range, once.
        assert(offset < result.count[row.bit_count]);
        const index = result.first_index[row.bit_count] + offset;
        assert(!placed[index]);
        placed[index] = true;
        result.symbols[index] = @intCast(symbol);
    }
    return result;
}

comptime {
    assert(table.codes.len == constants.huffman_symbol_count);
    // RFC 7541 §5.2 pads with the most significant bits of EOS, which is thirty set bits.
    const eos = table.codes[constants.huffman_eos_symbol];
    assert(eos.code == eos_code and eos.bit_count == constants.huffman_code_bits_max);
    // Kraft equality: the code is complete, so every sequence of thirty bits holds a symbol.
    var kraft_sum: u64 = 0;
    for (table.codes) |row| {
        assert(row.bit_count >= constants.huffman_code_bits_min);
        assert(row.bit_count <= constants.huffman_code_bits_max);
        kraft_sum += @as(u64, 1) << @intCast(constants.huffman_code_bits_max - row.bit_count);
    }
    assert(kraft_sum == @as(u64, 1) << constants.huffman_code_bits_max);
    assert_canonical_order();
}

/// Canonical order: the shortest length starts at code zero, and each longer length starts where
/// the previous length's range ends, shifted by the difference in length.
fn assert_canonical_order() void {
    var previous_bits: u8 = 0;
    for (canonical.count, 0..) |count, bits| {
        if (count == 0) continue;
        const expected: u32 = if (previous_bits == 0)
            0
        else
            (canonical.first_code[previous_bits] + canonical.count[previous_bits]) <<
                @intCast(bits - previous_bits);
        assert(canonical.first_code[bits] == expected);
        previous_bits = @intCast(bits);
    }
}

/// The most octets `data_len` octets of Huffman data can decode to. Every symbol costs at least
/// `huffman_code_bits_min` bits, so a caller sizes its output from this and never guesses.
pub fn decoded_len_max(data_len: usize) usize {
    return data_len * @bitSizeOf(u8) / constants.huffman_code_bits_min;
}

/// The most octets `data_len` octets can occupy once encoded, padding included. Every symbol costs
/// at most `huffman_code_bits_max` bits, so a limit on decoded octets gives a limit on encoded ones.
pub fn encoded_len_max(data_len: usize) usize {
    return std.math.divCeil(usize, data_len * constants.huffman_code_bits_max, @bitSizeOf(u8)) catch unreachable;
}

/// The octets `bytes` occupies once encoded, padding included.
pub fn encoded_len(bytes: []const u8) usize {
    var bit_total: usize = 0;
    for (bytes) |byte| bit_total += table.codes[byte].bit_count;
    return std.math.divCeil(usize, bit_total, @bitSizeOf(u8)) catch unreachable;
}

/// The code being assembled, one bit at a time.
const Partial = struct {
    code: u32 = 0,
    bit_count: u8 = 0,

    /// Appends one bit, and returns the symbol when the bits so far are a complete code.
    fn push(self: *Partial, bit: u1) ?u16 {
        self.code = (self.code << 1) | bit;
        // Kraft equality, pinned at comptime above, makes the code complete: every run of thirty
        // bits holds a symbol, so no partial code outgrows the longest code. The check is proved
        // at build time rather than asserted here, on a path every peer bit reaches.
        self.bit_count += 1;
        const offset = self.code -% canonical.first_code[self.bit_count];
        if (offset >= canonical.count[self.bit_count]) return null;
        const symbol = canonical.symbols[canonical.first_index[self.bit_count] + offset];
        self.* = .{};
        return symbol;
    }
};

/// Decodes all of `encoded` into `output`. On an error the output cursor does not move: it moves
/// once, when the whole string has decoded, and octets past it are scratch.
pub fn decode(encoded: []const u8, output: *Writer) DecodeError!void {
    var cursor = output.*;
    var partial: Partial = .{};
    for (encoded) |octet| {
        for (0..@bitSizeOf(u8)) |bit_index| {
            const bit: u1 = @truncate(octet >> @intCast(@bitSizeOf(u8) - 1 - bit_index));
            const symbol = partial.push(bit) orelse continue;
            // RFC 7541 §5.2: a Huffman-encoded string literal containing EOS is a decoding error.
            if (symbol == constants.huffman_eos_symbol) return error.HuffmanEosInData;
            try cursor.write_byte(@intCast(symbol));
        }
    }
    // RFC 7541 §5.2: padding strictly longer than 7 bits is a decoding error.
    if (partial.bit_count > constants.huffman_padding_bits_max) return error.HuffmanPaddingTooLong;
    const eos_prefix = (@as(u32, 1) << @intCast(partial.bit_count)) - 1;
    // RFC 7541 §5.2: padding that is not the most significant bits of EOS is a decoding error.
    if (partial.code != eos_prefix) return error.HuffmanPaddingNotEos;
    output.* = cursor;
}

/// Most whole octets ready to write after one symbol. At most seven bits wait between symbols and a
/// code is at most thirty, so no more than four octets are ever ready at once.
const ready_octets_max = (constants.huffman_padding_bits_max + constants.huffman_code_bits_max) /
    @bitSizeOf(u8);

/// Encodes `bytes` into `output`, padded with the most significant bits of EOS (RFC 7541 §5.2).
/// All of the octets are written, or none.
pub fn encode(bytes: []const u8, output: *Writer) core.writer.Error!void {
    if (encoded_len(bytes) > output.remaining_len()) return error.NoSpaceLeft;
    var pending: u64 = 0;
    var pending_bits: u8 = 0;
    for (bytes) |byte| {
        const row = table.codes[byte];
        pending = (pending << @intCast(row.bit_count)) | row.code;
        pending_bits += row.bit_count;
        for (0..ready_octets_max) |_| {
            if (pending_bits < @bitSizeOf(u8)) break;
            pending_bits -= @bitSizeOf(u8);
            output.write_byte(@truncate(pending >> @intCast(pending_bits))) catch unreachable;
        }
        assert(pending_bits < @bitSizeOf(u8));
        pending &= (@as(u64, 1) << @intCast(pending_bits)) - 1;
    }
    if (pending_bits == 0) return;
    const padding_bits: u8 = @bitSizeOf(u8) - pending_bits;
    const padding: u64 = (@as(u64, 1) << @intCast(padding_bits)) - 1;
    output.write_byte(@truncate((pending << @intCast(padding_bits)) | padding)) catch unreachable;
}

const testing = std.testing;

/// Octets of output the test helpers decode or encode into. Test-only.
const expect_buffer_len = 256;

fn expect_decodes(encoded: []const u8, decoded: []const u8) !void {
    var buffer: [expect_buffer_len]u8 = @splat(0);
    var output = Writer.init(&buffer);
    try decode(encoded, &output);
    try testing.expectEqualSlices(u8, decoded, output.written());
    try testing.expect(decoded.len <= decoded_len_max(encoded.len));
}

fn expect_encodes(decoded: []const u8, encoded: []const u8) !void {
    var buffer: [expect_buffer_len]u8 = @splat(0);
    var output = Writer.init(&buffer);
    try encode(decoded, &output);
    try testing.expectEqualSlices(u8, encoded, output.written());
    try testing.expectEqual(encoded.len, encoded_len(decoded));
}

test "RFC 7541 Appendix C's Huffman strings decode and encode" {
    const vectors = [_]struct { []const u8, []const u8 }{
        .{ "www.example.com", &.{ 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff } },
        .{ "no-cache", &.{ 0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf } },
        .{ "custom-key", &.{ 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f } },
        .{ "custom-value", &.{ 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf } },
        .{ "302", &.{ 0x64, 0x02 } },
        .{ "private", &.{ 0xae, 0xc3, 0x77, 0x1a, 0x4b } },
    };
    for (vectors) |vector| {
        try expect_decodes(vector[1], vector[0]);
        try expect_encodes(vector[0], vector[1]);
    }
}

test "octets 204 and 22 decode through a run of thirty-four ones with no EOS" {
    const encoded = [_]u8{ 0xff, 0xff, 0xfb, 0xff, 0xff, 0xff, 0xff, 0x7f };
    try expect_encodes(&.{ 0xcc, 0x16 }, &encoded);
    try expect_decodes(&encoded, &.{ 0xcc, 0x16 });
    // The run is there: past the seven padding bits, the last 36 bits of the two codes are the
    // zero inside symbol 204, thirty-four ones, and the zero that ends symbol 22.
    const bits = std.mem.readInt(u64, &encoded, .big);
    try testing.expectEqual(0x7fffffffe, (bits >> 7) & 0xfffffffff);
}

test "no octet encodes past encoded_len_max, and octet 22, at thirty bits, reaches it" {
    for (0..256) |value| {
        const octet = [_]u8{@intCast(value)};
        try testing.expect(encoded_len(&octet) <= encoded_len_max(1));
    }
    // One octet rounds 30 bits up to 4 octets, and eight take exactly 240 bits, 30 octets.
    const longest: [8]u8 = @splat(22);
    try testing.expectEqual(4, encoded_len_max(1));
    try testing.expectEqual(encoded_len_max(1), encoded_len(longest[0..1]));
    try testing.expectEqual(30, encoded_len_max(8));
    try testing.expectEqual(encoded_len_max(8), encoded_len(&longest));
    try testing.expectEqual(0, encoded_len_max(0));
}

test "every octet round-trips, and the empty string is empty" {
    var all: [256]u8 = @splat(0);
    for (&all, 0..) |*byte, value| byte.* = @intCast(value);
    var buffer: [1024]u8 = @splat(0);
    var output = Writer.init(&buffer);
    try encode(&all, &output);
    try expect_decodes(output.written(), &all);
    try expect_encodes("", "");
    try expect_decodes("", "");
}

test "a complete EOS inside the data is HuffmanEosInData, even before a valid symbol" {
    var buffer: [8]u8 = @splat(0);
    var output = Writer.init(&buffer);
    // EOS and two bits of padding.
    try testing.expectError(error.HuffmanEosInData, decode(&.{ 0xff, 0xff, 0xff, 0xff }, &output));
    // 'a' (00011), then EOS, then padding.
    const after_symbol = [_]u8{ 0x1f, 0xff, 0xff, 0xff, 0xfe };
    try testing.expectError(error.HuffmanEosInData, decode(&after_symbol, &output));
    try testing.expectEqual(0, output.offset);
}

test "padding longer than seven bits is HuffmanPaddingTooLong" {
    var buffer: [8]u8 = @splat(0);
    var output = Writer.init(&buffer);
    // 'a' (00011), then eleven ones.
    try testing.expectError(error.HuffmanPaddingTooLong, decode(&.{ 0x1f, 0xff }, &output));
    // Eight ones and nothing else.
    try testing.expectError(error.HuffmanPaddingTooLong, decode(&.{0xff}, &output));
    try testing.expectEqual(0, output.offset);
}

test "padding that is not a prefix of EOS is HuffmanPaddingNotEos" {
    var buffer: [8]u8 = @splat(0);
    var output = Writer.init(&buffer);
    // 'a' (00011), then 000.
    try testing.expectError(error.HuffmanPaddingNotEos, decode(&.{0x18}, &output));
    // 'a' (00011), then 110.
    try testing.expectError(error.HuffmanPaddingNotEos, decode(&.{0x1e}, &output));
    try testing.expectEqual(0, output.offset);
    // 'a' (00011), then 111, is legal.
    try expect_decodes(&.{0x1f}, "a");
}

test "a decode or an encode that does not fit leaves the output cursor where it was" {
    var buffer: [3]u8 = @splat(0xee);
    var output = Writer.init(&buffer);
    try output.write_byte(0x01);
    const no_cache = [_]u8{ 0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf };
    try testing.expectError(error.NoSpaceLeft, decode(&no_cache, &output));
    try testing.expectEqual(1, output.offset);
    try testing.expectError(error.NoSpaceLeft, encode("no-cache", &output));
    try testing.expectEqualSlices(u8, &.{0x01}, output.written());
}

/// Most octets a fuzz input carries. Test-only.
const fuzz_input_len_max = 64;

fn fuzz_decode(_: void, smith: *testing.Smith) anyerror!void {
    var input: [fuzz_input_len_max]u8 = @splat(0);
    const input_len = smith.slice(&input);
    var decoded_buffer: [decoded_len_max(fuzz_input_len_max)]u8 = @splat(0);
    var decoded = Writer.init(&decoded_buffer);
    decode(input[0..input_len], &decoded) catch |err| {
        try testing.expect(err != error.NoSpaceLeft);
        try testing.expectEqual(0, decoded.offset);
        return;
    };
    // The padding rules leave exactly one encoding per string, so a string that decoded
    // re-encodes to the very octets it came from.
    var encoded_buffer: [fuzz_input_len_max]u8 = @splat(0);
    var encoded = Writer.init(&encoded_buffer);
    try encode(decoded.written(), &encoded);
    try testing.expectEqualSlices(u8, input[0..input_len], encoded.written());
}

test "fuzz: a string that decodes re-encodes to the same octets" {
    try testing.fuzz({}, fuzz_decode, .{ .corpus = &.{
        core.fuzz.input("\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff"),
        core.fuzz.input("\xff\xff\xfb\xff\xff\xff\xff\x7f"),
        core.fuzz.input("\xff\xff\xff\xff"),
        core.fuzz.input("\x1f\xff"),
        core.fuzz.input("\x18"),
    } });
}

test "sweep: every input of up to two octets that decodes re-encodes to itself" {
    try core.fuzz.sweep(fuzz_decode, null);
}
