//! The string literal of RFC 7541 §5.2, with the N-bit prefix form RFC 9204 §4.1.2 adds for QPACK
//! (decision 11).
//!
//! A literal is an H flag, a length, and that many octets of string data. HPACK's literal starts on
//! an octet boundary: H is the high bit and the length is a 7-bit prefixed integer. QPACK's
//! "N-bit prefix string literal" starts mid-octet, after `8 - N` bits of the previous field: H is
//! the highest of the N bits and the length is an `N - 1`-bit prefixed integer, for N in 2..8. N
//! of 8 is HPACK's form, so one codec serves both. The length counts octets of string data as sent,
//! which for a Huffman-coded string is its encoded length.
//!
//! Decoding checks, in order (invariant 7):
//!   1. the length decodes as a prefixed integer, or its error;
//!   2. that many octets of string data are present, or `error.Truncated` (invariant 9);
//!   3. Huffman-coded data decodes, or one of the three errors of RFC 7541 §5.2;
//!   4. the decoded string fits the caller's output, or `error.NoSpaceLeft`.
//! A failed decode moves neither the input cursor nor the output cursor.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("constants.zig");
const prefixed_integer = @import("prefixed_integer.zig");
const huffman = @import("huffman.zig");

const Reader = core.Reader;
const Writer = core.Writer;

pub const DecodeError = prefixed_integer.DecodeError || huffman.DecodeError;

/// How the string data is coded on the wire.
pub const Coding = enum { raw, huffman };

pub const Decoded = struct {
    coding: Coding,
    /// Octets of string data the literal carried, before any Huffman decoding.
    encoded_len: usize,
};

/// The H flag: the highest of the N prefix bits.
fn huffman_flag(comptime prefix_size: u4) u8 {
    comptime assert(prefix_size >= 2 and prefix_size <= 8);
    return @as(u8, 1) << (prefix_size - 1);
}

/// Decodes one literal whose H flag and length occupy the low `prefix_size` bits of the next
/// octet, writing the string it carries into `output`.
pub fn decode(comptime prefix_size: u4, reader: *Reader, output: *Writer) DecodeError!Decoded {
    const flag = huffman_flag(prefix_size);
    var cursor = reader.*;
    // RFC 9204 §4.1.2: one bit for the Huffman flag, then the length as an (N-1)-bit integer.
    const coding: Coding = if ((try cursor.peek_byte()) & flag != 0) .huffman else .raw;
    const length = try prefixed_integer.decode(prefix_size - 1, &cursor);
    // RFC 7541 §5.2: String Length is the number of octets used to encode the string literal.
    const encoded_len = std.math.cast(usize, length) orelse return error.Truncated;
    const data = try cursor.take(encoded_len);
    switch (coding) {
        .huffman => try huffman.decode(data, output),
        .raw => try output.write_bytes(data),
    }
    reader.* = cursor;
    return .{ .coding = coding, .encoded_len = encoded_len };
}

/// Encodes `bytes` as one literal whose H flag and length occupy the low `prefix_size` bits of the
/// first octet, below `high_bits`. All of the octets are written, or none.
pub fn encode(
    comptime prefix_size: u4,
    output: *Writer,
    high_bits: u8,
    bytes: []const u8,
    coding: Coding,
) core.writer.Error!void {
    const flag = huffman_flag(prefix_size);
    assert(high_bits & ((flag << 1) -% 1) == 0);
    var cursor = output.*;
    switch (coding) {
        .huffman => {
            const encoded_len = huffman.encoded_len(bytes);
            try prefixed_integer.encode(prefix_size - 1, &cursor, high_bits | flag, encoded_len);
            try huffman.encode(bytes, &cursor);
        },
        .raw => {
            try prefixed_integer.encode(prefix_size - 1, &cursor, high_bits, bytes.len);
            try cursor.write_bytes(bytes);
        },
    }
    output.* = cursor;
}

const testing = std.testing;

test "RFC 7541 Appendix C.4.1's authority literal decodes as Huffman" {
    const literal = [_]u8{ 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff };
    var reader = Reader.init(&literal);
    var buffer: [32]u8 = @splat(0);
    var output = Writer.init(&buffer);
    const decoded = try decode(8, &reader, &output);
    try testing.expectEqual(Coding.huffman, decoded.coding);
    try testing.expectEqual(12, decoded.encoded_len);
    try testing.expectEqualStrings("www.example.com", output.written());
    try testing.expectEqual(literal.len, reader.offset);
}

test "RFC 7541 Appendix C.2.1's raw literal decodes as written" {
    const literal = [_]u8{0x0a} ++ "custom-key".*;
    var reader = Reader.init(&literal);
    var buffer: [32]u8 = @splat(0);
    var output = Writer.init(&buffer);
    const decoded = try decode(8, &reader, &output);
    try testing.expectEqual(Coding.raw, decoded.coding);
    try testing.expectEqualStrings("custom-key", output.written());
}

test "every prefix size places the H flag and the length below the caller's bits" {
    inline for (2..9) |size| {
        const prefix_size: u4 = @intCast(size);
        const high_bits: u8 = if (size == 8) 0 else @as(u8, 0xff) << @intCast(size);
        for ([_]Coding{ .raw, .huffman }) |coding| {
            var buffer: [64]u8 = @splat(0);
            var output = Writer.init(&buffer);
            try encode(prefix_size, &output, high_bits, "no-cache", coding);
            const first = output.written()[0];
            try testing.expectEqual(high_bits, first & high_bits);
            try testing.expectEqual(coding == .huffman, first & huffman_flag(prefix_size) != 0);
            var reader = Reader.init(output.written());
            var decoded_buffer: [64]u8 = @splat(0);
            var decoded = Writer.init(&decoded_buffer);
            const result = try decode(prefix_size, &reader, &decoded);
            try testing.expectEqual(coding, result.coding);
            try testing.expectEqualStrings("no-cache", decoded.written());
            try testing.expectEqual(output.offset, reader.offset);
        }
    }
}

test "a length longer than the data present is Truncated and consumes nothing" {
    const literal = [_]u8{ 0x0b, 'c', 'u', 's', 't', 'o', 'm', '-', 'k', 'e', 'y' };
    var reader = Reader.init(&literal);
    var buffer: [32]u8 = @splat(0);
    var output = Writer.init(&buffer);
    try testing.expectError(error.Truncated, decode(8, &reader, &output));
    try testing.expectEqual(0, reader.offset);
    try testing.expectEqual(0, output.offset);
}

test "a Huffman error inside the data fails the literal and consumes nothing" {
    // H set, length 1, then 'a' followed by 000 padding.
    const literal = [_]u8{ 0x81, 0x18 };
    var reader = Reader.init(&literal);
    var buffer: [8]u8 = @splat(0);
    var output = Writer.init(&buffer);
    try testing.expectError(error.HuffmanPaddingNotEos, decode(8, &reader, &output));
    try testing.expectEqual(0, reader.offset);
}

test "a literal that does not fit the output moves neither cursor" {
    var buffer: [4]u8 = @splat(0xee);
    var output = Writer.init(&buffer);
    try testing.expectError(error.NoSpaceLeft, encode(8, &output, 0, "custom-key", .raw));
    try testing.expectEqual(0, output.offset);
    const literal = [_]u8{0x0a} ++ "custom-key".*;
    var reader = Reader.init(&literal);
    try testing.expectError(error.NoSpaceLeft, decode(8, &reader, &output));
    try testing.expectEqual(0, reader.offset);
    try testing.expectEqual(0, output.offset);
}

/// Most octets a fuzz input carries. Test-only.
const fuzz_input_len_max = 64;

fn fuzz_decode(_: void, smith: *testing.Smith) anyerror!void {
    const prefix_size: u4 = smith.valueRangeAtMost(u4, 2, 8);
    var input: [fuzz_input_len_max]u8 = @splat(0);
    const input_len = smith.slice(&input);
    var reader = Reader.init(input[0..input_len]);
    var buffer: [huffman.decoded_len_max(fuzz_input_len_max)]u8 = @splat(0);
    var output = Writer.init(&buffer);
    const decoded = switch (prefix_size) {
        inline 2...8 => |size| decode(size, &reader, &output),
        else => unreachable,
    } catch |err| {
        try testing.expect(err != error.NoSpaceLeft);
        try testing.expectEqual(0, reader.offset);
        try testing.expectEqual(0, output.offset);
        return;
    };
    try testing.expect(decoded.encoded_len < reader.offset);
    if (decoded.coding == .huffman) {
        try testing.expect(output.offset <= huffman.decoded_len_max(decoded.encoded_len));
    }
    comptime assert(constants.integer_len_max < fuzz_input_len_max);
}

test "fuzz: a literal consumes its whole length or nothing" {
    try testing.fuzz({}, fuzz_decode, .{ .corpus = &.{
        core.fuzz.input_with_value(8, "\x8c\xf1\xe3\xc2\xe5\xf2\x3a\x6b\xa0\xab\x90\xf4\xff"),
        core.fuzz.input_with_value(8, "\x0acustom-key"),
        core.fuzz.input_with_value(4, "\x2e\xa8\xeb\x10\x64\x9c\xbf"),
        core.fuzz.input_with_value(8, "\x81\x18"),
    } });
}

test "sweep: every input of up to two octets, at every prefix size, decodes whole or not at all" {
    try core.fuzz.sweep(fuzz_decode, .{ .min = 2, .max = 8 });
}
