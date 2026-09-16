//! Limits and format constants wire owns (docs/design.md §7). Never written inline (CLAUDE.md
//! non-negotiable 4).
//!
//! Two integer codecs live in `wire` and their limits are kept apart on purpose: the QUIC
//! variable-length integer is a framing primitive, and the prefixed integer is a field-compression
//! primitive (decision 11). They share a 62-bit ceiling and nothing else.
const std = @import("std");
const assert = std.debug.assert;

/// Largest value a QUIC variable-length integer carries: 62 usable bits (RFC 9000 §16).
pub const varint_value_max: u64 = (1 << 62) - 1;

/// Longest QUIC variable-length integer, in octets (RFC 9000 §16).
pub const varint_len_max: u8 = 8;

/// The four lengths a QUIC variable-length integer takes, in octets, shortest first (RFC 9000 §16,
/// Table 4).
pub const varint_lens = [_]u8{ 1, 2, 4, varint_len_max };

/// Bits of a QUIC variable-length integer's first octet that encode its length (RFC 9000 §16). The
/// rest of the encoding carries the value.
pub const varint_length_bits: u8 = 2;

/// Largest value the prefixed-integer decoder accepts. RFC 9204 §4.1.1 requires decoding integers
/// up to and including 62 bits long, and RFC 7541 §5.1 requires an integer over an implementation
/// limit to be treated as a decoding error, so 62 bits is both the floor and the limit.
pub const integer_value_max: u64 = (1 << 62) - 1;

/// Longest prefixed integer, in octets: the prefix octet and nine continuation octets. Nine
/// seven-bit groups carry the 62 bits `integer_value_max` needs past even a 1-bit prefix. RFC 7541
/// §5.1 requires an encoding longer than an implementation limit to be treated as a decoding
/// error, which is what stops a peer sending an unbounded run of zero-valued continuation octets.
pub const integer_len_max: u8 = 10;

/// Fewest and most bits a prefixed integer's prefix takes. RFC 7541 §5.1 names the prefix N and
/// leaves its size to the representation using it; colibri's codec takes every size an octet holds.
pub const integer_prefix_bits_min: u4 = 1;
pub const integer_prefix_bits_max: u4 = 8;

/// Fewest bits a string literal's prefix takes: the H flag and a 1-bit length prefix
/// (RFC 9204 §4.1.2). The most is `integer_prefix_bits_max`, HPACK's form (RFC 7541 §5.2).
pub const string_prefix_bits_min: u4 = 2;

/// Bits of value each continuation octet of a prefixed integer carries (RFC 7541 §5.1).
pub const integer_continuation_bits: u8 = 7;

/// Octets added to an entry's name and value lengths when a dynamic table's size is computed
/// (RFC 7541 §4.1, RFC 9204 §3.2.1). The RFCs estimate it as two 64-bit pointers and two 64-bit
/// reference counts, and fix it so both endpoints account alike.
pub const table_entry_overhead: u32 = 32;

/// Symbols in the Huffman code: the 256 octets and EOS (RFC 7541 Appendix B).
pub const huffman_symbol_count: u16 = 257;

/// The EOS symbol's index in the Huffman code (RFC 7541 Appendix B).
pub const huffman_eos_symbol: u16 = 256;

/// Shortest and longest Huffman codes, in bits (RFC 7541 Appendix B). The shortest bounds how far a
/// string expands when decoded: every symbol costs at least five bits.
pub const huffman_code_bits_min: u8 = 5;
pub const huffman_code_bits_max: u8 = 30;

/// Most padding bits a Huffman-coded string may end with. RFC 7541 §5.2 makes padding strictly
/// longer than 7 bits a decoding error.
pub const huffman_padding_bits_max: u8 = 7;

comptime {
    // Nine continuation groups must carry every value up to the ceiling past a 1-bit prefix.
    assert((integer_len_max - 1) * integer_continuation_bits >= 62);
    // The decoder accumulates in a u64 without overflow checks: the largest sum it can reach is
    // a full 8-bit prefix plus every continuation group full, which must fit.
    assert((integer_len_max - 1) * integer_continuation_bits <= 63);
    assert(integer_value_max == varint_value_max);
    assert(huffman_code_bits_min <= huffman_code_bits_max);
    assert(huffman_padding_bits_max < 8);
    assert(table_entry_overhead == 32);
    // The four lengths are the powers of two up to the longest, and the shortest carries a value.
    for (varint_lens, 0..) |len, index| assert(len == @as(u8, 1) << @intCast(index));
    assert(varint_lens[varint_lens.len - 1] * 8 - varint_length_bits == 62);
    assert(integer_prefix_bits_max == 8);
    assert(string_prefix_bits_min == integer_prefix_bits_min + 1);
}

test "the prefixed integer length limit is exactly what 62 bits need" {
    const groups = std.math.divCeil(u8, 62, integer_continuation_bits) catch unreachable;
    try std.testing.expectEqual(integer_len_max, 1 + groups);
}
