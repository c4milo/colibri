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

/// Largest value the prefixed-integer decoder accepts. RFC 9204 §4.1.1 requires decoding integers
/// up to and including 62 bits long, and RFC 7541 §5.1 requires an integer over an implementation
/// limit to be treated as a decoding error, so 62 bits is both the floor and the limit.
pub const integer_value_max: u64 = (1 << 62) - 1;

/// Longest prefixed integer, in octets: the prefix octet and nine continuation octets. Nine
/// seven-bit groups carry the 62 bits `integer_value_max` needs past even a 1-bit prefix. RFC 7541
/// §5.1 requires an encoding longer than an implementation limit to be treated as a decoding
/// error, which is what stops a peer sending an unbounded run of zero-valued continuation octets.
pub const integer_len_max: u8 = 10;

/// Bits of value each continuation octet of a prefixed integer carries (RFC 7541 §5.1).
pub const integer_continuation_bits: u8 = 7;

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
}

test "the prefixed integer length limit is exactly what 62 bits need" {
    const groups = std.math.divCeil(u8, 62, integer_continuation_bits) catch unreachable;
    try std.testing.expectEqual(integer_len_max, 1 + groups);
}
