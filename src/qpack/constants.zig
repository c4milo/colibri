//! Limits qpack owns (docs/design.md §7). Never written inline (CLAUDE.md non-negotiable 4).
const std = @import("std");

test "constants compile" {
    try std.testing.expect(true);
}

/// The bit patterns that tell RFC 9204 §4.5's five field line representations apart, each read
/// from the high bits of the first octet, and the prefix each leaves for its integer.
///
/// §4.5.2, Indexed Field Line: `1T` and a 6-bit index.
pub const indexed_pattern: u8 = 0x80;
pub const indexed_pattern_mask: u8 = 0x80;
pub const indexed_static_flag: u8 = 0x40;
pub const indexed_prefix_bits: u4 = 6;

/// §4.5.4, Literal Field Line with Name Reference: `01NT` and a 4-bit name index.
pub const literal_name_reference_pattern: u8 = 0x40;
pub const literal_name_reference_mask: u8 = 0xc0;
pub const literal_name_reference_never_flag: u8 = 0x20;
pub const literal_name_reference_static_flag: u8 = 0x10;
pub const literal_name_reference_prefix_bits: u4 = 4;

/// §4.5.6, Literal Field Line with Literal Name: `001N`, then the name as a 4-bit prefix string
/// literal and the value as an 8-bit one.
pub const literal_pattern: u8 = 0x20;
pub const literal_mask: u8 = 0xe0;
pub const literal_never_flag: u8 = 0x10;
pub const literal_name_prefix_bits: u4 = 4;

/// §4.5.3, Indexed Field Line with Post-Base Index: `0001` and a 4-bit index.
pub const indexed_post_base_pattern: u8 = 0x10;
pub const indexed_post_base_mask: u8 = 0xf0;
pub const indexed_post_base_prefix_bits: u4 = 4;

/// §4.5.5, Literal Field Line with Post-Base Name Reference: `0000N` and a 3-bit name index.
pub const literal_post_base_pattern: u8 = 0x00;
pub const literal_post_base_mask: u8 = 0xf0;
pub const literal_post_base_never_flag: u8 = 0x08;
pub const literal_post_base_prefix_bits: u4 = 3;

/// Every representation encodes its value as an 8-bit prefix string literal (§4.5.4, §4.5.6).
pub const value_prefix_bits: u4 = 8;

/// §4.5.1: the field section prefix is the Required Insert Count with an 8-bit prefix, then the
/// Sign bit and the Delta Base with a 7-bit prefix.
pub const required_insert_count_prefix_bits: u4 = 8;
pub const delta_base_prefix_bits: u4 = 7;
pub const delta_base_sign_flag: u8 = 0x80;
