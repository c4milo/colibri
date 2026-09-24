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

/// RFC 9204 Appendix A: entries in the static table, numbered from 0 (§3.1).
pub const static_table_entries: u64 = 99;

/// The largest dynamic table colibri will hold, which is what it advertises as
/// `SETTINGS_QPACK_MAX_TABLE_CAPACITY` (RFC 9204 §3.2.3) when it uses one. The RFC bounds it at
/// nothing, so the bound is colibri's and the caller owns the storage (decision 35).
pub const dynamic_table_capacity_max: u32 = 16_384;

/// How many entries that many octets can hold. §3.2.1's smallest entry is 32 octets, so the
/// count follows the capacity and is not a second limit to keep in step.
pub const dynamic_table_entries_max: u32 = dynamic_table_capacity_max / @as(u32, @intCast(entry_overhead_len));

/// RFC 9204 §3.2.1: the size of an entry is its name and value lengths plus 32, which is what
/// makes the smallest possible entry 32 octets and bounds `MaxEntries` in §4.5.1.1.
pub const entry_overhead_len: u64 = 32;

/// RFC 9204 §4.3's encoder instructions, told apart by the high bits of the first octet.
///
/// §4.3.2, Insert with Name Reference: `1T` and a 6-bit name index.
pub const insert_name_reference_pattern: u8 = 0x80;
pub const insert_name_reference_mask: u8 = 0x80;
pub const insert_name_reference_static_flag: u8 = 0x40;
pub const insert_name_reference_prefix_bits: u4 = 6;

/// §4.3.3, Insert with Literal Name: `01`, then the name as a 6-bit prefix string literal and
/// the value as an 8-bit one.
pub const insert_literal_pattern: u8 = 0x40;
pub const insert_literal_mask: u8 = 0xc0;
pub const insert_literal_name_prefix_bits: u4 = 6;

/// §4.3.1, Set Dynamic Table Capacity: `001` and a 5-bit capacity.
pub const set_capacity_pattern: u8 = 0x20;
pub const set_capacity_mask: u8 = 0xe0;
pub const set_capacity_prefix_bits: u4 = 5;

/// §4.3.4, Duplicate: `000` and a 5-bit relative index.
pub const duplicate_pattern: u8 = 0x00;
pub const duplicate_mask: u8 = 0xe0;
pub const duplicate_prefix_bits: u4 = 5;

/// RFC 9204 §4.4's decoder instructions, told apart the same way.
///
/// §4.4.1, Section Acknowledgment: `1` and a 7-bit stream identifier.
pub const section_acknowledgment_pattern: u8 = 0x80;
pub const section_acknowledgment_mask: u8 = 0x80;
pub const section_acknowledgment_prefix_bits: u4 = 7;

/// §4.4.2, Stream Cancellation: `01` and a 6-bit stream identifier.
pub const stream_cancellation_pattern: u8 = 0x40;
pub const stream_cancellation_mask: u8 = 0xc0;
pub const stream_cancellation_prefix_bits: u4 = 6;

/// §4.4.3, Insert Count Increment: `00` and a 6-bit increment.
pub const insert_count_increment_pattern: u8 = 0x00;
pub const insert_count_increment_mask: u8 = 0xc0;
pub const insert_count_increment_prefix_bits: u4 = 6;

/// How many field sections with dynamic table references may be outstanding at once, across
/// every stream. RFC 9204 bounds this at nothing — §2.1.1 only requires an encoder to track
/// them — so the bound is colibri's, and an encoder that reaches it falls back to a
/// representation that references nothing rather than losing track of one.
pub const outstanding_sections_max: usize = 64;

/// The most streams the decoder holds as blocked (RFC 9204 §2.1.2), and so the most it may
/// advertise as `SETTINGS_QPACK_BLOCKED_STREAMS` (§5). Decision 74: the decoder keeps each one's
/// stream ID and Required Insert Count, and the caller keeps its octets.
pub const blocked_streams_max: u64 = 100;

/// Section Acknowledgments and Stream Cancellations the decoder may owe before the caller writes
/// its decoder stream (decision 74). A decoder whose queue is full decodes nothing more until the
/// caller writes, so no instruction is dropped.
pub const decoder_instructions_owed_max: usize = 64;

/// The longest encoder instruction the decoder waits for (decision 74), which is also the most
/// encoder stream octets a caller must hold. An instruction whose entry fits the largest table
/// fits here when its strings are sent raw; RFC 9204 §7.4 lets a decoder refuse a longer one.
pub const encoder_instruction_len_max: usize = dynamic_table_capacity_max;

/// The error codes of RFC 9204 §6, which HTTP/3 carries when QPACK cannot continue.
pub const error_decompression_failed: u64 = 0x0200;
pub const error_encoder_stream: u64 = 0x0201;
pub const error_decoder_stream: u64 = 0x0202;
