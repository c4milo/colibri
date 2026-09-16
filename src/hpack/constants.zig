//! Limits hpack owns (docs/design.md §7). Never written inline (CLAUDE.md non-negotiable 4).
//!
//! RFC 7541 §7.4 requires an implementation to set limits on the integers and the string
//! literals it accepts. The integer limits are `wire`'s. The string limits are the field-length
//! limits of `core`, so a name or a value the decoder accepts is one the field validators can
//! measure.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");

/// Entries in the static table, numbered from 1 (RFC 7541 Appendix A, §2.3.3).
pub const static_table_len: u32 = 61;

/// The largest dynamic table colibri keeps, in octets of the RFC 7541 §4.1 accounting, in either
/// direction. Policy: the protocol leaves the maximum to the endpoint (§4.2), h2's initial value
/// is 4,096 (RFC 9113 §6.5.2), and colibri never advertises more than this, nor uses more of what
/// a peer advertises. It sizes the caller-owned storage of every `DynamicTable`. The owner ruled
/// 16,384 on 2026-09-16 so every directory of http2jp/hpack-test-case decodes in-process.
pub const dynamic_table_capacity_max: u32 = 16_384;

/// Most entries a dynamic table holds: every entry costs at least the overhead, so a table of
/// `dynamic_table_capacity_max` octets holds at most this many.
pub const dynamic_table_entries_max: u32 = dynamic_table_capacity_max / wire.constants.table_entry_overhead;

/// Most dynamic table size updates one field block may start with. RFC 7541 §4.2: the smallest
/// maximum in the interval and the final one, "resulting in at most two".
pub const size_updates_per_block_max: u32 = 2;

/// Longest name and value a literal may carry, in decoded octets: the field-length limits of
/// `core`, which RFC 7541 §7.4 asks the implementation to set. A longer literal is a decoding
/// error, because a decoder that stopped reading the block would desynchronise the dynamic table
/// (invariant 10).
pub const name_len_max: u32 = core.constants.field_name_len_max;
pub const value_len_max: u32 = core.constants.field_value_len_max;

/// Most field lines one block may hold. A block of n octets holds at most n representations, and
/// a caller that reads them one at a time needs no array; this bounds the decode loop.
pub const block_len_max: u32 = core.constants.field_section_size_max;

/// The first-octet patterns of the five representations (RFC 7541 §6), each a mask over the
/// bits above its prefix.
pub const indexed_pattern: u8 = 0x80;
pub const incremental_pattern: u8 = 0x40;
pub const size_update_pattern: u8 = 0x20;
pub const never_indexed_pattern: u8 = 0x10;
pub const without_indexing_pattern: u8 = 0x00;

/// The prefix sizes of the representations' integers: 7 for an indexed field (§6.1), 6 for a
/// literal with incremental indexing (§6.2.1), 4 for the other two literals (§6.2.2, §6.2.3),
/// 5 for a size update (§6.3). A string literal's length takes a 7-bit prefix after its H flag,
/// which is the 8-bit prefix form of `wire.string_literal` (§5.2).
pub const indexed_prefix_bits: u4 = 7;
pub const incremental_prefix_bits: u4 = 6;
pub const literal_prefix_bits: u4 = 4;
pub const size_update_prefix_bits: u4 = 5;
pub const string_prefix_bits: u4 = 8;

/// Most octets a fuzzed block holds. Test-only.
pub const fuzz_block_len_max: u32 = 64;

comptime {
    assert(static_table_len > 0);
    // Each pattern's bits lie above its prefix, and the four non-zero patterns are distinct bits.
    assert(indexed_pattern == 1 << indexed_prefix_bits);
    assert(incremental_pattern == 1 << incremental_prefix_bits);
    assert(size_update_pattern == 1 << size_update_prefix_bits);
    assert(never_indexed_pattern == 1 << literal_prefix_bits);
    assert(without_indexing_pattern == 0);
    assert(dynamic_table_capacity_max >= 4096);
    assert(dynamic_table_entries_max * wire.constants.table_entry_overhead == dynamic_table_capacity_max);
    assert(size_updates_per_block_max == 2);
    assert(name_len_max > 0 and value_len_max > 0);
}

test "the entry bound is exact: one more entry than it could not fit" {
    const smallest = wire.table_size.entry_size(0, 0);
    try std.testing.expect(smallest * dynamic_table_entries_max <= dynamic_table_capacity_max);
    try std.testing.expect(smallest * (dynamic_table_entries_max + 1) > dynamic_table_capacity_max);
}
