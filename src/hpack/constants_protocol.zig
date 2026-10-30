//! The values the RFCs fix for hpack, which no one may change.
//! Decision 137 groups them, and `constants.zig` exports this file as `protocol`.
const std = @import("std");
const assert = std.debug.assert;
const wire = @import("wire");

/// Entries in the static table, numbered from 1 (RFC 7541 Appendix A, §2.3.3).
pub const static_table_len: u32 = 61;

/// Most dynamic table size updates one field block may start with. RFC 7541 §4.2: the smallest
/// maximum in the interval and the final one, "resulting in at most two".
pub const size_updates_per_block_max: u32 = 2;

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

comptime {
    assert(static_table_len > 0);
    // Each pattern's bits lie above its prefix, and the four non-zero patterns are distinct bits.
    assert(indexed_pattern == 1 << indexed_prefix_bits);
    assert(incremental_pattern == 1 << incremental_prefix_bits);
    assert(size_update_pattern == 1 << size_update_prefix_bits);
    assert(never_indexed_pattern == 1 << literal_prefix_bits);
    assert(without_indexing_pattern == 0);
    assert(size_updates_per_block_max == 2);
}
