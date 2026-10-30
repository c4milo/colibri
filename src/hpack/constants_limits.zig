//! The bounds colibri chose for hpack, which size memory or bound a loop or a queue. Ask the
//! owner before changing one (CLAUDE.md): the test at the end pins each value.
//! Decision 137 groups them, and `constants.zig` exports this file as `limits`.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const wire = @import("wire");

/// The largest dynamic table colibri keeps, in octets of the RFC 7541 §4.1 accounting, in either
/// direction. Policy: the protocol leaves the maximum to the endpoint (§4.2), h2's initial value
/// is 4,096 (RFC 9113 §6.5.2), and colibri never advertises more than this, nor uses more of what
/// a peer advertises. It sizes the caller-owned storage of every `DynamicTable`. The owner ruled
/// 16,384 on 2026-09-16 so every directory of http2jp/hpack-test-case decodes in-process.
pub const dynamic_table_capacity_max: u32 = 16_384;

/// Most entries a dynamic table holds: every entry costs at least the overhead, so a table of
/// `dynamic_table_capacity_max` octets holds at most this many.
pub const dynamic_table_entries_max: u32 = dynamic_table_capacity_max / wire.constants.protocol.table_entry_overhead;

/// Longest name and value a literal may carry, in decoded octets: the field-length limits of
/// `core`, which RFC 7541 §7.4 asks the implementation to set. A longer literal is a decoding
/// error, because a decoder that stopped reading the block would desynchronise the dynamic table
/// (invariant 10).
pub const name_len_max: u32 = core.constants.limits.field_name_len_max;
pub const value_len_max: u32 = core.constants.limits.field_value_len_max;

/// Most field lines one block may hold. A block of n octets holds at most n representations, and
/// Most field lines one block may hold. A block of n octets holds at most n representations, and a caller that reads them one at a time needs no array. No decode loop reads this constant: `Block.next_other`, which `Block.next` calls for every line but an indexed one, is bounded by `size_updates_per_block_max`, and h2's loop by `h2.constants.limits.field_block_buffer_len`.
pub const block_len_max: u32 = core.constants.limits.field_section_size_max;

/// Most octets a fuzzed block holds. Test-only.
pub const fuzz_block_len_max: u32 = 64;

comptime {
    assert(dynamic_table_capacity_max >= 4096);
    assert(dynamic_table_entries_max * wire.constants.protocol.table_entry_overhead == dynamic_table_capacity_max);
    assert(name_len_max > 0 and value_len_max > 0);
}

test "the entry bound is exact: one more entry than it could not fit" {
    const smallest = wire.table_size.entry_size(0, 0);
    try std.testing.expect(smallest * dynamic_table_entries_max <= dynamic_table_capacity_max);
    try std.testing.expect(smallest * (dynamic_table_entries_max + 1) > dynamic_table_capacity_max);
}

test "decision 137: each limit holds the value the owner ruled" {
    // A failure here is a changed limit, which the owner rules on before this test changes.
    const expectEqual = @import("std").testing.expectEqual;
    try expectEqual(16384, dynamic_table_capacity_max);
    try expectEqual(512, dynamic_table_entries_max);
    try expectEqual(256, name_len_max);
    try expectEqual(8192, value_len_max);
    try expectEqual(16384, block_len_max);
    try expectEqual(64, fuzz_block_len_max);
}
