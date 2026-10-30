//! The bounds colibri chose for qpack, which size memory or bound a loop or a queue. Ask the
//! owner before changing one (CLAUDE.md): the test at the end pins each value.
//! Decision 137 groups them, and `constants.zig` exports this file as `limits`.
const protocol = @import("constants_protocol.zig");

/// The largest dynamic table colibri will hold, which is what it advertises as
/// `SETTINGS_QPACK_MAX_TABLE_CAPACITY` (RFC 9204 §3.2.3) when it uses one. The RFC bounds it at
/// nothing, so the bound is colibri's and the caller owns the storage (decision 35).
pub const dynamic_table_capacity_max: u32 = 16_384;

/// How many entries that many octets can hold. §3.2.1's smallest entry is 32 octets, so the
/// count follows the capacity and is not a second limit to keep in step.
pub const dynamic_table_entries_max: u32 = dynamic_table_capacity_max / @as(u32, @intCast(protocol.entry_overhead_len));

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

/// Most octets one fuzzed input holds: a field section, or encoder or decoder stream octets.
/// Test-only.
pub const fuzz_input_len_max: u32 = 64;

test "decision 137: each limit holds the value the owner ruled" {
    // A failure here is a changed limit, which the owner rules on before this test changes.
    const expectEqual = @import("std").testing.expectEqual;
    try expectEqual(16384, dynamic_table_capacity_max);
    try expectEqual(512, dynamic_table_entries_max);
    try expectEqual(64, outstanding_sections_max);
    try expectEqual(100, blocked_streams_max);
    try expectEqual(64, decoder_instructions_owed_max);
    try expectEqual(16384, encoder_instruction_len_max);
    try expectEqual(64, fuzz_input_len_max);
}
