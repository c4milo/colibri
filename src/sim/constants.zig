//! Limits sim owns (docs/design.md §7). Never written inline (CLAUDE.md non-negotiable 4).
const std = @import("std");
const assert = std.debug.assert;

/// The version of the trace format, written on its first line (design §6.6). colibri's own
/// formats are versioned from the first commit (CLAUDE.md non-negotiable 6); a change to what a
/// trace line holds is a new version, never a silent edit.
pub const trace_version: u32 = 1;

/// Longest trace record, in octets, its newline included. A record is built whole before it is
/// written, so this sizes the line a record is built in.
pub const trace_record_len_max: u32 = 512;

/// Longest gate name a trace's first line carries.
pub const gate_name_len_max: u32 = 32;

/// Longest chunk the byte pipe hands the caller at once, in octets. A chunk is 1 to this many
/// octets, so a seed reaches every split of a short value.
pub const chunk_len_max: u32 = 16;

/// Longest delay between two chunks, in nanoseconds: one millisecond.
pub const chunk_delay_ns_max: u64 = 1_000_000;

/// Seeds `zig build sim -- --<gate>-gate` runs when no count is given, and the seeds each gate's
/// test runs.
pub const gate_seeds_default: u64 = 256;

/// Most values one chunk-gate stream carries before its refused tail, if it has one.
pub const chunk_gate_values_max: u32 = 16;

/// Longest text one chunk-gate string literal carries, in octets.
pub const chunk_gate_text_len_max: u32 = 16;

/// Longest encoding of one chunk-gate value, in octets. `chunk_stream.zig` pins it against the
/// longest Huffman literal.
pub const chunk_gate_value_len_max: u32 = 72;

/// Longest chunk-gate stream: every value at its longest, and a refused tail.
pub const chunk_gate_stream_len_max: u32 = (chunk_gate_values_max + 1) * chunk_gate_value_len_max;

/// One chunk-gate seed in this many, on average, ends its stream with a refused encoding.
pub const chunk_gate_refusal_one_in: u64 = 4;

/// Most octets one chunk-gate trace holds: a record for every octet fed, every value, the refusal,
/// and the first and last lines, each at its longest.
pub const chunk_gate_trace_len_max: u32 =
    (chunk_gate_stream_len_max + chunk_gate_values_max + 3) * trace_record_len_max;

comptime {
    assert(trace_version > 0);
    assert(chunk_len_max > 0);
    // The first line holds its fixed words, the gate name and a 64-bit seed in hexadecimal.
    assert(trace_record_len_max > gate_name_len_max + 64);
    assert(gate_seeds_default > 0);
}

test "a chunk and a trace record are never empty" {
    try std.testing.expect(chunk_len_max >= 1);
    try std.testing.expect(trace_record_len_max >= 1);
}
