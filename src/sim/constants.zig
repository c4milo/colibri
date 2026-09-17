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

/// Most frames one connection-gate plan draws, before the frames of its refusal if it has one.
/// It stays below h2's `rst_stream_rate_max`, which `connection_stream.zig` pins: a plan that
/// reached that rate limit would fail for an instant the pipe chose, and chunking would decide
/// the outcome.
pub const connection_gate_frames_max: u32 = 24;

/// Most streams one connection-gate plan opens: one per frame it draws.
pub const connection_gate_streams_max: u32 = connection_gate_frames_max;

/// Most DATA payload octets one connection-gate frame carries.
pub const connection_gate_data_len_max: u32 = 64;

/// The fragments one connection-gate field block is cut into: the HEADERS frame and the
/// CONTINUATION frames that follow it. A cut block has at least two, or no CONTINUATION frame
/// follows and it is not cut at all.
pub const connection_gate_fragments_min: u32 = 2;
pub const connection_gate_fragments_max: u32 = 4;

/// The SETTINGS_INITIAL_WINDOW_SIZE a connection-gate plan advertises when it advertises a small
/// one: a window that holds several DATA frames and far less than the initial value.
pub const connection_gate_window_size_small: u32 = 1024;

/// Largest WINDOW_UPDATE increment one connection-gate frame carries. It is small so that the
/// increments of a whole plan cannot take a flow-control window near its maximum, which would end
/// the connection rather than exercise the window.
pub const connection_gate_increment_max: u32 = 4096;

/// Identifiers a connection-gate plan's first request may open. The lowest is the second one a
/// client may use, never the first, so the first identifier stays below the watermark and the
/// `headers_below_watermark` refusal always has one to name.
pub const connection_gate_first_stream_ids: u64 = 3;

/// Most identifiers of its own parity a connection-gate plan steps over between two requests. A
/// step above one leaves identifiers the peer never opened below the watermark.
pub const connection_gate_stream_id_steps: u64 = 3;

/// One connection-gate seed in this many, on average, ends its stream with frames the connection
/// refuses.
pub const connection_gate_refusal_one_in: u64 = 4;

/// Most octets the client connection preface and the SETTINGS frame after it take.
pub const connection_gate_preface_len_max: u32 = 64;

/// Most octets one drawn connection-gate frame takes, the frames that continue it included.
pub const connection_gate_frame_len_max: u32 = 96;

/// Most frames one connection-gate refusal writes.
pub const connection_gate_refusal_frames_max: u32 = 2;

/// Longest connection-gate stream: the preface, every frame at its longest, and a refusal.
pub const connection_gate_stream_len_max: u32 = connection_gate_preface_len_max +
    (connection_gate_frames_max + connection_gate_refusal_frames_max) * connection_gate_frame_len_max;

/// Most octets one connection-gate trace holds: a record for every octet fed, every frame the
/// connection consumed, and the first and last lines, each at its longest.
pub const connection_gate_trace_len_max: u32 = (connection_gate_stream_len_max +
    connection_gate_frames_max * connection_gate_fragments_max +
    connection_gate_refusal_frames_max + 3) * trace_record_len_max;

/// Octets the connection-gate subject gives the connection to write the frames it owes: its own
/// SETTINGS frame and every reply its queues can hold. `connection_stream.zig` pins it.
pub const connection_gate_output_len_max: u32 = 1024;

comptime {
    assert(trace_version > 0);
    assert(chunk_len_max > 0);
    // The first line holds its fixed words, the gate name and a 64-bit seed in hexadecimal.
    assert(trace_record_len_max > gate_name_len_max + 64);
    assert(gate_seeds_default > 0);
    assert(connection_gate_frames_max > 0);
    assert(connection_gate_fragments_min > 1);
    assert(connection_gate_fragments_max >= connection_gate_fragments_min);
    assert(connection_gate_window_size_small > 0);
    assert(connection_gate_first_stream_ids > 0 and connection_gate_stream_id_steps > 0);
    assert(connection_gate_refusal_one_in > 1);
}

test "a chunk and a trace record are never empty" {
    try std.testing.expect(chunk_len_max >= 1);
    try std.testing.expect(trace_record_len_max >= 1);
}
