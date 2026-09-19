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

/// Longest check name a trace's first line carries.
pub const check_name_len_max: u32 = 32;

/// Longest chunk the byte pipe hands the caller at once, in octets. A chunk is 1 to this many
/// octets, so a seed produces every split of a short value.
pub const chunk_len_max: u32 = 16;

/// Longest delay between two chunks, in nanoseconds: one millisecond.
pub const chunk_delay_ns_max: u64 = 1_000_000;

/// Seeds `zig build sim -- --<check>-check` runs when no count is given, and the seeds each check's
/// test runs.
pub const check_seeds_default: u64 = 256;

/// Most values one chunk-check stream carries before its refused tail, if it has one.
pub const chunk_check_values_max: u32 = 16;

/// Longest text one chunk-check string literal carries, in octets.
pub const chunk_check_text_len_max: u32 = 16;

/// Longest encoding of one chunk-check value, in octets. `chunk_stream.zig` pins it against the
/// longest Huffman literal.
pub const chunk_check_value_len_max: u32 = 72;

/// Longest chunk-check stream: every value at its longest, and a refused tail.
pub const chunk_check_stream_len_max: u32 = (chunk_check_values_max + 1) * chunk_check_value_len_max;

/// One chunk-check seed in this many, on average, ends its stream with a refused encoding.
pub const chunk_check_refusal_one_in: u64 = 4;

/// Most octets one chunk-check trace holds: a record for every octet fed, every value, the refusal,
/// and the first and last lines, each at its longest.
pub const chunk_check_trace_len_max: u32 =
    (chunk_check_stream_len_max + chunk_check_values_max + 3) * trace_record_len_max;

/// Most frames one connection-check plan draws, before the frames of its refusal if it has one.
/// It stays below h2's `rst_stream_rate_max`, which `connection_stream.zig` pins: a plan that
/// reached that rate limit would fail for an instant the pipe chose, and chunking would decide
/// the outcome.
pub const connection_check_frames_max: u32 = 24;

/// Most streams one connection-check plan opens: one per frame it draws.
pub const connection_check_streams_max: u32 = connection_check_frames_max;

/// Most DATA payload octets one connection-check frame carries.
pub const connection_check_data_len_max: u32 = 64;

/// The fragments one connection-check field block is cut into: the HEADERS frame and the
/// CONTINUATION frames that follow it. A cut block has at least two, or no CONTINUATION frame
/// follows and it is not cut at all.
pub const connection_check_fragments_min: u32 = 2;
pub const connection_check_fragments_max: u32 = 4;

/// The SETTINGS_INITIAL_WINDOW_SIZE a connection-check plan advertises when it advertises a small
/// one: a window that holds several DATA frames and far less than the initial value.
pub const connection_check_window_size_small: u32 = 1024;

/// Largest WINDOW_UPDATE increment one connection-check frame carries. It is small so that the
/// increments of a whole plan cannot take a flow-control window near its maximum, which would end
/// the connection rather than exercise the window.
pub const connection_check_increment_max: u32 = 4096;

/// Identifiers a connection-check plan's first request may open. The lowest is the second one a
/// client may use, never the first, so the first identifier stays below the watermark and the
/// `headers_below_watermark` refusal always has one to name.
pub const connection_check_first_stream_ids: u64 = 3;

/// Most identifiers of its own parity a connection-check plan steps over between two requests. A
/// step above one leaves identifiers the peer never opened below the watermark.
pub const connection_check_stream_id_steps: u64 = 3;

/// One connection-check seed in this many, on average, ends its stream with frames the connection
/// refuses.
pub const connection_check_refusal_one_in: u64 = 4;

/// Most octets the client connection preface and the SETTINGS frame after it take.
pub const connection_check_preface_len_max: u32 = 64;

/// Most octets one drawn connection-check frame takes, the frames that continue it included.
pub const connection_check_frame_len_max: u32 = 96;

/// Most frames one connection-check refusal writes.
pub const connection_check_refusal_frames_max: u32 = 2;

/// Longest connection-check stream: the preface, every frame at its longest, and a refusal.
pub const connection_check_stream_len_max: u32 = connection_check_preface_len_max +
    (connection_check_frames_max + connection_check_refusal_frames_max) * connection_check_frame_len_max;

/// Most octets one connection-check trace holds: a record for every octet fed, every frame the
/// connection consumed, and the first and last lines, each at its longest.
pub const connection_check_trace_len_max: u32 = (connection_check_stream_len_max +
    connection_check_frames_max * connection_check_fragments_max +
    connection_check_refusal_frames_max + 3) * trace_record_len_max;

/// Octets the connection-check subject gives the connection to write the frames it owes: its own
/// SETTINGS frame and every reply its queues can hold. `connection_check.zig` pins it.
pub const connection_check_output_len_max: u32 = 1024;

comptime {
    assert(trace_version > 0);
    assert(chunk_len_max > 0);
    // The first line holds its fixed words, the check name and a 64-bit seed in hexadecimal.
    assert(trace_record_len_max > check_name_len_max + 64);
    assert(check_seeds_default > 0);
    assert(connection_check_frames_max > 0);
    assert(connection_check_fragments_min > 1);
    assert(connection_check_fragments_max >= connection_check_fragments_min);
    assert(connection_check_window_size_small > 0);
    assert(connection_check_first_stream_ids > 0 and connection_check_stream_id_steps > 0);
    assert(connection_check_refusal_one_in > 1);
}

test "a chunk and a trace record are never empty" {
    try std.testing.expect(chunk_len_max >= 1);
    try std.testing.expect(trace_record_len_max >= 1);
}

/// The offsets inside the record header RFC 8446 §5.1 defines, for the null provider's framing.
pub const record_content_type_offset: u32 = 0;
pub const record_version_offset: u32 = 1;
pub const record_length_offset: u32 = 3;

/// RFC 8446 §5.1: legacy_record_version is 0x0303 on every record a TLS 1.3 endpoint writes after
/// the first flight. Both octets are the same value.
pub const record_legacy_version_octet: u8 = 0x03;

/// The octets a real AEAD adds to every record (RFC 8446 §5.2). The null provider writes as many
/// zeros, so a record occupies what one would occupy on the wire.
pub const record_tag_len: u32 = 16;

/// The largest h2 byte stream the TLS check wraps in records: a preface, a SETTINGS frame and one
/// request. It is fixed, because what the check varies is where the records cut it.
pub const tls_check_stream_len_max: u32 = 512;

/// Where the TLS check's connection writes what it owes, which the check drops.
pub const tls_check_output_len_max: u32 = 1024;

/// The plaintext one `decrypt` call writes, which is one record's body.
pub const tls_check_plaintext_len_max: u32 = tls_check_stream_len_max;

/// Records one seed may cut the stream into, which bounds the check's loop (non-negotiable 4).
pub const tls_check_records_max: u32 = 64;

/// The events one run may record, which is one per frame the connection accepted.
pub const tls_check_events_max: u32 = 32;

/// The octets a record adds around its body: the header RFC 8446 §5.1 defines, whose last field is
/// the two-octet length, and the tag §5.2 sizes.
pub const record_overhead_len: u32 = record_length_offset + @sizeOf(u16) + record_tag_len;

/// The buffers the counted-cost check drives one request through. They are generous on purpose:
/// what the check measures is how many times the caller crosses colibri's boundary and how many
/// octets cross with it, not what a small buffer forces.
pub const cost_check_buffer_len: u32 = 4096;
