//! Limits the QIF tools of design §9 own. Never written inline (CLAUDE.md non-negotiable 4).
const std = @import("std");
const assert = std.debug.assert;

/// The largest file the tools read or write: a QIF input, or a file in the "QPACK Offline
/// Interop" format. The largest in the qpackers/qifs corpus is 352 KB.
pub const file_len_max: usize = 1 << 20;

/// The largest encoded field section, or encoder stream octets written with one, the encode tool
/// holds before it writes them to the file.
pub const section_len_max: usize = 64 * 1024;

/// Octets of decoder instructions the tools write at once: every Section Acknowledgment and
/// Stream Cancellation the decoder can queue, and an Insert Count Increment, with room to spare.
pub const decoder_stream_len_max: usize = 4096;

/// The offline format's block header: a 64-bit stream ID and a 32-bit length.
pub const block_header_len: usize = @sizeOf(u64) + @sizeOf(u32);

/// The offline format's stream ID for the encoder stream. Request streams start at 1.
pub const encoder_stream_id: u64 = 0;
pub const first_request_stream_id: u64 = 1;

comptime {
    assert(section_len_max < file_len_max);
    assert(first_request_stream_id != encoder_stream_id);
}
