//! The bounds colibri chose for h3, which size memory or bound a loop or a queue. Ask the
//! owner before changing one (CLAUDE.md): the test at the end pins each value.
//! Decision 137 groups them, and `constants.zig` exports this file as `limits`.
const core = @import("core");
const qpack = @import("qpack");
const std = @import("std");
const assert = std.debug.assert;
const protocol = @import("constants_protocol.zig");

/// The unidirectional streams of the peer's that one connection tracks at once (design §7): the
/// three RFC 9114 §6.2 and RFC 9204 §4.2 make critical, and room for more whose type the
/// connection reads before it stops reading them (§6.2, §6.2.3). A caller's QUIC transport
/// parameter `initial_max_streams_uni` must not grant the peer more.
pub const uni_streams_max: u32 = 8;

/// The request streams one connection holds state for at once. RFC 9114 §6.1: "at least 100
/// request streams SHOULD be permitted at a time". A server's QUIC transport parameter
/// `initial_max_streams_bidi` must not grant the peer more.
pub const request_streams_max: u32 = 100;

/// The longest HEADERS frame payload the connection reads (design §7). It is the field section
/// size colibri accepts: RFC 9114 §10.5.1 lets an endpoint treat a larger section as malformed,
/// and an encoded section is rarely longer than the size §4.2.2 counts, which adds 32 octets a
/// line.
pub const frame_length_max: u32 = core.constants.limits.field_section_size_max;

/// Where a frame is copied out of `quic` before it is read (decision 80), and where a field section
/// is encoded before its frame header goes in front of it: a frame header and the longest field
/// section, encoded or received.
pub const scratch_len: usize = protocol.frame_header_len_max + frame_length_max + protocol.section_prefix_len_max;

/// Frames one `receive` reads on the control stream, and on one request stream, before it moves
/// on, so one busy stream cannot keep the others waiting.
pub const control_frames_per_call_max: u32 = 16;
pub const request_frames_per_call_max: u32 = 16;

/// Push IDs colibri grants a server (design §7). Decision 17 refuses server push, so a client
/// never sends MAX_PUSH_ID (RFC 9114 §4.6).
pub const push_ids_max: u32 = 0;

/// What the connection keeps of each of its own three streams until the peer acknowledges it
/// (decision 79). The control stream carries its type, one SETTINGS frame and a few GOAWAY
/// frames. The encoder stream holds a whole table's worth of inserts in flight. The decoder
/// stream holds every instruction the decoder may owe at once, each at most
/// `decoder_instruction_len_max`.
pub const control_buffer_len: usize = 256;
pub const encoder_buffer_len: usize = qpack.constants.limits.dynamic_table_capacity_max;
pub const decoder_buffer_len: usize = qpack.constants.limits.decoder_instructions_owed_max * protocol.decoder_instruction_len_max;

comptime {
    // One insert the QPACK encoder may make, at its largest, fits the encoder stream's buffer.
    assert(encoder_buffer_len >= qpack.constants.limits.dynamic_table_capacity_max / qpack.constants.policy.insert_size_divisor);
    // A whole encoder instruction fits the connection's scratch, so a partial one always completes.
    assert(scratch_len >= qpack.constants.limits.encoder_instruction_len_max);
}

test "decision 137: each limit holds the value the owner ruled" {
    // A failure here is a changed limit, which the owner rules on before this test changes.
    const expectEqual = @import("std").testing.expectEqual;
    try expectEqual(8, uni_streams_max);
    try expectEqual(100, request_streams_max);
    try expectEqual(16384, frame_length_max);
    try expectEqual(16420, scratch_len);
    try expectEqual(16, control_frames_per_call_max);
    try expectEqual(16, request_frames_per_call_max);
    try expectEqual(0, push_ids_max);
    try expectEqual(256, control_buffer_len);
    try expectEqual(16384, encoder_buffer_len);
    try expectEqual(640, decoder_buffer_len);
}
