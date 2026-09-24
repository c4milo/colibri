//! Limits h3 owns (docs/design.md §7). Never written inline (CLAUDE.md non-negotiable 4).
const std = @import("std");
const core = @import("core");
const qpack = @import("qpack");

/// The frame types of RFC 9114 §7.2. The gaps are deliberate: 0x02, 0x06, 0x08 and 0x09 are
/// HTTP/2 frame types with no HTTP/3 counterpart, and §7.2.8 makes receiving one a connection
/// error of H3_FRAME_UNEXPECTED rather than something to ignore.
pub const frame_data: u64 = 0x00;
pub const frame_headers: u64 = 0x01;
pub const frame_cancel_push: u64 = 0x03;
pub const frame_settings: u64 = 0x04;
pub const frame_push_promise: u64 = 0x05;
pub const frame_goaway: u64 = 0x07;
pub const frame_max_push_id: u64 = 0x0d;

/// RFC 9114 §11.2.1: the HTTP/2 frame types reserved in HTTP/3, which MUST NOT be sent and whose
/// receipt is a connection error. They are the HTTP/2 types whose function QUIC itself performs.
pub const frame_reserved_http2 = [_]u64{ 0x02, 0x06, 0x08, 0x09 };

/// The unidirectional stream types of RFC 9114 §6.2, and QPACK's two from RFC 9204 §4.2.
pub const stream_control: u64 = 0x00;
pub const stream_push: u64 = 0x01;
pub const stream_qpack_encoder: u64 = 0x02;
pub const stream_qpack_decoder: u64 = 0x03;

/// RFC 9114 §6.2.3 and §7.2.8: stream types and frame types of the form `0x1f * N + 0x21` are
/// reserved to exercise the rule that an unknown type is ignored. One expression covers both,
/// because the two sections define the same form over separate spaces.
pub const reserved_step: u64 = 0x1f;
pub const reserved_base: u64 = 0x21;

/// Whether a type is one of the reserved ones (RFC 9114 §6.2.3, §7.2.8).
pub fn is_reserved(value: u64) bool {
    if (value < reserved_base) return false;
    return (value - reserved_base) % reserved_step == 0;
}

/// The settings of RFC 9114 §7.2.4.1 and RFC 9204 §5, by identifier.
pub const setting_max_field_section_size: u64 = 0x06;
pub const setting_qpack_max_table_capacity: u64 = 0x01;
pub const setting_qpack_blocked_streams: u64 = 0x07;

/// RFC 9114 §7.2.4.1: the HTTP/2 setting identifiers reserved in HTTP/3, whose receipt is a
/// connection error of H3_SETTINGS_ERROR.
pub const setting_reserved_http2 = [_]u64{ 0x02, 0x03, 0x04, 0x05 };

/// The error codes of RFC 9114 §8.1.
pub const error_no_error: u64 = 0x0100;
pub const error_general_protocol: u64 = 0x0101;
pub const error_internal: u64 = 0x0102;
pub const error_stream_creation: u64 = 0x0103;
pub const error_closed_critical_stream: u64 = 0x0104;
pub const error_frame_unexpected: u64 = 0x0105;
pub const error_frame_error: u64 = 0x0106;
pub const error_excessive_load: u64 = 0x0107;
pub const error_id_error: u64 = 0x0108;
pub const error_settings_error: u64 = 0x0109;
pub const error_missing_settings: u64 = 0x010a;
pub const error_request_rejected: u64 = 0x010b;
pub const error_request_cancelled: u64 = 0x010c;
pub const error_request_incomplete: u64 = 0x010d;
pub const error_message_error: u64 = 0x010e;
pub const error_connect_error: u64 = 0x010f;
pub const error_version_fallback: u64 = 0x0110;

/// The streams each endpoint opens for the whole connection: its control stream and QPACK's
/// encoder and decoder streams (RFC 9114 §6.2.1, RFC 9204 §4.2).
pub const critical_streams: u32 = 3;

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
pub const frame_length_max: u32 = core.constants.field_section_size_max;

/// The longest frame header: a type and a length, each a variable-length integer of at most eight
/// octets (RFC 9114 §7.1, RFC 9000 §16). A unidirectional stream header is shorter still.
pub const frame_header_len_max: u32 = 16;

/// The longest QPACK field section prefix (RFC 9204 §4.5.1): two prefixed integers of up to 62
/// bits, each at most one octet plus one for every seven bits.
pub const section_prefix_len_max: usize = 20;

/// The most octets a QPACK field line representation adds to its name and value (RFC 9204
/// §4.5.2 to §4.5.6): its pattern octet and the prefixed integers of a name index or length and
/// of a value length, within colibri's field limits.
pub const line_representation_len_max: usize = 8;

/// Where a frame is copied out of `quic` before it is read (decision 80), and where a field section
/// is encoded before its frame header goes in front of it: a frame header and the longest field
/// section, encoded or received.
pub const scratch_len: usize = frame_header_len_max + frame_length_max + section_prefix_len_max;

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
pub const encoder_buffer_len: usize = qpack.constants.dynamic_table_capacity_max;
pub const decoder_buffer_len: usize = qpack.constants.decoder_instructions_owed_max * decoder_instruction_len_max;

/// The longest decoder instruction (RFC 9204 §4.4): a stream ID or an increment of up to 62 bits
/// in a prefixed integer with a 6-bit prefix, which takes one octet plus one per 7 bits.
pub const decoder_instruction_len_max: usize = 10;

/// The range RFC 9114 §7.2.4.1's reserved setting and §8.1's reserved error codes draw `N` from,
/// from the caller's grease value (design §6.5). Small, so each reserved value fits a short
/// variable-length integer.
pub const grease_range: u64 = 1024;

/// One in this many errors the connection would send as H3_NO_ERROR goes out as a reserved code
/// instead (RFC 9114 §8.1: "with some probability").
pub const grease_error_one_in: u64 = 2;

comptime {
    const assert = std.debug.assert;
    // The three streams the connection opens, the peer's unidirectional ones and every request
    // stream fit the QUIC stream table together.
    assert(critical_streams + uni_streams_max + request_streams_max <= core.constants.streams_per_connection_max);
    // The critical streams, and at least one more, fit the peer's slots.
    assert(uni_streams_max > critical_streams);
    // One insert the QPACK encoder may make, at its largest, fits the encoder stream's buffer.
    assert(encoder_buffer_len >= qpack.constants.dynamic_table_capacity_max / qpack.constants.insert_size_divisor);
    // A whole encoder instruction fits the connection's scratch, so a partial one always completes.
    assert(scratch_len >= qpack.constants.encoder_instruction_len_max);
}

test "§6.2.3 and §7.2.8: the reserved types are 0x1f * N + 0x21 and nothing else" {
    const testing = std.testing;
    try testing.expect(is_reserved(0x21));
    try testing.expect(is_reserved(0x21 + 0x1f));
    try testing.expect(is_reserved(0x21 + 0x1f * 2));
    try testing.expect(!is_reserved(0x20));
    try testing.expect(!is_reserved(0x22));
    // No frame or stream type this document defines is reserved, so the two spaces do not clash.
    try testing.expect(!is_reserved(frame_data));
    try testing.expect(!is_reserved(frame_max_push_id));
    try testing.expect(!is_reserved(stream_qpack_decoder));
    for (frame_reserved_http2) |held| try testing.expect(!is_reserved(held));
}
