//! Limits h3 owns (docs/design.md §7). Never written inline (CLAUDE.md non-negotiable 4).
const std = @import("std");

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
