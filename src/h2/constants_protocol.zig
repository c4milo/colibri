//! The values the RFCs fix for h2, which no one may change.
//! Decision 137 groups them, and `constants.zig` exports this file as `protocol`.
const std = @import("std");
const assert = std.debug.assert;

// Frame format (RFC 9113 §4.1).

/// Octets in every frame header, not counted in its Length field (RFC 9113 §4.1).
pub const frame_header_len: u32 = 9;

/// Octets of the Length field: a 24-bit integer (RFC 9113 §4.1).
pub const frame_length_len: u32 = 3;

/// Largest value the 24-bit Length field holds (RFC 9113 §4.1).
pub const frame_length_max: u32 = (1 << 24) - 1;

/// Largest stream identifier: 31 bits (RFC 9113 §4.1, §5.1.1).
pub const stream_id_max: u32 = (1 << 31) - 1;

/// The stream identifier of a frame that concerns the connection as a whole (RFC 9113 §4.1).
pub const connection_stream_id: u32 = 0;

// Stream identifiers (RFC 9113 §5.1.1).

/// The two parities of stream identifiers: odd for a stream a client opens, even for one a server
/// opens (§5.1.1). They are the identifier classes of the stream table's slot pool.
pub const stream_id_parity_count: u32 = 2;

/// The first identifier a client opens: the lowest odd identifier (§5.1.1).
pub const stream_id_client_first: u32 = 1;

/// The first identifier a server opens: the lowest even identifier, since 0 is the connection's
/// and cannot open a stream (§5.1.1).
pub const stream_id_server_first: u32 = 2;

/// The distance from one identifier colibri opens to the next it opens: the next identifier of the
/// same parity, which is numerically greater, as §5.1.1 requires, and skips none.
pub const stream_id_step: u32 = 2;

/// The mask of the reserved bit above a 31-bit identifier or window increment, ignored on receipt
/// and unset on send (RFC 9113 §4.1, §6.6, §6.8, §6.9).
pub const reserved_bit_mask: u32 = 1 << 31;

/// The mask of the Exclusive bit above the 31-bit Stream Dependency of the priority fields a
/// HEADERS frame carries under the PRIORITY flag (§6.2) and a PRIORITY frame always carries (§6.3).
pub const exclusive_bit_mask: u32 = 1 << 31;

// Frame types (RFC 9113 §6).

pub const frame_type_data: u8 = 0x00;
pub const frame_type_headers: u8 = 0x01;
pub const frame_type_priority: u8 = 0x02;
pub const frame_type_rst_stream: u8 = 0x03;
pub const frame_type_settings: u8 = 0x04;
pub const frame_type_push_promise: u8 = 0x05;
pub const frame_type_ping: u8 = 0x06;
pub const frame_type_goaway: u8 = 0x07;
pub const frame_type_window_update: u8 = 0x08;
pub const frame_type_continuation: u8 = 0x09;

// Extension frame types (RFC 9113 §5.5), each from the RFC that defines it.

/// RFC 7838 §4: "The ALTSVC frame type is 0xa (decimal 10)."
pub const frame_type_altsvc: u8 = 0x0a;
/// RFC 7838 §4: the Origin-Len field that starts an ALTSVC payload, "an unsigned, 16-bit integer".
pub const altsvc_origin_len_len: u32 = @sizeOf(u16);

// Flags, by the frames that define them (RFC 9113 §6.1 to §6.10). A flag bit a frame type does not
// define is unused: ignored on receipt and unset on send (§4.1).

/// END_STREAM on DATA (§6.1) and HEADERS (§6.2).
pub const flag_end_stream: u8 = 0x01;
/// ACK on SETTINGS (§6.5) and PING (§6.7).
pub const flag_ack: u8 = 0x01;
/// END_HEADERS on HEADERS (§6.2), PUSH_PROMISE (§6.6) and CONTINUATION (§6.10).
pub const flag_end_headers: u8 = 0x04;
/// PADDED on DATA (§6.1), HEADERS (§6.2) and PUSH_PROMISE (§6.6).
pub const flag_padded: u8 = 0x08;
/// PRIORITY on HEADERS (§6.2), deprecated but still parsed (decision 18).
pub const flag_priority: u8 = 0x20;

// Fixed payload shapes (RFC 9113 §6).

/// Octets of the Pad Length field, and the most padding it can name (§6.1).
pub const pad_length_len: u32 = 1;
pub const padding_len_max: u32 = std.math.maxInt(u8);

/// Octets of the Exclusive bit, Stream Dependency and Weight that the PRIORITY flag adds to a
/// HEADERS payload (§6.2), and the whole payload of a PRIORITY frame (§6.3).
pub const priority_fields_len: u32 = 5;

/// The payload of a RST_STREAM frame: one error code (§6.4).
pub const rst_stream_len: u32 = 4;

/// Octets per setting in a SETTINGS payload: a 16-bit identifier and a 32-bit value (§6.5.1).
pub const setting_len: u32 = 6;

/// The payload of a PING frame: eight octets of opaque data (§6.7).
pub const ping_len: u32 = 8;

/// The fixed part of a GOAWAY payload: the last stream identifier and the error code, before any
/// debug data (§6.8).
pub const goaway_len_min: u32 = 8;

/// Octets of the Promised Stream ID field of a PUSH_PROMISE payload (§6.6).
pub const promised_stream_id_len: u32 = 4;

/// The payload of a WINDOW_UPDATE frame: one 31-bit increment (§6.9).
pub const window_update_len: u32 = 4;

// Settings (RFC 9113 §6.5.2).

pub const setting_header_table_size: u16 = 0x01;
pub const setting_enable_push: u16 = 0x02;
pub const setting_max_concurrent_streams: u16 = 0x03;
pub const setting_initial_window_size: u16 = 0x04;
pub const setting_max_frame_size: u16 = 0x05;
pub const setting_max_header_list_size: u16 = 0x06;

/// Initial values (RFC 9113 §6.5.2). MAX_CONCURRENT_STREAMS and MAX_HEADER_LIST_SIZE start
/// unlimited, which is why colibri always advertises both (design §6.1).
pub const header_table_size_initial: u32 = 4096;
pub const enable_push_initial: u32 = 1;
pub const initial_window_size_initial: u32 = 65_535;
pub const max_frame_size_initial: u32 = 1 << 14;

/// The two values SETTINGS_ENABLE_PUSH may take (§6.5.2): any other is a connection error of
/// PROTOCOL_ERROR. colibri never pushes (decision 17), so a client sends `enable_push_disabled`
/// and a server omits the setting, which §6.5.2 lets it do.
pub const enable_push_disabled: u32 = 0;
pub const enable_push_enabled: u32 = 1;

/// The settings §6.5.2 defines, numbered 0x01 to 0x06, and so the most (identifier, value) pairs
/// colibri puts in one SETTINGS frame it sends.
pub const settings_count: u32 = 6;

/// The range SETTINGS_MAX_FRAME_SIZE may take: the initial value to the largest Length (§4.2,
/// §6.5.2). A value outside it is a connection error of PROTOCOL_ERROR.
pub const max_frame_size_min: u32 = max_frame_size_initial;
pub const max_frame_size_max: u32 = frame_length_max;

/// The largest flow-control window, and the largest SETTINGS_INITIAL_WINDOW_SIZE (§6.5.2, §6.9.1).
pub const window_max: u32 = (1 << 31) - 1;

// Error codes (RFC 9113 §7).

pub const error_no_error: u32 = 0x00;
pub const error_protocol_error: u32 = 0x01;
pub const error_internal_error: u32 = 0x02;
pub const error_flow_control_error: u32 = 0x03;
pub const error_settings_timeout: u32 = 0x04;
pub const error_stream_closed: u32 = 0x05;
pub const error_frame_size_error: u32 = 0x06;
pub const error_refused_stream: u32 = 0x07;
pub const error_cancel: u32 = 0x08;
pub const error_compression_error: u32 = 0x09;
pub const error_connect_error: u32 = 0x0a;
pub const error_enhance_your_calm: u32 = 0x0b;
pub const error_inadequate_security: u32 = 0x0c;
pub const error_http_1_1_required: u32 = 0x0d;

// The connection preface (RFC 9113 §3.4).

/// The 24 octets a client sends first: `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`.
pub const client_preface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
pub const client_preface_len: u32 = 24;

comptime {
    assert(client_preface.len == client_preface_len);
    // The flag bits each frame defines are distinct where two share a frame (§6.2).
    assert(flag_end_stream & flag_end_headers == 0 and flag_padded & flag_priority == 0);
    assert(flag_end_headers & flag_padded == 0 and flag_end_stream & flag_padded == 0);
    assert(goaway_len_min == rst_stream_len + promised_stream_id_len);
    // The header is the Length field, the Type octet, the Flags octet and the Stream Identifier.
    assert(frame_length_len + @sizeOf(u8) + @sizeOf(u8) + @sizeOf(u32) == frame_header_len);
    // ENABLE_PUSH starts enabled (§6.5.2), and its two legal values are distinct.
    assert(enable_push_initial == enable_push_enabled and enable_push_disabled != enable_push_enabled);
    // The six settings are numbered consecutively from 0x01, so the count is the identifier range.
    assert(settings_count == setting_max_header_list_size - setting_header_table_size + 1);
    // A client's first identifier is odd and a server's even and not the connection's (§5.1.1),
    // and one step keeps the parity.
    assert(stream_id_client_first % stream_id_parity_count == 1);
    assert(stream_id_server_first % stream_id_parity_count == 0);
    assert(stream_id_server_first != connection_stream_id and stream_id_step == stream_id_parity_count);
    // The largest identifier is odd: a client's last is `stream_id_max`, a server's the one below.
    assert(stream_id_max % stream_id_parity_count == 1);
}

test "the preface is the 24 octets RFC 9113 §3.4 gives, in hexadecimal" {
    const expected = "\x50\x52\x49\x20\x2a\x20\x48\x54\x54\x50\x2f\x32\x2e\x30\x0d\x0a\x0d\x0a\x53\x4d\x0d\x0a\x0d\x0a";
    try std.testing.expectEqualSlices(u8, expected, client_preface);
}

test "the ten frame types are numbered 0 to 9 and the fourteen error codes 0 to 13" {
    try std.testing.expectEqual(0, frame_type_data);
    try std.testing.expectEqual(9, frame_type_continuation);
    try std.testing.expectEqual(0, error_no_error);
    try std.testing.expectEqual(13, error_http_1_1_required);
}
