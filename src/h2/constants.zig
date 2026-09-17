//! Limits and format constants h2 owns (docs/design.md §7, §6.1). Never written inline (CLAUDE.md
//! non-negotiable 4).
//!
//! Two kinds of number live here. The format constants are RFC 9113's: frame types, flag bits,
//! setting identifiers, error codes, the fixed frame lengths, the preface. The limits are colibri's,
//! each named because the RFC leaves the bound to the implementation and says so, or because the
//! initial value the RFC gives is "unlimited" and an endpoint that advertises nothing has bounded
//! nothing (design §6.1).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const hpack = @import("hpack");
const wire = @import("wire");

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
/// and unset on send (RFC 9113 §4.1, §6.2, §6.9).
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

/// Most settings one SETTINGS frame colibri accepts can carry: the largest payload it accepts
/// (`frame_size_max`) over `setting_len`. The bound of the loop that walks a SETTINGS payload
/// (§6.5.3: values are processed in the order they appear).
pub const settings_per_frame_max: u32 = frame_size_max / setting_len;

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

// Limits colibri chooses (design §7).

/// Largest frame payload colibri accepts and the SETTINGS_MAX_FRAME_SIZE it advertises: the
/// RFC 9113 §4.2 floor, which every implementation must accept, and colibri never raises it.
pub const frame_size_max: u32 = max_frame_size_initial;

/// Most CONTINUATION frames one field block may span. RFC 9113 §6.10 sets no cap, so this is the
/// bound invariant 14 names; one past it is a connection error of ENHANCE_YOUR_CALM (§10.5).
pub const continuation_count_max: u32 = 32;

/// The longest representation of one field line the decoder accepts, in encoded octets. RFC 7541
/// §7.4 asks for limits on integers and on string literals, and colibri's are
/// `wire.constants.integer_len_max` and hpack's `name_len_max` and `value_len_max`, in decoded
/// octets. This is the longest line within all three:
///
/// - two size updates (§4.2), which count toward the block's first line;
/// - a literal with a literal name, whose first octet carries index 0 in its prefix and so has no
///   continuation octets (§5.1, §6.2). An indexed name is shorter: one integer replaces that octet,
///   the name's length and the name;
/// - the name's and the value's lengths;
/// - a name and a value at their limits, each octet at the longest Huffman code (Appendix B).
///
/// Every integer is at its longest, because §5.1 does not forbid continuation octets that carry
/// zeros. A line is measured from the end of the line before it. The measure does not depend on
/// where the fragments were cut, because RFC 9113 §4.3 makes a field block logically equivalent to
/// a single frame.
///
/// No line the decoder accepts is longer, so this refuses nothing the field-length limits admit. It
/// bounds the octets the field-block slot keeps of a line a fragment cut: a cut line whose octets
/// fed so far are longer is one the decoder would refuse once whole, and is a connection error of
/// COMPRESSION_ERROR.
pub const representation_len_max: u32 =
    hpack.constants.size_updates_per_block_max * wire.constants.integer_len_max +
    @sizeOf(u8) + 2 * wire.constants.integer_len_max +
    wire.huffman.encoded_len_max(hpack.constants.name_len_max) +
    wire.huffman.encoded_len_max(hpack.constants.value_len_max);

/// Octets of the field-block slot's buffer (decision 40, invariant 14): the octets kept from a line
/// the last fragment cut, at most `representation_len_max`, then the fragment being decoded, at
/// most `frame_size_max`.
pub const field_block_buffer_len: u32 = representation_len_max + frame_size_max;

/// The SETTINGS_MAX_CONCURRENT_STREAMS colibri advertises: the slot pool's capacity, so a peer that
/// honours the setting never finds the pool full (§5.1.2). Advertised, or nothing is bounded.
pub const concurrent_streams_max: u32 = core.constants.streams_per_connection_max;

/// The SETTINGS_INITIAL_WINDOW_SIZE colibri advertises, and the window every stream starts with:
/// the RFC's initial value (§6.9.2).
pub const window_initial: u32 = initial_window_size_initial;

/// The SETTINGS_MAX_HEADER_LIST_SIZE colibri advertises: the field section it can hold, measured
/// the way §6.5.2 measures it. Advisory to the peer (§10.5.1); colibri enforces it on the decoded
/// section and still decodes every octet (invariant 10).
pub const header_list_size_max: u32 = core.constants.field_section_size_max;

/// The SETTINGS_HEADER_TABLE_SIZE colibri advertises: the RFC's initial value, kept small
/// (design §6.1). The decoder's storage is `hpack.constants.dynamic_table_capacity_max`.
pub const header_table_size_advertised: u32 = header_table_size_initial;

/// Most SETTINGS frames colibri has sent and not yet seen acknowledged. A sender that could not
/// bound this would hold unbounded pending values (§6.5.3).
pub const settings_pending_max: u32 = 4;

/// Most PING frames colibri has sent and not yet seen answered.
pub const ping_pending_max: u32 = 4;

/// Most RST_STREAM frames colibri sends in one `rst_stream_rate_period_ns`, after which invalid
/// requests are a connection error of ENHANCE_YOUR_CALM (§10.5: track the use of these features
/// and set limits).
pub const rst_stream_rate_max: u32 = 100;
pub const rst_stream_rate_period_ns: u64 = 1_000_000_000;

/// How long colibri waits for a SETTINGS acknowledgment before a connection error of
/// SETTINGS_TIMEOUT (§6.5.3 leaves "a reasonable amount of time" to the implementation).
pub const settings_timeout_ns: u64 = 10_000_000_000;

/// The receive window colibri lets a peer consume before it sends a WINDOW_UPDATE: half the
/// initial window, so the update is neither per frame nor too late (§6.9.1 advises against tiny
/// increments).
pub const window_update_threshold: u32 = window_initial / 2;

comptime {
    assert(client_preface.len == client_preface_len);
    assert(frame_size_max >= max_frame_size_min and frame_size_max <= max_frame_size_max);
    assert(window_initial <= window_max and initial_window_size_initial <= window_max);
    assert(window_update_threshold > 0 and window_update_threshold <= window_initial);
    assert(concurrent_streams_max > 0);
    assert(header_list_size_max >= core.constants.field_name_len_max + core.constants.field_value_len_max);
    assert(header_table_size_advertised <= hpack.constants.dynamic_table_capacity_max);
    assert(continuation_count_max > 0 and settings_pending_max > 0 and ping_pending_max > 0);
    // The longest line fits in the most fragments one block may span, so the CONTINUATION count
    // refuses no line the field-length limits admit (§6.10).
    assert(representation_len_max <= (continuation_count_max + 1) * frame_size_max);
    assert(rst_stream_rate_max > 0 and rst_stream_rate_period_ns > 0 and settings_timeout_ns > 0);
    // The flag bits each frame defines are distinct where two share a frame (§6.2).
    assert(flag_end_stream & flag_end_headers == 0 and flag_padded & flag_priority == 0);
    assert(flag_end_headers & flag_padded == 0 and flag_end_stream & flag_padded == 0);
    assert(goaway_len_min == rst_stream_len + promised_stream_id_len);
    // The header is the Length field, the Type octet, the Flags octet and the Stream Identifier.
    assert(frame_length_len + @sizeOf(u8) + @sizeOf(u8) + @sizeOf(u32) == frame_header_len);
    assert(settings_per_frame_max > 0 and settings_per_frame_max * setting_len <= frame_size_max);
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
