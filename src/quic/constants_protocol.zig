//! The values the RFCs fix for quic, which no one may change.
//! Decision 137 groups them, and `constants.zig` exports this file as `protocol`.
const std = @import("std");
const assert = std.debug.assert;
const wire = @import("wire");
const crypto = @import("crypto");
const constants = @import("constants.zig");

/// QUIC version 1 (RFC 9000 §15), named once in `crypto` because a suite's calls name it too
/// (decision 108).
pub const version_1: u32 = @intFromEnum(crypto.suite.Version.v1);
/// QUIC version 2 (RFC 9369 §3.1), named in `crypto` for the same reason.
pub const version_2: u32 = @intFromEnum(crypto.suite.Version.v2);

/// Most octets of a connection ID in version 1 (RFC 9000 §17.2): a long header that carries a
/// longer one MUST be dropped. RFC 8999 permits 255, and only the version 1 reader applies this.
/// Named in `crypto`, because a Retry token carries two (decision 55).
pub const connection_id_len_max: u8 = crypto.constants.protocol.connection_id_len_max;

/// What `quic` and a `crypto.Suite` must agree on is named once, in `crypto`, and read from here
/// under the same names: the packet number's range and field length (RFC 9000 §12.3, §17.1).
pub const packet_number_max: u64 = crypto.constants.protocol.packet_number_max;
pub const packet_number_len_max: u8 = crypto.constants.protocol.packet_number_len_max;
pub const packet_number_range_factor: u64 = crypto.constants.protocol.packet_number_range_factor;

/// Byte 0 of a version 1 packet (RFC 9000 §17.2, §17.3.1).
pub const fixed_bit: u8 = 0x40;

/// RFC 8999 §5.1's Header Form bit: 1 for a long header and 0 for a short one. It is an
/// invariant across QUIC versions, which is why RFC 9000 §10.3's Figure 10 can fix it.
pub const header_form_bit: u8 = 0x80;
/// The Long Packet Type, and how far it sits from bit 0 (RFC 9000 §17.2, Table 5).
pub const long_packet_type_mask: u8 = 0x30;
pub const long_packet_type_shift: u3 = 4;
/// The Reserved Bits of a long header and of a short one. Both are under header protection, and
/// both MUST be 0 once it is removed.
pub const long_reserved_bits: u8 = 0x0c;
pub const short_reserved_bits: u8 = 0x18;
/// The Spin Bit and the Key Phase bit of a short header (RFC 9000 §17.3.1).
pub const spin_bit: u8 = 0x20;
pub const key_phase_bit: u8 = crypto.constants.protocol.key_phase_bit;
/// The Packet Number Length, one less than the field's length in octets (RFC 9000 §17.2).
pub const packet_number_len_mask: u8 = 0x03;
/// The four bits of a Retry packet's byte 0 that carry no meaning (RFC 9000 §17.2.5).
pub const retry_unused_bits: u8 = 0x0f;

/// The Retry Integrity Tag (RFC 9000 §17.2.5, RFC 9001 §5.8), the AEAD tag every protected packet
/// ends with (RFC 9001 §5.3), and the smallest Packet Number field and payload together
/// (RFC 9001 §5.4.2), as `crypto` names them.
pub const retry_integrity_tag_len: usize = crypto.constants.protocol.retry_integrity_tag_len;
pub const aead_tag_len: usize = crypto.constants.protocol.aead_tag_len;
pub const protected_len_min: usize = crypto.constants.protocol.protected_len_min;

/// The frame types of RFC 9000 §19, as Table 3 in §12.4 lists them. A type is a variable-length
/// integer, and every one of these is a single octet (RFC 9000 §12.4).
pub const frame_padding: u64 = 0x00;
pub const frame_ping: u64 = 0x01;
/// ACK without and with the ECN counts of §19.3.2; the low bit says which.
pub const frame_ack: u64 = 0x02;
pub const frame_ack_ecn: u64 = 0x03;
pub const frame_reset_stream: u64 = 0x04;
pub const frame_stop_sending: u64 = 0x05;
pub const frame_crypto: u64 = 0x06;
pub const frame_new_token: u64 = 0x07;
/// STREAM, whose three low bits carry the OFF, LEN and FIN flags (§19.8).
pub const frame_stream_first: u64 = 0x08;
pub const frame_stream_last: u64 = 0x0f;
pub const frame_max_data: u64 = 0x10;
pub const frame_max_stream_data: u64 = 0x11;
/// MAX_STREAMS and STREAMS_BLOCKED, whose low bit says bidirectional or unidirectional.
pub const frame_max_streams_bidirectional: u64 = 0x12;
pub const frame_max_streams_unidirectional: u64 = 0x13;
pub const frame_data_blocked: u64 = 0x14;
pub const frame_stream_data_blocked: u64 = 0x15;
pub const frame_streams_blocked_bidirectional: u64 = 0x16;
pub const frame_streams_blocked_unidirectional: u64 = 0x17;
pub const frame_new_connection_id: u64 = 0x18;
pub const frame_retire_connection_id: u64 = 0x19;
pub const frame_path_challenge: u64 = 0x1a;
pub const frame_path_response: u64 = 0x1b;
/// CONNECTION_CLOSE for a transport error and for an application one (§19.19).
pub const frame_connection_close_transport: u64 = 0x1c;
pub const frame_connection_close_application: u64 = 0x1d;
pub const frame_handshake_done: u64 = 0x1e;

/// The three bits of a STREAM frame's type (RFC 9000 §19.8).
pub const stream_flag_off: u64 = 0x04;
pub const stream_flag_len: u64 = 0x02;
pub const stream_flag_fin: u64 = 0x01;

/// The low bit of an ACK type, which says the ECN counts follow (RFC 9000 §19.3.2), and of a
/// MAX_STREAMS or STREAMS_BLOCKED type, which says unidirectional (§19.11, §19.14).
pub const frame_low_bit: u64 = 0x01;

/// Octets of a PATH_CHALLENGE or PATH_RESPONSE payload (RFC 9000 §19.17, §19.18).
pub const path_challenge_len: usize = 8;

/// Octets of the Stateless Reset Token a NEW_CONNECTION_ID carries (RFC 9000 §19.15).
pub const stateless_reset_token_len: usize = 16;

/// Fewest octets of the Destination Connection ID a client's first Initial carries (RFC 9000
/// §7.2): it "MUST be at least 8 bytes in length", and the Initial keys come from it.
pub const initial_destination_len_min: usize = 8;

/// Fewest octets of a connection ID a NEW_CONNECTION_ID may carry (RFC 9000 §19.15): a length
/// below 1 or above `connection_id_len_max` is a FRAME_ENCODING_ERROR.
pub const connection_id_len_min: u8 = 1;

/// The largest value a MAX_STREAMS or STREAMS_BLOCKED frame may carry (RFC 9000 §4.6, §19.11): a
/// larger one would permit a stream ID no variable-length integer can hold.
pub const max_streams_max: u64 = 1 << 60;

/// The largest offset a stream can reach, which is the largest variable-length integer
/// (RFC 9000 §19.8): the sum of a STREAM frame's offset and length may not exceed it.
pub const stream_offset_max: u64 = wire.constants.protocol.varint_value_max;

/// The packet number spaces of RFC 9000 §12.3: Initial, Handshake and Application data. 0-RTT
/// and 1-RTT share the last one, so the count is the encryption levels colibri uses.
pub const packet_number_spaces = crypto.suite.levels_count;

/// The two low bits of a stream ID (RFC 9000 §2.1): the first names the initiator and the
/// second the directionality, so each of the four types has its own space of identifiers.
pub const stream_id_initiator_bit: u64 = 0x01;
pub const stream_id_directionality_bit: u64 = 0x02;
pub const stream_id_directionality_shift: u6 = 1;
pub const stream_id_type_bits: u6 = 2;

/// The largest stream ID, which is 62 bits (RFC 9000 §2.1), and the largest index within one
/// type, which is what is left after the two bits above.
pub const stream_id_max: u64 = wire.constants.protocol.varint_value_max;
pub const stream_index_max: u64 = stream_id_max >> stream_id_type_bits;

/// The four stream types of RFC 9000 §2.1 Table 1, which are the pool's classes, and the two
/// directionalities, which have separate limits under §4.6.
pub const stream_types: u32 = 4;
pub const stream_directionalities: usize = 2;

/// RFC 9000 §18.2: `active_connection_id_limit` MUST be at least 2, and a peer that sends less
/// is a TRANSPORT_PARAMETER_ERROR. Absent, a value of 2 is assumed.
pub const active_connection_id_limit_min: u64 = 2;

/// RFC 9000 §8: before a peer's address is validated an endpoint must not send it more than
/// this many times what it received from it, which is what stops a spoofed source address
/// turning an endpoint into an amplifier (invariant 18).
pub const anti_amplification_factor: u64 = 3;

/// RFC 9000 §14.1, §8.2.1: the smallest allowed maximum datagram size. A datagram carrying a
/// PATH_CHALLENGE reaches it, unless §8's limit forbids, so the path's MTU is tested too.
pub const datagram_len_min: u64 = 1200;

/// RFC 9000 §18.2: the default for `max_udp_payload_size` "is the maximum permitted UDP payload
/// of 65527", which is the largest datagram anything can hand colibri or ask it to write.
pub const datagram_len_max: u64 = 65527;

/// The smallest Stateless Reset (RFC 9000 §10.3): the 16-octet token, and five octets before it
/// so the Unpredictable Bits field carries the 38 bits that make the datagram look like a valid
/// short-header packet.
pub const stateless_reset_unpredictable_len_min: usize = 5;
pub const stateless_reset_len_min: usize = stateless_reset_unpredictable_len_min + stateless_reset_token_len;

/// RFC 9000 §10.3.3: a Stateless Reset must be smaller than three times the packet that
/// triggered it, which is §8's anti-amplification factor applied to a datagram this endpoint
/// cannot associate with a connection.
pub const stateless_reset_amplification_factor: u64 = anti_amplification_factor;

/// RFC 9000 §18.2: `max_ack_delay` is the peer's, in milliseconds, assumed to be 25 when absent
/// and invalid at 2^14 or above. It is held per connection and never as a limit of colibri's.
pub const max_ack_delay_default_ns: u64 = 25 * constants.nanoseconds_per_millisecond;
pub const max_ack_delay_invalid_at: u64 = 1 << 14;

/// Octets the Length field of a long header may be written in, which are the lengths of a
/// variable-length integer (RFC 9000 §16). A sender that has not built its payload yet reserves
/// one of these and knows its header's length.
pub const length_field_lens = wire.constants.protocol.varint_lens;

comptime {
    // RFC 9000 §14.1's floor is below §18.2's ceiling, or no datagram size would be legal.
    assert(datagram_len_min < datagram_len_max);
    // A packet that consumed nothing would not end the walk, so the divisor must be above zero.
    assert(protected_len_min + aead_tag_len > 0);
    // RFC 9000 §10.3: the resulting minimum size is 21 bytes.
    assert(stateless_reset_len_min == 21);
    assert(frame_stream_last - frame_stream_first == stream_flag_off | stream_flag_len | stream_flag_fin);
    assert(frame_ack_ecn == frame_ack | frame_low_bit);
    assert(connection_id_len_min > 0 and connection_id_len_min <= connection_id_len_max);
    assert(max_streams_max < stream_offset_max);
    // RFC 9000 §12.3: the largest packet number is the largest variable-length integer.
    assert(packet_number_max == wire.constants.protocol.varint_value_max);
    assert(packet_number_len_mask + 1 == packet_number_len_max);
    assert(packet_number_len_mask == crypto.constants.protocol.packet_number_len_mask);
    assert(long_reserved_bits & ~crypto.constants.protocol.long_header_protected_bits == 0);
    assert(short_reserved_bits & ~crypto.constants.protocol.short_header_protected_bits == 0);
    assert(long_packet_type_mask >> long_packet_type_shift == 0x03);
    // The fields of byte 0 do not overlap, in either header form.
    assert(fixed_bit & long_packet_type_mask & long_reserved_bits & packet_number_len_mask == 0);
    assert(fixed_bit | long_packet_type_mask | long_reserved_bits | packet_number_len_mask == 0x7f);
    assert(fixed_bit | spin_bit | short_reserved_bits | key_phase_bit | packet_number_len_mask == 0x7f);
}
