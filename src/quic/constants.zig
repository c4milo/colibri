//! Limits quic owns (docs/design.md §7), and the fixed values of the version 1 wire format
//! (RFC 9000 §17). Never written inline (CLAUDE.md non-negotiable 4).
//!
//! `packet/invariant.zig` imports none of this: it reads RFC 8999 alone, and invariant 22 keeps
//! every version 1 value out of its reach.
const std = @import("std");
const assert = std.debug.assert;
const wire = @import("wire");
const crypto = @import("crypto");

/// QUIC version 1 (RFC 9000 §15).
pub const version_1: u32 = 0x00000001;

/// Most octets of a connection ID in version 1 (RFC 9000 §17.2): a long header that carries a
/// longer one MUST be dropped. RFC 8999 permits 255, and only the version 1 reader applies this.
pub const connection_id_len_max: u8 = 20;

/// What `quic` and a `crypto.Suite` must agree on is named once, in `crypto`, and read from here
/// under the same names: the packet number's range and field length (RFC 9000 §12.3, §17.1).
pub const packet_number_max: u64 = crypto.constants.packet_number_max;
pub const packet_number_len_max: u8 = crypto.constants.packet_number_len_max;
pub const packet_number_range_factor: u64 = crypto.constants.packet_number_range_factor;

/// Byte 0 of a version 1 packet (RFC 9000 §17.2, §17.3.1).
pub const fixed_bit: u8 = 0x40;
/// The Long Packet Type, and how far it sits from bit 0 (RFC 9000 §17.2, Table 5).
pub const long_packet_type_mask: u8 = 0x30;
pub const long_packet_type_shift: u3 = 4;
/// The Reserved Bits of a long header and of a short one. Both are under header protection, and
/// both MUST be 0 once it is removed.
pub const long_reserved_bits: u8 = 0x0c;
pub const short_reserved_bits: u8 = 0x18;
/// The Spin Bit and the Key Phase bit of a short header (RFC 9000 §17.3.1).
pub const spin_bit: u8 = 0x20;
pub const key_phase_bit: u8 = crypto.constants.key_phase_bit;
/// The Packet Number Length, one less than the field's length in octets (RFC 9000 §17.2).
pub const packet_number_len_mask: u8 = 0x03;
/// The four bits of a Retry packet's byte 0 that carry no meaning (RFC 9000 §17.2.5).
pub const retry_unused_bits: u8 = 0x0f;

/// The Retry Integrity Tag (RFC 9000 §17.2.5, RFC 9001 §5.8), the AEAD tag every protected packet
/// ends with (RFC 9001 §5.3), and the smallest Packet Number field and payload together
/// (RFC 9001 §5.4.2), as `crypto` names them.
pub const retry_integrity_tag_len: usize = crypto.constants.retry_integrity_tag_len;
pub const aead_tag_len: usize = crypto.constants.aead_tag_len;
pub const protected_len_min: usize = crypto.constants.protected_len_min;

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

/// Fewest octets of a connection ID a NEW_CONNECTION_ID may carry (RFC 9000 §19.15): a length
/// below 1 or above `connection_id_len_max` is a FRAME_ENCODING_ERROR.
pub const connection_id_len_min: u8 = 1;

/// The largest value a MAX_STREAMS or STREAMS_BLOCKED frame may carry (RFC 9000 §4.6, §19.11): a
/// larger one would permit a stream ID no variable-length integer can hold.
pub const max_streams_max: u64 = 1 << 60;

/// The largest offset a stream can reach, which is the largest variable-length integer
/// (RFC 9000 §19.8): the sum of a STREAM frame's offset and length may not exceed it.
pub const stream_offset_max: u64 = wire.constants.varint_value_max;

/// Ranges of received packet numbers one space remembers and reports (RFC 9000 §13.2.3): a
/// receiver limits them to bound an ACK frame and to avoid resource exhaustion. Past this many
/// the oldest is dropped, and a packet below what is left is discarded rather than processed,
/// because §12.3's certainty is gone.
pub const ack_ranges_max: usize = 32;

/// The packet number spaces of RFC 9000 §12.3: Initial, Handshake and Application data. 0-RTT
/// and 1-RTT share the last one, so the count is the encryption levels colibri uses.
pub const packet_number_spaces = crypto.suite.levels_count;

/// Ack-eliciting packets a receiver takes before it sends an ACK frame (RFC 9000 §13.2.2): a
/// receiver SHOULD send one after at least two.
pub const ack_eliciting_before_ack: u64 = 2;

/// Nanoseconds in a microsecond, which the ACK Delay field is measured in (RFC 9000 §19.3).
pub const nanoseconds_per_microsecond: u64 = 1_000;

/// Probe Timeouts the closing and draining states last, and the floor RFC 9000 §10.1 puts under
/// the idle timeout: §10.2 says both states SHOULD persist for at least three times the current
/// PTO, and §10.1 says the idle period MUST be at least that too, so several probes can be sent
/// and lost before a connection is given up.
pub const close_probe_timeouts: u64 = 3;

/// How the answers of a closing endpoint thin out (RFC 9000 §10.2.1): each one waits for this
/// many times as many received packets as the last, which is the "progressively increasing
/// number of received packets" the section offers.
pub const close_answer_backoff: u64 = 2;

/// Nanoseconds in a millisecond, which `max_idle_timeout` is advertised in (RFC 9000 §18.2).
pub const nanoseconds_per_millisecond: u64 = 1_000 * nanoseconds_per_microsecond;

/// Branches the compiler may take per octet of source and of needle while a comptime check scans
/// a source file for a name (`packet/packet_header.zig`, invariant 22).
pub const comptime_scan_branches_per_octet: u32 = 4;

/// Octets the Length field of a long header may be written in, which are the lengths of a
/// variable-length integer (RFC 9000 §16). A sender that has not built its payload yet reserves
/// one of these and knows its header's length.
pub const length_field_lens = wire.constants.varint_lens;

comptime {
    assert(frame_stream_last - frame_stream_first == stream_flag_off | stream_flag_len | stream_flag_fin);
    assert(frame_ack_ecn == frame_ack | frame_low_bit);
    assert(connection_id_len_min > 0 and connection_id_len_min <= connection_id_len_max);
    assert(max_streams_max < stream_offset_max);
    // RFC 9000 §12.3: the largest packet number is the largest variable-length integer.
    assert(packet_number_max == wire.constants.varint_value_max);
    assert(packet_number_len_mask + 1 == packet_number_len_max);
    assert(packet_number_len_mask == crypto.constants.packet_number_len_mask);
    assert(long_reserved_bits & ~crypto.constants.long_header_protected_bits == 0);
    assert(short_reserved_bits & ~crypto.constants.short_header_protected_bits == 0);
    assert(long_packet_type_mask >> long_packet_type_shift == 0x03);
    // The fields of byte 0 do not overlap, in either header form.
    assert(fixed_bit & long_packet_type_mask & long_reserved_bits & packet_number_len_mask == 0);
    assert(fixed_bit | long_packet_type_mask | long_reserved_bits | packet_number_len_mask == 0x7f);
    assert(fixed_bit | spin_bit | short_reserved_bits | key_phase_bit | packet_number_len_mask == 0x7f);
}
