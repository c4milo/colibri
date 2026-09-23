//! Limits quic owns (docs/design.md §7), and the fixed values of the version 1 wire format
//! (RFC 9000 §17). Never written inline (CLAUDE.md non-negotiable 4).
//!
//! `packet/invariant.zig` imports none of this: it reads RFC 8999 alone, and invariant 22 keeps
//! every version 1 value out of its reach.
const std = @import("std");
const assert = std.debug.assert;
const wire = @import("wire");
const core = @import("core");
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

/// Probe Timeouts RFC 9001 §6.5 measures both of its key update waits in: an endpoint "SHOULD
/// retain old read keys for no more than three times the PTO after having received a packet
/// protected using the new keys", and "SHOULD wait three times the PTO before initiating a key
/// update after receiving an acknowledgment that confirms that the previous key update was
/// received".
pub const key_update_probe_timeouts: u64 = 3;

/// Probe Timeouts RFC 9000 §8.2.4 gives a path validation before it is abandoned: "A value of
/// three times the larger of the current PTO or the PTO for the new path ... is RECOMMENDED",
/// which "allows for multiple PTOs to expire prior to failing path validation, so that loss of a
/// single PATH_CHALLENGE or PATH_RESPONSE frame does not cause path validation failure".
pub const path_probe_timeouts: u64 = 3;

comptime {
    // Both of §6.5's sentences say "three times the PTO", so the number is the RFC's and not a
    // knob: a change here is a change to what the specification asks for.
    assert(key_update_probe_timeouts == 3);
}

/// How the answers of a closing endpoint thin out (RFC 9000 §10.2.1): each one waits for this
/// many times as many received packets as the last, which is the "progressively increasing
/// number of received packets" the section offers.
pub const close_answer_backoff: u64 = 2;

/// Nanoseconds in a millisecond, which `max_idle_timeout` is advertised in (RFC 9000 §18.2).
pub const nanoseconds_per_millisecond: u64 = 1_000 * nanoseconds_per_microsecond;

/// The two low bits of a stream ID (RFC 9000 §2.1): the first names the initiator and the
/// second the directionality, so each of the four types has its own space of identifiers.
pub const stream_id_initiator_bit: u64 = 0x01;
pub const stream_id_directionality_bit: u64 = 0x02;
pub const stream_id_directionality_shift: u6 = 1;
pub const stream_id_type_bits: u6 = 2;

/// The largest stream ID, which is 62 bits (RFC 9000 §2.1), and the largest index within one
/// type, which is what is left after the two bits above.
pub const stream_id_max: u64 = wire.constants.varint_value_max;
pub const stream_index_max: u64 = stream_id_max >> stream_id_type_bits;

/// When a receiver advertises more flow control credit (RFC 9000 §4.2, which leaves the timing
/// to the implementation): once the peer has used this fraction of the window, so that a round
/// trip of silence would leave it blocked. A larger fraction sends fewer frames and risks the
/// peer stalling; a smaller one spends frames on credit the peer has not asked for.
pub const flow_credit_fraction: u64 = 2;

/// How the receive window grows (decision 49). A receiver that credits again within this many
/// round trips was draining faster than the peer could learn of the room, so the window and not
/// the path is the limit, and it is multiplied by the factor below. Two round trips is what
/// Chromium's QUIC, quiche and TCP's receive buffer auto-tuning all settle on: one for the
/// credit to reach the peer and one for the data to come back.
pub const flow_tune_round_trips: u64 = 2;
pub const flow_window_growth: u64 = 2;

/// The four stream types of RFC 9000 §2.1 Table 1, which are the pool's classes, and the two
/// directionalities, which have separate limits under §4.6.
pub const stream_types: u32 = 4;
pub const stream_directionalities: usize = 2;

/// Streams one connection holds at once. It bounds the table, and so bounds what this endpoint
/// advertises under §4.6: §3.2's implicit creation makes an advertised limit a promise to hold
/// that many streams at once.
pub const streams_per_connection_max: u32 = core.constants.streams_per_connection_max;

/// Connection IDs from the peer this endpoint holds at once. It is what
/// `active_connection_id_limit` advertises (RFC 9000 §18.2), which that parameter puts a floor
/// of 2 under, and it bounds the table that holds them.
pub const connection_ids_max: usize = 8;

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

/// The most packets one datagram can hold (RFC 9000 §12.2), which is what bounds the loop that
/// walks them. It over-counts on purpose: the divisor is only the Packet Number field, the
/// payload RFC 9001 §5.4.2 requires beside it and the authentication tag, leaving out every
/// header octet a real packet also carries. A datagram holds a handful in practice.
pub const coalesced_packets_max: usize = @intCast(datagram_len_max / (protected_len_min + aead_tag_len));

/// The most frames one packet can hold, which bounds the walk over a payload. RFC 9000 §19.1
/// makes PADDING one octet, and no frame is shorter, so a payload holds at most its own length
/// in frames. The reader takes a run of PADDING as one frame, so this over-counts too.
pub const frames_per_packet_max: usize = @intCast(datagram_len_max);

comptime {
    // RFC 9000 §14.1's floor is below §18.2's ceiling, or no datagram size would be legal.
    assert(datagram_len_min < datagram_len_max);
    // A packet that consumed nothing would not end the walk, so the divisor must be above zero.
    assert(protected_len_min + aead_tag_len > 0);
    assert(coalesced_packets_max > 0);
    assert(frames_per_packet_max > 0);
}

/// Octets of an Initial packet's Token field colibri will carry (RFC 9000 §17.2.2), and of a
/// Retry token a client repeats (§17.2.5.3). Both RFCs bound the field only by the packet that
/// carries it, so there is nothing to derive it from and
/// [decision 54](../../docs/decisions.md) rules it: 256 holds the authenticated, address-bound,
/// expiring token §8.1.1 describes, and the number is a judgement rather than a rule.
pub const token_len_max: usize = 256;

/// Octets of a Retry packet colibri will act on (RFC 9000 §17.2.5), less its Integrity Tag: byte
/// 0, the Version, both connection IDs with their length octets, and the Retry Token. It is
/// derived from limits already ruled, not a limit of its own: a Retry carrying a longer token is
/// one colibri could not repeat under §8.1.2, so it is discarded before this is needed.
pub const retry_len_max: usize = 1 + @sizeOf(u32) + 2 * (1 + connection_id_len_max) + token_len_max;

/// Octets of the Retry Pseudo-Packet of RFC 9001 §5.8: the Original Destination Connection ID
/// with its length octet, then the Retry packet less its tag.
pub const retry_pseudo_packet_len_max: usize = 1 + connection_id_len_max + retry_len_max;

/// Octets of the longest packet header colibri writes (RFC 9000 §17.2): byte 0, the Version, both
/// connection IDs with their length octets, an Initial's Token Length and Token, the Length field
/// and the Packet Number field.
pub const packet_header_len_max: usize = 1 + @sizeOf(u32) +
    2 * (1 + connection_id_len_max) +
    wire.constants.varint_len_max + token_len_max +
    wire.constants.varint_len_max + packet_number_len_max;

comptime {
    // A header must fit the smallest datagram §14.1 allows, or no Initial could ever be written.
    assert(packet_header_len_max < datagram_len_min);
}

/// Octets of out-of-order CRYPTO data colibri buffers per encryption level. RFC 9000 §7.5:
/// "Implementations MUST support buffering at least 4096 bytes of data received in out-of-order
/// CRYPTO frames." It is the RFC's floor and not a choice of colibri's: in-order data is handed
/// to the handshake as it arrives and never sits here, so this bounds only what a gap holds.
/// More than this is a connection error of CRYPTO_BUFFER_EXCEEDED, which §7.5 names for it.
pub const crypto_buffer_len: usize = 4096;

/// Octets of its own handshake flow colibri keeps per encryption level, so a CRYPTO frame can be
/// written again under a new packet number (RFC 9000 §13.3) and a client can repeat its first
/// flight after a Retry (§17.2.5.3). Nothing in either RFC sizes it, so it is a judgement, made
/// equal to the window §7.5 sets for the other direction: a flight that fits is never forgotten,
/// and a longer one forgets the octets it has already framed rather than stalling. Three levels
/// of it sit in every connection, which `Connection` pays for once.
pub const crypto_send_buffer_len: usize = crypto_buffer_len;

/// The smallest Stateless Reset (RFC 9000 §10.3): the 16-octet token, and five octets before it
/// so the Unpredictable Bits field carries the 38 bits that make the datagram look like a valid
/// short-header packet.
pub const stateless_reset_unpredictable_len_min: usize = 5;
pub const stateless_reset_len_min: usize = stateless_reset_unpredictable_len_min + stateless_reset_token_len;

/// RFC 9000 §10.3.3: a Stateless Reset must be smaller than three times the packet that
/// triggered it, which is §8's anti-amplification factor applied to a datagram this endpoint
/// cannot associate with a connection.
pub const stateless_reset_amplification_factor: u64 = anti_amplification_factor;

/// The round trip estimator and loss detection of RFC 9002, whose Appendix A.2 names each one.
///
/// `kInitialRtt`: the estimate before any sample, which §6.2.2 recommends at 333 milliseconds.
/// The variation starts at half of it (§5.3).
pub const rtt_initial_ns: u64 = 333 * nanoseconds_per_millisecond;
pub const rtt_initial_variation_divisor: u64 = 2;

/// The weights of RFC 9002 §5.3's moving averages, as divisors: the smoothed estimate keeps
/// seven eighths of itself and the variation three quarters.
pub const rtt_smoothed_weight: u64 = 8;
pub const rtt_variation_weight: u64 = 4;

/// RFC 9002 §6.2.1: the Probe Timeout carries four times the variation.
pub const rtt_variation_factor: u64 = 4;

/// `kGranularity`: the timer granularity, which §6.1.2 recommends at 1 millisecond. A timeout
/// is never shorter, so a timer cannot expire the instant it is armed.
pub const rtt_granularity_ns: u64 = nanoseconds_per_millisecond;

/// `kTimeThreshold`: how far past an estimate a packet is declared lost by time, which §6.1.2
/// recommends at nine eighths.
pub const loss_time_threshold_numerator: u64 = 9;
pub const loss_time_threshold_denominator: u64 = 8;

/// `kPacketThreshold`: how many packets may arrive after one before it is declared lost, which
/// §6.1.1 recommends at 3.
pub const loss_packet_threshold: u64 = 3;

/// The congestion window of RFC 9002 §7.2, whose Appendix B.1 names each one.
///
/// `kInitialWindow`: ten maximum datagrams, held to the larger of 14,720 octets and two of them.
/// §7.2 takes the figure from the analysis it cites, raised for UDP's smaller header.
pub const congestion_window_initial_datagrams: u64 = 10;
pub const congestion_window_initial_len_max: u64 = 14_720;

/// `kMinimumWindow`: the smallest the window falls to on loss, on an increase in the peer's
/// ECN-CE count, or on persistent congestion, which §7.2 recommends at two maximum datagrams.
pub const congestion_window_minimum_datagrams: u64 = 2;

/// `kLossReductionFactor`: what the window is scaled by on a congestion event, which §7
/// recommends at one half.
pub const congestion_loss_reduction_divisor: u64 = 2;

/// How many packets one packet number space may hold outstanding, which bounds the table of
/// RFC 9002 Appendix A.1.1. The RFC bounds `sent_packets` at nothing, so this bound is colibri's
/// and a sender that reaches it waits for an acknowledgment rather than sending past it. It also
/// caps the congestion window in practice: 256 packets at RFC 9000 §14.1's smallest datagram is
/// a window of about 300 kilobytes. The Initial and Handshake spaces never come near it, and
/// giving them a smaller table of their own is a change design §11 would have to measure first.
pub const sent_packets_max: usize = 256;

/// Lost stream ranges a connection keeps until they are framed again (RFC 9000 §13.3). A lost
/// range comes from one lost packet, and new octets wait while any range is owed (decision 57),
/// so the sent table's bound is this one's too. Merging adjacent ranges absorbs the pieces that a
/// smaller packet splits one into.
pub const stream_lost_ranges_max: usize = sent_packets_max;

/// RFC 9002 Appendix A.9: a Probe Timeout sends one or two ack-eliciting packets, and two is
/// what recovers a tail of exactly one lost packet in one round trip rather than two.
pub const probe_packets: u8 = 2;

/// RFC 9002 §7.7's `N`, as a fraction: the pacing rate is `N * congestion_window / smoothed_rtt`,
/// and §7.7 asks for an `N` that is small but at least 1, giving 1.25 as its example. Above 1 the
/// window is not left underused when the round trip moves.
pub const pacing_rate_numerator: u64 = 5;
pub const pacing_rate_denominator: u64 = 4;

/// How far the Probe Timeout may back off. RFC 9002 §6.2.1 doubles the timeout on every
/// consecutive probe and names no ceiling, so this one is colibri's: at sixteen doublings the
/// timeout is already far past RFC 9000 §10.1's idle timeout, which ends the connection first.
pub const probe_timeout_backoff_max: u6 = 16;

/// `kPersistentCongestionThreshold`: how many Probe Timeouts a span of loss must cover before it
/// counts as persistent congestion, which §7.6.1 recommends at 3.
pub const persistent_congestion_threshold: u64 = 3;

/// RFC 9000 §18.2: `max_ack_delay` is the peer's, in milliseconds, assumed to be 25 when absent
/// and invalid at 2^14 or above. It is held per connection and never as a limit of colibri's.
pub const max_ack_delay_default_ns: u64 = 25 * nanoseconds_per_millisecond;
pub const max_ack_delay_invalid_at: u64 = 1 << 14;

/// Branches the compiler may take per octet of source and of needle while a comptime check scans
/// a source file for a name (`packet/packet_header.zig`, invariant 22).
pub const comptime_scan_branches_per_octet: u32 = 4;

/// Octets the Length field of a long header may be written in, which are the lengths of a
/// variable-length integer (RFC 9000 §16). A sender that has not built its payload yet reserves
/// one of these and knows its header's length.
pub const length_field_lens = wire.constants.varint_lens;

comptime {
    // RFC 9000 §10.3: the resulting minimum size is 21 bytes.
    assert(stateless_reset_len_min == 21);
    assert(connection_ids_max >= active_connection_id_limit_min);
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
