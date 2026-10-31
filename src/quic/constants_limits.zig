//! The bounds colibri chose for quic, which size memory or bound a loop or a queue. Ask the
//! owner before changing one (CLAUDE.md): the test at the end pins each value.
//! Decision 137 groups them, and `constants.zig` exports this file as `limits`.
const std = @import("std");
const assert = std.debug.assert;
const wire = @import("wire");
const core = @import("core");
const protocol = @import("constants_protocol.zig");

/// Most Available Versions colibri keeps of a peer's Version Information (RFC 9368 §3). The list is
/// bounded only by the parameter's length, so the reader checks every entry and keeps this many,
/// more than any endpoint lists today, reserved versions included.
pub const version_information_versions_max: usize = 16;

/// The longest peer address a caller names (decision 72): an IPv6 address, which RFC 4291 §2
/// makes 128 bits. colibri compares these octets and never reads them otherwise.
pub const peer_address_len_max: usize = 16;

/// The peer addresses a connection's qlog holds a tuple number for at once (quic-events §4.7).
/// Policy: the active path, the previous one, and new arrivals RFC 9000 §9.3 may move to. An
/// address that comes back after four others takes a new number.
pub const qlog_tuples_max: usize = 4;

/// Ranges of received packet numbers one space remembers and reports (RFC 9000 §13.2.3): a
/// receiver limits them to bound an ACK frame and to avoid resource exhaustion. Past this many
/// the oldest is dropped, and a packet below what is left is discarded rather than processed,
/// because §12.3's certainty is gone.
pub const ack_ranges_max: usize = 32;

/// Streams one connection holds at once. It bounds the table, and so bounds what this endpoint
/// advertises under §4.6: §3.2's implicit creation makes an advertised limit a promise to hold
/// that many streams at once.
pub const streams_per_connection_max: u32 = core.constants.limits.streams_per_connection_max;

/// Connection IDs from the peer this endpoint holds at once. It is what
/// `active_connection_id_limit` advertises (RFC 9000 §18.2), which that parameter puts a floor
/// of 2 under, and it bounds the table that holds them.
pub const connection_ids_max: usize = 8;

/// The most packets one datagram can hold (RFC 9000 §12.2), which is what bounds the loop that
/// walks them. It over-counts on purpose: the divisor is only the Packet Number field, the
/// payload RFC 9001 §5.4.2 requires beside it and the authentication tag, leaving out every
/// header octet a real packet also carries. A datagram holds a handful in practice.
pub const coalesced_packets_max: usize = @intCast(protocol.datagram_len_max / (protocol.protected_len_min + protocol.aead_tag_len));

/// The most frames one packet can hold, which bounds the walk over a payload. RFC 9000 §19.1
/// makes PADDING one octet, and no frame is shorter, so a payload holds at most its own length
/// in frames. The reader takes a run of PADDING as one frame, so this over-counts too.
pub const frames_per_packet_max: usize = @intCast(protocol.datagram_len_max);

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
pub const retry_len_max: usize = 1 + @sizeOf(u32) + 2 * (1 + protocol.connection_id_len_max) + token_len_max;

/// Octets of the Retry Pseudo-Packet of RFC 9001 §5.8: the Original Destination Connection ID
/// with its length octet, then the Retry packet less its tag.
pub const retry_pseudo_packet_len_max: usize = 1 + protocol.connection_id_len_max + retry_len_max;

/// Octets of the longest packet header colibri writes (RFC 9000 §17.2): byte 0, the Version, both
/// connection IDs with their length octets, an Initial's Token Length and Token, the Length field
/// and the Packet Number field.
pub const packet_header_len_max: usize = 1 + @sizeOf(u32) +
    2 * (1 + protocol.connection_id_len_max) +
    wire.constants.protocol.varint_len_max + token_len_max +
    wire.constants.protocol.varint_len_max + protocol.packet_number_len_max;

/// Octets of out-of-order CRYPTO data colibri buffers per encryption level. RFC 9000 §7.5:
/// "Implementations MUST support buffering at least 4096 bytes of data received in out-of-order
/// CRYPTO frames." It is the RFC's floor and not a choice of colibri's: in-order data is handed
/// to the handshake as it arrives and never sits here, so this bounds only what a gap holds.
/// More than this is a connection error of CRYPTO_BUFFER_EXCEEDED, which §7.5 names for it.
pub const crypto_buffer_len: usize = 4096;

/// Octets of a block of the receive pool (`stream_incoming.zig`, decision 61). A stream holding
/// any unread octets holds at least one, so a smaller block wastes less on a stream with little
/// waiting, and a larger one means fewer blocks for a read to walk.
pub const stream_receive_block_len: usize = 1024;

/// The receive pool a caller places when it asks for no size in particular, in octets. Decision
/// 61 makes it the cap on the connection's receive window and on each stream's: at a 100 ms
/// round trip it sustains about 80 Mbit/s per connection.
pub const receive_pool_len_default: usize = 1_048_576;

/// Octets of its own handshake flow colibri keeps per encryption level, so a CRYPTO frame can be
/// written again under a new packet number (RFC 9000 §13.3) and a client can repeat its first
/// flight after a Retry (§17.2.5.3). Nothing in either RFC sizes it. Decision 64 has a PTO at a
/// handshake level send that level's whole flight again, so a flight longer than this loses its
/// early octets and closes the connection. 16 KiB holds a server's Handshake flight with a
/// 10 KB certificate chain, the one the QUIC Interop Runner's amplification case sends. Three
/// levels of it sit in every connection, which `Connection` pays for once.
pub const crypto_send_buffer_len: usize = 16 * 1024;

/// How many packets one packet number space may hold outstanding, which bounds the table of
/// RFC 9002 Appendix A.1.1. The RFC bounds `sent_packets` at nothing, so this bound is colibri's
/// and a sender that reaches it waits for an acknowledgment rather than sending past it. It also
/// caps the congestion window in practice: 256 packets at RFC 9000 §14.1's smallest datagram is
/// a window of about 300 kilobytes. The Initial and Handshake spaces never come near it, and
/// giving them a smaller table of their own is a change design §11 would have to measure first.
pub const sent_packets_max: usize = 256;

/// Packet numbers of the application space that one loss episode may declare lost and still be
/// found spurious (draft-ietf-ccwg-bbr-06 §5.5.11, the owner's ruling of 2026-10-31, design §8
/// step 29b.3). RFC 9002 detects no spurious loss, so the bound is colibri's. An episode that
/// declares more is never undone.
pub const spurious_loss_numbers_max: usize = 32;

/// STREAM frames one application-level packet carries at most (decision 131).
pub const stream_frames_per_packet_max: usize = 16;

/// Stream ranges the ring holds: each application-level packet's ranges after its first, in send
/// order (decision 131, INV-33). A packet whose ranges would not fit carries one STREAM frame.
pub const stream_ranges_max: usize = 512;

/// Lost stream ranges a connection keeps until they are framed again (RFC 9000 §13.3). Every
/// range in flight may be lost at once: each packet's first range in its record, and the others
/// in the ring (decision 131). New octets wait while any range is owed (decision 57). Merging
/// adjacent ranges absorbs the pieces that a smaller packet splits one into.
pub const stream_lost_ranges_max: usize = sent_packets_max + stream_ranges_max;

/// How far the Probe Timeout may back off. RFC 9002 §6.2.1 doubles the timeout on every
/// consecutive probe and names no ceiling, so this one is colibri's: at sixteen doublings the
/// timeout is already far past RFC 9000 §10.1's idle timeout, which ends the connection first.
pub const probe_timeout_backoff_max: u6 = 16;

/// Branches the compiler may take per octet of source and of needle while a comptime check scans
/// a source file for a name (`packet/packet_header.zig`, invariant 22).
pub const comptime_scan_branches_per_octet: u32 = 4;

comptime {
    assert(coalesced_packets_max > 0);
    // `recovery_spurious.zig` marks each number acknowledged in one bit of a `u32`.
    assert(spurious_loss_numbers_max > 0 and spurious_loss_numbers_max <= 32);
    assert(frames_per_packet_max > 0);
    // A record counts its extra ranges in a `u8`, the ring wraps in a `u32`, and every range in
    // flight may be lost at once.
    assert(stream_frames_per_packet_max > 1 and stream_frames_per_packet_max - 1 <= std.math.maxInt(u8));
    assert(stream_ranges_max >= stream_frames_per_packet_max and stream_ranges_max < std.math.maxInt(u32) / 2);
    assert(stream_lost_ranges_max >= sent_packets_max + stream_ranges_max);
}

test "decision 137: each limit holds the value the owner ruled" {
    // A failure here is a changed limit, which the owner rules on before this test changes.
    const expectEqual = @import("std").testing.expectEqual;
    try expectEqual(16, version_information_versions_max);
    try expectEqual(16, peer_address_len_max);
    try expectEqual(4, qlog_tuples_max);
    try expectEqual(32, ack_ranges_max);
    try expectEqual(128, streams_per_connection_max);
    try expectEqual(8, connection_ids_max);
    try expectEqual(3276, coalesced_packets_max);
    try expectEqual(65527, frames_per_packet_max);
    try expectEqual(256, token_len_max);
    try expectEqual(303, retry_len_max);
    try expectEqual(324, retry_pseudo_packet_len_max);
    try expectEqual(323, packet_header_len_max);
    try expectEqual(4096, crypto_buffer_len);
    try expectEqual(1024, stream_receive_block_len);
    try expectEqual(1048576, receive_pool_len_default);
    try expectEqual(16384, crypto_send_buffer_len);
    try expectEqual(256, sent_packets_max);
    try expectEqual(16, stream_frames_per_packet_max);
    try expectEqual(512, stream_ranges_max);
    try expectEqual(768, stream_lost_ranges_max);
    try expectEqual(16, probe_timeout_backoff_max);
    try expectEqual(4, comptime_scan_branches_per_octet);
    try expectEqual(32, spurious_loss_numbers_max);
}
