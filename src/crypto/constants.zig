//! Sizes and limits of QUIC packet protection that both sides of `Suite` must agree on
//! (docs/design.md §7). Never written inline (CLAUDE.md non-negotiable 4). `quic` names the same
//! values through this module, so a suite and the code that frames its packets cannot disagree.
const std = @import("std");
const assert = std.debug.assert;

/// The largest packet number (RFC 9000 §12.3): 2^62-1.
pub const packet_number_max: u64 = (1 << 62) - 1;

/// Most octets of a Packet Number field (RFC 9000 §17.1).
pub const packet_number_len_max: u8 = 4;

/// RFC 9000 §17.1: the field must represent more than twice the range between the largest
/// acknowledged packet number and the one sent, so the receiver's window has that range on each
/// side of the number it expects.
pub const packet_number_range_factor: u64 = 2;

/// Octets of the tag a protected packet ends with (RFC 9001 §5.3). Both AEADs QUIC version 1
/// uses produce 16.
pub const aead_tag_len: usize = 16;

/// Octets of the Retry Integrity Tag (RFC 9001 §5.8).
pub const retry_integrity_tag_len: usize = 16;

/// Octets of the header protection sample, and how far past the start of the Packet Number field
/// it begins, which is the field's longest length (RFC 9001 §5.4.2).
pub const header_protection_sample_len: usize = 16;
pub const header_protection_sample_offset: usize = packet_number_len_max;

/// Octets of the header protection mask: one for byte 0, and one for each octet of the longest
/// Packet Number field (RFC 9001 §5.4.1).
pub const header_protection_mask_len: usize = 1 + packet_number_len_max;

/// The bits of byte 0 that header protection covers: four in a long header and five in a short
/// one (RFC 9001 §5.4.1).
pub const long_header_protected_bits: u8 = 0x0f;
pub const short_header_protected_bits: u8 = 0x1f;

/// RFC 8999 §5: the Header Form bit, which header protection never covers, so a suite reads it
/// to know which of the two masks above applies.
pub const header_form_bit: u8 = 0x80;

/// The Key Phase bit of a short header's byte 0 (RFC 9000 §17.3.1), which header protection
/// covers and a suite reads once it has unmasked the byte, to pick the keys (RFC 9001 §6.5).
pub const key_phase_bit: u8 = 0x04;

/// The Packet Number Length bits of byte 0, one less than the field's octets (RFC 9000 §17.2).
pub const packet_number_len_mask: u8 = 0x03;

/// RFC 9001 §5.4.2: the Packet Number field and the payload together are at least this many
/// octets, so that the sample lies inside the packet. The sender pads to reach it.
pub const protected_len_min: usize = packet_number_len_max;

comptime {
    assert(packet_number_len_mask + 1 == packet_number_len_max);
    assert(header_protection_mask_len == 5);
    assert(long_header_protected_bits & short_header_protected_bits == long_header_protected_bits);
    assert(short_header_protected_bits & header_form_bit == 0);
    assert(short_header_protected_bits & key_phase_bit == key_phase_bit);
}
