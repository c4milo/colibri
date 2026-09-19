//! Limits quic owns (docs/design.md §7), and the fixed values of the version 1 wire format
//! (RFC 9000 §17). Never written inline (CLAUDE.md non-negotiable 4).
//!
//! `packet/invariant.zig` imports none of this: it reads RFC 8999 alone, and invariant 22 keeps
//! every version 1 value out of its reach.
const std = @import("std");
const assert = std.debug.assert;
const wire = @import("wire");

/// QUIC version 1 (RFC 9000 §15).
pub const version_1: u32 = 0x00000001;

/// Most octets of a connection ID in version 1 (RFC 9000 §17.2): a long header that carries a
/// longer one MUST be dropped. RFC 8999 permits 255, and only the version 1 reader applies this.
pub const connection_id_len_max: u8 = 20;

/// The largest packet number (RFC 9000 §12.3), which is the largest variable-length integer.
pub const packet_number_max: u64 = wire.constants.varint_value_max;

/// Most octets of a Packet Number field (RFC 9000 §17.1).
pub const packet_number_len_max: u8 = 4;

/// RFC 9000 §17.1: the field must represent more than twice the range between the largest
/// acknowledged packet number and the one sent, so the receiver's window has that range on each
/// side of the number it expects.
pub const packet_number_range_factor: u64 = 2;

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
pub const key_phase_bit: u8 = 0x04;
/// The Packet Number Length, one less than the field's length in octets (RFC 9000 §17.2).
pub const packet_number_len_mask: u8 = 0x03;
/// The four bits of a Retry packet's byte 0 that carry no meaning (RFC 9000 §17.2.5).
pub const retry_unused_bits: u8 = 0x0f;

/// Octets of the Retry Integrity Tag (RFC 9000 §17.2.5, RFC 9001 §5.8).
pub const retry_integrity_tag_len: usize = 16;

/// Octets of the AEAD tag every protected packet ends with (RFC 9001 §5.3): both AEADs QUIC
/// version 1 uses produce 16.
pub const aead_tag_len: usize = 16;

/// Octets of the header protection sample (RFC 9001 §5.4.2), and how far past the start of the
/// Packet Number field it begins, which is the field's longest length.
pub const header_protection_sample_len: usize = 16;
pub const header_protection_sample_offset: usize = packet_number_len_max;

/// Branches the compiler may take per octet of source and of needle while a comptime check scans
/// a source file for a name (`packet/packet_header.zig`, invariant 22).
pub const comptime_scan_branches_per_octet: u32 = 4;

/// Octets the Length field of a long header may be written in, which are the lengths of a
/// variable-length integer (RFC 9000 §16). A sender that has not built its payload yet reserves
/// one of these and knows its header's length.
pub const length_field_lens = wire.constants.varint_lens;

comptime {
    assert(packet_number_max == (1 << 62) - 1);
    assert(packet_number_len_mask + 1 == packet_number_len_max);
    assert(long_packet_type_mask >> long_packet_type_shift == 0x03);
    // The fields of byte 0 do not overlap, in either header form.
    assert(fixed_bit & long_packet_type_mask & long_reserved_bits & packet_number_len_mask == 0);
    assert(fixed_bit | long_packet_type_mask | long_reserved_bits | packet_number_len_mask == 0x7f);
    assert(fixed_bit | spin_bit | short_reserved_bits | key_phase_bit | packet_number_len_mask == 0x7f);
}
