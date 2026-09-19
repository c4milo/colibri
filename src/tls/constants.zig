//! Limits tls owns (docs/design.md §7). Never written inline (CLAUDE.md non-negotiable 4).
const std = @import("std");
const assert = std.debug.assert;

/// RFC 8446 §5.1: the length of TLSPlaintext.fragment MUST NOT exceed 2^14 octets.
pub const record_plaintext_len_max: u32 = 1 << 14;

/// The ContentType, the legacy record version and the length (RFC 8446 §5.1).
pub const record_header_len: u32 = 5;

/// RFC 8446 §5.2: the length of TLSCiphertext.length MUST NOT exceed 2^14 + 256 octets, which is
/// the plaintext, the content type and the AEAD tag.
pub const record_ciphertext_len_max: u32 = (1 << 14) + 256;

/// The smallest output buffer a provider never answers with `error.NoSpaceLeft`: one whole record.
pub const record_write_len_min: u32 = record_header_len + record_ciphertext_len_max;

/// RFC 7301 §3.1: a ProtocolName is `opaque ProtocolName<1..2^8-1>`, so it is at most 255 octets.
pub const alpn_protocol_name_len_max: u32 = 255;

/// RFC 9113 §3.1: the "h2" protocol identifier, serialized as the two octets 0x68 and 0x32.
pub const alpn_h2: [2]u8 = .{ 0x68, 0x32 };

comptime {
    // RFC 8446 §5.2: the protected record is the plaintext, one content-type octet and the tag, so
    // it is longer than the plaintext it carries.
    assert(record_ciphertext_len_max > record_plaintext_len_max);
    // RFC 7301 §3.1: "h2" is two octets, well inside what a ProtocolName may carry.
    assert(alpn_h2.len <= alpn_protocol_name_len_max);
}

test "constants compile" {
    try std.testing.expect(true);
}
