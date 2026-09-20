//! Limits tls owns (docs/design.md §7). Never written inline (CLAUDE.md non-negotiable 4).
const std = @import("std");
const assert = std.debug.assert;

/// RFC 9846 §5.1: the length of TLSPlaintext.fragment MUST NOT exceed 2^14 octets.
pub const record_plaintext_len_max: u32 = 1 << 14;

/// The ContentType, the legacy record version and the length (RFC 9846 §5.1).
pub const record_header_len: u32 = 5;

/// RFC 9846 §5.2: the length of TLSCiphertext.length MUST NOT exceed 2^14 + 256 octets, which is
/// the plaintext, the content type and the AEAD tag.
pub const record_ciphertext_len_max: u32 = (1 << 14) + 256;

/// The smallest output buffer a provider never answers with `error.NoSpaceLeft`: one whole record.
pub const record_write_len_min: u32 = record_header_len + record_ciphertext_len_max;

/// RFC 9846 Appendix B.1: the ProtocolVersion codepoint of TLS 1.2.
pub const version_tls_1_2: u16 = 0x0303;

/// RFC 9846 Appendix B.1: the ProtocolVersion codepoint of TLS 1.3, which §4.3.1 carries in the
/// supported_versions extension rather than in legacy_version.
pub const version_tls_1_3: u16 = 0x0304;

/// The cipher suites colibri admits, by their RFC 9846 Appendix B.4 codepoints. These are the
/// three RFC 9846 §9.1 names: a compliant application MUST implement TLS_AES_128_GCM_SHA256 and
/// SHOULD implement the other two. They are also the three RFC 9001 §5.3 permits for QUIC, which
/// excludes TLS_AES_128_CCM_8_SHA256 by name for its 64-bit tag (decision 45).
pub const cipher_suite_aes_128_gcm_sha256: u16 = 0x1301;
pub const cipher_suite_aes_256_gcm_sha384: u16 = 0x1302;
pub const cipher_suite_chacha20_poly1305_sha256: u16 = 0x1303;
pub const cipher_suite_aes_128_ccm_sha256: u16 = 0x1304;
pub const cipher_suite_aes_128_ccm_8_sha256: u16 = 0x1305;

pub const cipher_suites_admitted = [_]u16{
    cipher_suite_aes_128_gcm_sha256,
    cipher_suite_aes_256_gcm_sha384,
    cipher_suite_chacha20_poly1305_sha256,
};

/// RFC 7301 §3.1: a ProtocolName is `opaque ProtocolName<1..2^8-1>`, so it is at most 255 octets.
pub const alpn_protocol_name_len_max: u32 = 255;

/// RFC 9113 §3.1: the "h2" protocol identifier, serialized as the two octets 0x68 and 0x32.
pub const alpn_h2: [2]u8 = .{ 0x68, 0x32 };

comptime {
    // RFC 9846 §5.2: the protected record is the plaintext, one content-type octet and the tag, so
    // it is longer than the plaintext it carries.
    assert(record_ciphertext_len_max > record_plaintext_len_max);
    // RFC 7301 §3.1: "h2" is two octets, well inside what a ProtocolName may carry.
    assert(alpn_h2.len <= alpn_protocol_name_len_max);
    // RFC 9846 Appendix B.1: the codepoints order by version, which is what a floor compares.
    assert(version_tls_1_3 > version_tls_1_2);
    // RFC 9846 Appendix B.4: the TLS 1.3 suites are 0x1301 to 0x1305, and colibri admits the
    // first three. Neither CCM suite is here: RFC 9001 §5.3 excludes TLS_AES_128_CCM_8_SHA256,
    // and RFC 9846 §9.1 makes neither CCM suite a MUST or a SHOULD.
    for (cipher_suites_admitted) |suite| {
        assert(suite >= cipher_suite_aes_128_gcm_sha256 and suite <= cipher_suite_chacha20_poly1305_sha256);
    }
    assert(cipher_suite_aes_128_ccm_8_sha256 > cipher_suite_chacha20_poly1305_sha256);
}

test "constants compile" {
    try std.testing.expect(true);
}
