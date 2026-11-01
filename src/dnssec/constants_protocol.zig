//! The values the RFCs and IANA's registries fix for DNSSEC, which no one may change.
//! Decision 137 groups them, and `constants.zig` exports this file as `protocol`.
const std = @import("std");
const assert = std.debug.assert;

/// The DNS Security Algorithm Numbers colibri checks: RSA/SHA-256 and RSA/SHA-512 (RFC 5702 §2
/// and §3), ECDSA P-256 with SHA-256 and P-384 with SHA-384 (RFC 6605 §4), and Ed25519 (RFC 8080
/// §5).
pub const algorithm_rsasha256: u8 = 8;
pub const algorithm_rsasha512: u8 = 10;
pub const algorithm_ecdsap256sha256: u8 = 13;
pub const algorithm_ecdsap384sha384: u8 = 14;
pub const algorithm_ed25519: u8 = 15;

/// The DS digest types colibri computes: SHA-1 (RFC 4034 §5.1.4), SHA-256 (RFC 4509 §2.1) and
/// SHA-384 (RFC 6605 §2). SHA-1 is also NSEC3's hash algorithm 1 (RFC 5155 §5).
pub const digest_sha1: u8 = 1;
pub const digest_sha256: u8 = 2;
pub const digest_sha384: u8 = 4;

/// The longest digest `Hash.final` writes: SHA-512's, which RSA/SHA-512 and Ed25519 hash with.
pub const digest_len_max: usize = 64;

comptime {
    assert(algorithm_rsasha256 < algorithm_rsasha512 and algorithm_ecdsap384sha384 < algorithm_ed25519);
    assert(digest_sha1 < digest_sha256 and digest_sha256 < digest_sha384);
}
