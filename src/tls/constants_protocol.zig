//! The values the RFCs fix for tls, which no one may change.
//! Decision 137 groups them, and `constants.zig` exports this file as `protocol`.
const std = @import("std");
const assert = std.debug.assert;

/// Octets of the SHA-256 a ticket is bound to (chapulin's `webpki_ticket.h`) and of an SPKI pin.
pub const sha256_len: usize = 32;

/// Octets of an ecdsa_secp256r1_sha256 identity's keys: the point X||Y and the scalar.
pub const p256_public_key_len: usize = 64;
pub const p256_private_key_len: usize = 32;

/// Octets of a server's cookie key and ticket key, chapulin's `CH_SRV_COOKIE_KEY_LEN` and
/// `CH_SRV_TICKET_KEY_LEN`, which the configurations assert.
pub const server_key_len: usize = 32;
