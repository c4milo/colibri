//! The limits of colibri's `tls` module (design §8 step 16). A limit chapulin names stays
//! chapulin's, under its C name in `chapulin.c`, such as `CH_WEBPKI_ANCHOR_MAX` and `CH_ALPN_MAX`;
//! these are the ones colibri chooses.
const std = @import("std");
const assert = std.debug.assert;

/// Octets of a session's receive buffer, chapulin's `cfg.buf`. It holds the largest record, 2^14
/// plus 256 octets (RFC 9846 §5.2), and it bounds the largest handshake message a session reads:
/// a server's flight of four certificates of 3,072 octets needs 12,338 (chapulin's
/// `docs/webpki.md`), which design §8 step 5 measured against a Go server. A record-mode session
/// advertises it, less record overhead, as its record_size_limit.
pub const receive_len: usize = 20 * 1024;

/// Octets of the server_name a server keeps from a ClientHello (RFC 9846 §9.2). chapulin copies
/// no longer name, and a server reports none for one.
pub const server_name_len_max: usize = 255;

/// Certificates in one identity's chain, the end-entity first (RFC 9846 §4.5.1). chapulin sets no
/// limit on a chain it sends. The QUIC Interop Runner's amplification case presents a leaf under
/// eight intermediates, and the owner set this on 2026-09-26 with room past it.
pub const certificate_chain_len_max: usize = 16;

/// KeyUpdate answers one record may owe (RFC 9846 §4.7.3). A peer that asks for more in one record
/// than this fails the read, and with it the connection, which is the fail-closed answer to a
/// record no honest peer sends.
pub const key_update_replies_max: usize = 2;

/// Cipher suites a server may name in its order: the three colibri admits (decision 45).
pub const cipher_suites_max: usize = 3;

/// Octets of a resumption ticket's identity and PSK colibri keeps, chapulin's `CH_TICKET_ID_MAX`
/// and SHA-384's length, the longest hash a suite of RFC 9846 §9.1 uses (§4.7.1).
pub const ticket_identity_len_max: usize = 320;
pub const ticket_psk_len_max: usize = 48;

/// Octets of the SHA-256 a ticket is bound to (chapulin's `webpki_ticket.h`) and of an SPKI pin.
pub const sha256_len: usize = 32;

/// Octets of the handshake messages a QUIC session holds at one encryption level until colibri
/// frames them as CRYPTO data (RFC 9001 §4.1.3). A server's Handshake flight is the largest: the
/// QUIC Interop Runner's amplification case, a leaf under eight intermediates, takes 9,663.
pub const crypto_out_len: usize = 20 * 1024;

/// Octets of the peer's transport parameters a QUIC session keeps (RFC 9001 §8.2). RFC 9000 §18
/// sets no bound, and this holds every parameter §18.2 defines with room for a peer's own.
pub const transport_parameters_len_max: usize = 1024;

/// Nanoseconds in a second: colibri passes instants in nanoseconds, and chapulin counts a Retry
/// token's lifetime in seconds.
pub const nanoseconds_per_second: u64 = 1_000_000_000;

/// Octets of an ecdsa_secp256r1_sha256 identity's keys: the point X||Y and the scalar.
pub const p256_public_key_len: usize = 64;
pub const p256_private_key_len: usize = 32;

/// Octets of a server's cookie key and ticket key, chapulin's `CH_SRV_COOKIE_KEY_LEN` and
/// `CH_SRV_TICKET_KEY_LEN`, which the configurations assert.
pub const server_key_len: usize = 32;

comptime {
    assert(receive_len > (1 << 14) + 256);
    assert(server_name_len_max > 0 and certificate_chain_len_max > 0);
    assert(key_update_replies_max > 0 and cipher_suites_max > 0);
    assert(ticket_psk_len_max >= sha256_len);
    assert(crypto_out_len > 0 and transport_parameters_len_max > 0);
}
