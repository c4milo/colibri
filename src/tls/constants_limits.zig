//! The bounds colibri chose for tls, which size memory or bound a loop or a queue. Ask the
//! owner before changing one (CLAUDE.md): the test at the end pins each value.
//! Decision 137 groups them, and `constants.zig` exports this file as `limits`.
const std = @import("std");
const assert = std.debug.assert;

/// Octets of a session's receive buffer, chapulin's `cfg.buf`. It holds the largest record, 2^14
/// plus 256 octets (RFC 9846 §5.2), and it bounds the largest handshake message a session reads:
/// a server's flight of four certificates of 3,072 octets needs 12,338 (chapulin's
/// `docs/webpki.md`), which design §8 step 5 measured against a Go server. A record-mode session
/// advertises it, less record overhead, as its record_size_limit.
pub const receive_len: usize = 20 * 1024;

/// Trust anchors one client's values name (RFC 9846 §4.5.1.3). chapulin takes any count of one
/// or more since its commit 237e6e19. colibri keeps 12, chapulin's earlier
/// `CH_WEBPKI_ANCHOR_MAX`, so no configuration grows. The owner ruled this on 2026-10-17. The PEM
/// reader for a CA bundle (https://github.com/c4milo/colibri/issues/97) sizes it again for a
/// system bundle. Each anchor costs a `ch_trust_anchor`, four words, in each client configuration.
pub const anchors_max: usize = 12;

/// Octets of the server_name a server keeps from a ClientHello (RFC 9846 §9.2). chapulin copies
/// no longer name, and a server reports none for one.
pub const server_name_len_max: usize = 255;

/// Certificates in one identity's chain, the end-entity first (RFC 9846 §4.5.1). chapulin sets no
/// limit on a chain it sends. The QUIC Interop Runner's amplification case presents a leaf under
/// eight intermediates, and the owner set this on 2026-09-26 with room past it.
pub const certificate_chain_len_max: usize = 16;

/// Cipher suites a server may name in its order: the three colibri admits (decision 45).
pub const cipher_suites_max: usize = 3;

/// Octets of a resumption ticket's identity and PSK colibri keeps, chapulin's `CH_TICKET_ID_MAX`
/// and SHA-384's length, the longest hash a suite of RFC 9846 §9.1 uses (§4.7.1).
pub const ticket_identity_len_max: usize = 320;
pub const ticket_psk_len_max: usize = 48;

/// Octets of the handshake messages a QUIC session holds at one encryption level until colibri
/// frames them as CRYPTO data (RFC 9001 §4.1.3). A server's Handshake flight is the largest: the
/// QUIC Interop Runner's amplification case, a leaf under eight intermediates, takes 9,663.
pub const crypto_out_len: usize = 20 * 1024;

/// Octets of the peer's transport parameters a QUIC session keeps (RFC 9001 §8.2). RFC 9000 §18
/// sets no bound, and this holds every parameter §18.2 defines with room for a peer's own.
pub const transport_parameters_len_max: usize = 1024;

comptime {
    assert(receive_len > (1 << 14) + 256);
    assert(server_name_len_max > 0 and certificate_chain_len_max > 0);
    assert(cipher_suites_max > 0);
    assert(crypto_out_len > 0 and transport_parameters_len_max > 0);
}

test "decision 137: each limit holds the value the owner ruled" {
    // A failure here is a changed limit, which the owner rules on before this test changes.
    const expectEqual = @import("std").testing.expectEqual;
    try expectEqual(20480, receive_len);
    try expectEqual(12, anchors_max);
    try expectEqual(255, server_name_len_max);
    try expectEqual(16, certificate_chain_len_max);
    try expectEqual(3, cipher_suites_max);
    try expectEqual(320, ticket_identity_len_max);
    try expectEqual(48, ticket_psk_len_max);
    try expectEqual(20480, crypto_out_len);
    try expectEqual(1024, transport_parameters_len_max);
}
