//! What a program sets to run TLS through colibri (design §8 step 16c, decision 97 as amended):
//! plain values, one set for h11, h2 and h3 alike. `tls` converts them once for each chapulin
//! object into that object's values, in a configuration the caller places, and every session of
//! the object borrows it. Each rule the values carry is chapulin's (its `cfg.h`, `webpki_cfg.h`
//! and `srv_cfg.h`), and colibri checks none of them twice.
//!
//! The program's `stdx.crypto.Context` is here (decision 175): its CPU features, which stdx maps
//! to chapulin's description of the CPU, and its random source, which every session of the
//! configuration and every draw of the engine or the pool that holds it fill from. The clock and
//! a ticket to offer belong to each connection, so they are not here: a session's `start` takes
//! them.
const std = @import("std");
const stdx_crypto = @import("stdx").crypto;
const constants = @import("constants.zig");

/// A root a client trusts: its subject Name and its SubjectPublicKeyInfo, each the whole DER TLV.
pub const Anchor = struct {
    subject: []const u8,
    spki: []const u8,
};

/// The SHA-256 of a DER SubjectPublicKeyInfo.
pub const Pin = [constants.protocol.sha256_len]u8;

/// How a client judges the server.
pub const Trust = union(enum) {
    /// The chain must reach one of `anchors`, valid at the connection's clock, and name
    /// `server_name`, which is also sent as server_name. With `pins`, the path must also carry one
    /// of them.
    web_pki: struct {
        anchors: []const Anchor,
        server_name: []const u8,
        pins: []const Pin = &.{},
    },
    /// The server must prove it holds the key one of `pins` names. No clock is read and no
    /// certificate is judged, and `server_name` is sent when given.
    pins: struct {
        pins: []const Pin,
        server_name: ?[]const u8 = null,
    },
};

pub const Client = struct {
    trust: Trust,
    /// Protocols to offer, most preferred first (RFC 7301 §3.1). Empty when the caller names
    /// none, as `client.Pool` requires: it names the protocols its versions allow (decision
    /// 117).
    alpn: []const []const u8 = &.{},
    /// The program's one `stdx.crypto.init(features, random)` (decision 175). There is no
    /// default. stdx maps its features to chapulin's description of the CPU, and each session
    /// draws from its random source.
    crypto: stdx_crypto.Context,
    /// Refuse a handshake whose key exchange is not X25519MLKEM768.
    require_pq: bool = false,
    /// Suites to offer, most preferred first, as RFC 9846 Appendix B.4 codepoints; empty for
    /// chapulin's. A list may leave suites out, and the ClientHello offers exactly this list.
    cipher_suites: []const u16 = &.{},
    /// Keep the tickets that a server sends (RFC 9846 §4.7.1), for `take_ticket`. With false, a
    /// session keeps none and `take_ticket` gives null. A web PKI session then hashes its anchors
    /// only to check a ticket that it offers, not at each start (chapulin's decision 132,
    /// https://github.com/c4milo/colibri/issues/104). A ticket that it offers still resumes.
    takes_tickets: bool = true,
};

/// A NewSessionTicket a client kept (RFC 9846 §4.7.1), in fixed-size fields, so a program keeps it
/// as long as it likes: across connections, and across h2 and h3 of one server.
pub const Ticket = struct {
    identity: [constants.limits.ticket_identity_len_max]u8,
    identity_len: u16,
    psk: [constants.limits.ticket_psk_len_max]u8,
    psk_len: u8,
    age_add: u32,
    /// ticket_lifetime, in seconds (RFC 9846 §4.7.1).
    lifetime_s: u32,
    /// The hash of the trust the ticket was issued under (chapulin's `webpki_ticket.h`).
    binding: [constants.protocol.sha256_len]u8,
    /// The QUIC version of the connection that issued it, or 0 for one a TCP connection issued.
    /// RFC 9369 §5 makes a ticket specific to that version, and chapulin's decision 79 keeps a
    /// ticket to its transport, so a client offers it to a connection of that version alone.
    quic_version: u32,

    /// Zeroes the ticket, its PSK included. A program calls it when it drops a ticket.
    pub fn wipe(ticket: *Ticket) void {
        std.crypto.secureZero(u8, std.mem.asBytes(ticket));
    }
};

/// A ticket a connection offers, and its age: the milliseconds since `take_ticket` handed it over.
pub const Resumption = struct {
    ticket: *const Ticket,
    age_ms: u64,
};

/// A key's signature algorithm, by its SignatureScheme code point (RFC 9846 §4.3.3), as
/// `cipher_suites` names suites by theirs (decision 147).
pub const SignatureScheme = enum(u16) {
    /// RFC 9846 §4.3.3.
    ecdsa_secp256r1_sha256 = 0x0403,
    /// RFC 9846 §4.3.3, RSASSA-PSS with SHA-256 over an rsaEncryption key.
    rsa_pss_rsae_sha256 = 0x0804,
    /// draft-ietf-tls-mldsa-05 §3, ML-DSA-87.
    mldsa87 = 0x0906,
};

/// A key pair a server signs with, which `pem.key` fills, in room for the largest key, ML-DSA-87's
/// (RFC 9881 §4 and §6). A key of another scheme uses the start of each room. colibri passes
/// chapulin pointers into it and never reads the secret. The program places it, keeps it in place
/// while a session uses it, and calls `wipe` once none does. The program fills a P-256 key itself
/// when it holds the raw scalar and point, and an RSA key only through `pem.key`.
pub const Key = struct {
    /// The key's algorithm, or null until `pem.key` fills it. A server refuses a key with none.
    scheme: ?SignatureScheme = null,
    /// The private key: a P-256 scalar, big-endian; chapulin's RSA key, its modulus, exponent and
    /// CRT integers in chapulin's `RsaKey`, which holds machine words and so is aligned to
    /// one; or an expanded ML-DSA-87 secret key.
    private_key: [constants.protocol.mldsa87_private_key_len]u8 align(@alignOf(usize)) = @splat(0),
    /// The public key: a P-256 point X||Y, an RSA modulus, big-endian, or an ML-DSA-87 public key.
    public_key: [constants.protocol.mldsa87_public_key_len]u8 = @splat(0),

    /// Writes zero over the private key, through a write the compiler keeps.
    pub fn wipe(key: *Key) void {
        std.crypto.secureZero(u8, &key.private_key);
    }
};

/// A server's identity: a chain and the key its end-entity certificate carries.
pub const Identity = struct {
    /// DER certificates, the end-entity first (RFC 9846 §4.5.1).
    chain: []const []const u8,
    key: *const Key,
};

pub const Server = struct {
    /// At most one identity for each scheme. chapulin signs with ML-DSA-87 when the client offers
    /// it, then with ECDSA P-256, and with RSA-PSS when the client offers neither (its decision
    /// 180). `tools/tls_openssl.sh` checks the order.
    identities: []const Identity = &.{},
    /// RFC 9846 §4.3.2's cookie key, which chapulin requires of every server.
    cookie_key: *const [constants.protocol.server_key_len]u8,
    /// The key tickets are sealed under, or null to issue none.
    ticket_key: ?*const [constants.protocol.server_key_len]u8 = null,
    /// The key tickets were sealed under before `ticket_key`, or null. chapulin seals new tickets
    /// under `ticket_key` alone, and opens a ticket under `ticket_key` and then under this key
    /// (https://github.com/c4milo/chapulin/issues/220). It reads both keys' bytes at each open and
    /// each seal, so a program writes new bytes in place between two calls (decision 161).
    ticket_key_previous: ?*const [constants.protocol.server_key_len]u8 = null,
    /// Protocols this server selects from, in its order (RFC 7301 §3.2). Empty for a server's
    /// endpoint, which names the protocols its versions allow (decision 119).
    alpn: []const []const u8 = &.{},
    /// The program's one `stdx.crypto.init(features, random)`, as `Client.crypto` is (decision
    /// 175). There is no default. Each session and each identity check draws from its random
    /// source.
    crypto: stdx_crypto.Context,
    /// Refuse a ClientHello with no server_name (RFC 9846 §9.2).
    require_server_name: bool = false,
    /// Suites in this server's order, as RFC 9846 Appendix B.4 codepoints; empty for chapulin's.
    cipher_suites: []const u16 = &.{},
};
