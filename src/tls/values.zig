//! What a program sets to run TLS through colibri (design §8 step 16c, decision 97 as amended):
//! plain values, one set for h11, h2 and h3 alike. `tls` converts them once for each chapulin
//! object into that object's values, in a configuration the caller places, and every session of
//! the object borrows it. Each rule the values carry is chapulin's (its `cfg.h`, `webpki_cfg.h`
//! and `srv_cfg.h`), and colibri checks none of them twice.
//!
//! The clock, a ticket to offer and the source of randomness belong to each connection, so they
//! are not here: a session's `start` takes them.
const std = @import("std");
const constants = @import("constants.zig");

/// The source a session's randomness comes from, which the caller passes to each session's `start`
/// (decision 94 as amended on 2026-09-27). Every draw chapulin makes for that session fills from
/// it, so a caller that seeds it replays the session. colibri makes no generator and draws from
/// none (non-negotiable 5): this is the one file under `src/` that names the type, which
/// `tools/lint/determinism.zig` permits. The generator it points at outlives the session, and
/// answers on the thread that drives the session.
pub const Random = std.Random;

/// A root a client trusts: its subject Name and its SubjectPublicKeyInfo, each the whole DER TLV.
pub const Anchor = struct {
    subject: []const u8,
    spki: []const u8,
};

/// The SHA-256 of a DER SubjectPublicKeyInfo.
pub const Pin = [constants.sha256_len]u8;

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
    /// Protocols to offer, most preferred first (RFC 7301 §3.1).
    alpn: []const []const u8,
    /// Refuse a handshake whose key exchange is not X25519MLKEM768.
    require_pq: bool = false,
    /// Suites to offer, most preferred first, as RFC 9846 Appendix B.4 codepoints; empty for
    /// chapulin's. A list may leave suites out, and the ClientHello offers exactly this list.
    cipher_suites: []const u16 = &.{},
};

/// A NewSessionTicket a client kept (RFC 9846 §4.7.1), in fixed-size fields, so a program keeps it
/// as long as it likes: across connections, and across h2 and h3 of one server.
pub const Ticket = struct {
    identity: [constants.ticket_identity_len_max]u8,
    identity_len: u16,
    psk: [constants.ticket_psk_len_max]u8,
    psk_len: u8,
    age_add: u32,
    /// ticket_lifetime, in seconds (RFC 9846 §4.7.1).
    lifetime_s: u32,
    /// The hash of the trust the ticket was issued under (chapulin's `webpki_ticket.h`).
    binding: [constants.sha256_len]u8,
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

/// An ecdsa_secp256r1_sha256 identity.
pub const EcdsaP256Identity = struct {
    /// DER certificates, the end-entity first (RFC 9846 §4.5.1).
    chain: []const []const u8,
    /// The end-entity's point, X||Y.
    public_key: *const [constants.p256_public_key_len]u8,
    /// The private scalar, big-endian. colibri passes the pointer to chapulin and never reads it.
    private_key: *const [constants.p256_private_key_len]u8,
};

/// An rsa_pss_rsae_sha256 identity.
pub const RsaPssIdentity = struct {
    chain: []const []const u8,
    /// The modulus, big-endian.
    public_key: []const u8,
    /// A chapulin `ch_rsa_priv`, the modulus and the private exponent. It is opaque here because
    /// chapulin's type is one of each object, and colibri passes the pointer and never reads it.
    private_key: *const anyopaque,
};

pub const Server = struct {
    ecdsa_p256: ?EcdsaP256Identity = null,
    rsa_pss: ?RsaPssIdentity = null,
    /// RFC 9846 §4.3.2's cookie key, which chapulin requires of every server.
    cookie_key: *const [constants.server_key_len]u8,
    /// The key tickets are sealed under, or null to issue none.
    ticket_key: ?*const [constants.server_key_len]u8 = null,
    /// Protocols this server selects from, in its order (RFC 7301 §3.2).
    alpn: []const []const u8,
    /// Refuse a ClientHello with no server_name (RFC 9846 §9.2).
    require_server_name: bool = false,
    /// Suites in this server's order, as RFC 9846 Appendix B.4 codepoints; empty for chapulin's.
    cipher_suites: []const u16 = &.{},
};
