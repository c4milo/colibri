//! Step 16c's values converted, once, into the TCP object's chapulin values (decision 97 as
//! amended). chapulin's values point at lists of its own C element types, so the configuration
//! holds those lists, at chapulin's limits, and every session of the object borrows it. The
//! caller places a configuration and does not move it after `init`: its values point into it.
//!
//! A conversion refuses only a list longer than the one it copies into. Every other rule is
//! chapulin's, which a session's `start` or the server's `check` reports (design §8 step 16c).
const std = @import("std");
const assert = std.debug.assert;
const chapulin = @import("chapulin_tcp");
const constants = @import("../constants.zig");
const values = @import("../values.zig");

const c = chapulin.c;

pub const Error = error{
    /// More anchors than chapulin's `CH_WEBPKI_ANCHOR_MAX`.
    TooManyAnchors,
    /// More protocols than chapulin's `CH_ALPN_MAX`.
    TooManyProtocols,
    /// An identity's chain is longer than `certificate_chain_len_max`.
    TooManyCertificates,
    /// More suites than `cipher_suites_max`.
    TooManySuites,
};

comptime {
    assert(constants.server_key_len == c.CH_SRV_COOKIE_KEY_LEN);
    assert(constants.server_key_len == c.CH_SRV_TICKET_KEY_LEN);
    assert(constants.sha256_len == c.SHA256_LEN);
    assert(constants.ticket_identity_len_max == c.CH_TICKET_ID_MAX);
}

/// A client's values, converted.
pub const ClientConfig = struct {
    anchors: [c.CH_WEBPKI_ANCHOR_MAX]c.ch_trust_anchor,
    alpn: [c.CH_ALPN_MAX]c.ch_alpn_protocol,
    /// What each session starts from; `start` sets the clock and the ticket.
    values: chapulin.Client,

    pub fn init(config: *ClientConfig, client: values.Client) Error!void {
        // chapulin's `build.h`: the object and the declarations colibri reads were built from one
        // define list, which the package guarantees and this checks once per configuration.
        assert(chapulin.buildMatches());
        const alpn = try protocols(&config.alpn, client.alpn);
        const trust = try config.trust_of(client.trust);
        config.values = .{ .trust = trust, .alpn = alpn, .require_pq = client.require_pq };
    }

    fn trust_of(config: *ClientConfig, trust: values.Trust) Error!chapulin.Trust {
        switch (trust) {
            .web_pki => |judged| {
                // RFC 9846 §4.5.1.3: the trusted CAs a chain must reach, copied into a list of
                // chapulin's `CH_WEBPKI_ANCHOR_MAX`.
                if (judged.anchors.len > config.anchors.len) return error.TooManyAnchors;
                const anchors = config.anchors[0..judged.anchors.len];
                for (judged.anchors, anchors) |anchor, *converted| converted.* = chapulin.trustAnchor(anchor.subject, anchor.spki);
                return .{ .web_pki = .{ .anchors = anchors, .server_name = judged.server_name, .now_seconds = 0, .pins = judged.pins } };
            },
            .pins => |pinned| return .{ .pins = .{ .pins = pinned.pins, .server_name = pinned.server_name } },
        }
    }
};

/// A server's values, converted.
pub const ServerConfig = struct {
    ecdsa_chain: [constants.certificate_chain_len_max]c.ch_cert,
    rsa_chain: [constants.certificate_chain_len_max]c.ch_cert,
    alpn: [c.CH_ALPN_MAX]c.ch_alpn_protocol,
    suites: [constants.cipher_suites_max]chapulin.Suite,
    /// What each session starts from; `start` sets the clock.
    values: chapulin.Server,

    pub fn init(config: *ServerConfig, server: values.Server) Error!void {
        assert(chapulin.buildMatches());
        // RFC 9846 §9.1: the suites in the server's order, copied into a list as long as the three
        // colibri admits (decision 45).
        if (server.cipher_suites.len > config.suites.len) return error.TooManySuites;
        for (server.cipher_suites, config.suites[0..server.cipher_suites.len]) |code, *suite| suite.* = @enumFromInt(code);
        config.values = .{
            .cookie_key = server.cookie_key,
            .ticket_key = server.ticket_key,
            .now_seconds = 0,
            .alpn = try protocols(&config.alpn, server.alpn),
            .require_server_name = server.require_server_name,
            .cipher_suites = config.suites[0..server.cipher_suites.len],
        };
        if (server.ecdsa_p256) |identity| config.values.ecdsa_p256 = .{
            .chain = try certificates(&config.ecdsa_chain, identity.chain),
            .public_key = identity.public_key,
            .private_key = identity.private_key,
        };
        if (server.rsa_pss) |identity| config.values.rsa_pss = .{
            .chain = try certificates(&config.rsa_chain, identity.chain),
            .public_key = identity.public_key,
            .private_key = @ptrCast(@alignCast(identity.private_key)),
        };
    }

    /// chapulin's `ch_srv_check`: each provisioned key signs, and the signature verifies. It draws
    /// entropy and runs no I/O, so a program runs it once, before it serves.
    pub fn check(config: *const ServerConfig) error{IdentityRefused}!void {
        // RFC 9846 §4.5.2: a server's key signs its CertificateVerify, which its public key must
        // verify; a server with no identity has none.
        config.values.check() catch return error.IdentityRefused;
    }
};

/// Copies the protocol names into chapulin's list, which an empty list leaves empty: a program
/// that offers none sends no ALPN extension (RFC 7301 §3.1).
fn protocols(storage: *[c.CH_ALPN_MAX]c.ch_alpn_protocol, names: []const []const u8) Error![]const c.ch_alpn_protocol {
    // RFC 7301 §3.1: the protocols, most preferred first, copied into a list of chapulin's
    // `CH_ALPN_MAX`.
    if (names.len > storage.len) return error.TooManyProtocols;
    for (names, storage[0..names.len]) |name, *protocol| protocol.* = chapulin.alpnProtocol(name);
    return storage[0..names.len];
}

/// Copies a chain into chapulin's list, the end-entity first (RFC 9846 §4.5.1).
fn certificates(storage: *[constants.certificate_chain_len_max]c.ch_cert, chain: []const []const u8) Error![]const c.ch_cert {
    // RFC 9846 §4.5.1: the certificate_list, copied into a list of `certificate_chain_len_max`.
    if (chain.len > storage.len) return error.TooManyCertificates;
    for (chain, storage[0..chain.len]) |der, *certificate| certificate.* = chapulin.cert(der);
    return storage[0..chain.len];
}
