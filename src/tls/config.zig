//! Step 16c's values converted, once, into one chapulin object's values (decision 97 as amended).
//! chapulin's values point at lists of its own C element types, so a configuration holds those
//! lists, at chapulin's limits, and every session of the object borrows it. The caller places a
//! configuration and does not move it after `init`: its values point into it.
//!
//! Each object's module is a type of its own, so each configuration is a function of the module:
//! `record` takes the TCP object's and `quic` the QUIC object's.
//!
//! A conversion refuses only a list longer than the one it copies into. Every other rule is
//! chapulin's, which a session's `start` or the server's `check` reports (design §8 step 16c).
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const values = @import("values.zig");

pub const Error = error{
    /// More anchors than chapulin's `CH_WEBPKI_ANCHOR_MAX`.
    TooManyAnchors,
    /// More protocols than chapulin's `CH_ALPN_MAX`.
    TooManyProtocols,
    /// An identity's chain is longer than `certificate_chain_len_max`.
    TooManyCertificates,
    /// More suites than `cipher_suites_max`.
    TooManySuites,
    /// A suite order for an object that holds TLS_CHACHA20_POLY1305_SHA256 alone, which one built
    /// for a target without the AES instructions does (decision 97).
    SuitesUnavailable,
};

/// A client's values, converted for the object whose module is `chapulin`.
pub fn ClientConfig(comptime chapulin: type) type {
    const c = chapulin.c;
    return struct {
        const Config = @This();

        /// The most anchors and ALPN protocols the values may name, chapulin's
        /// `CH_WEBPKI_ANCHOR_MAX` and `CH_ALPN_MAX`: `init` refuses more.
        pub const anchors_max: usize = c.CH_WEBPKI_ANCHOR_MAX;
        pub const protocols_max: usize = c.CH_ALPN_MAX;

        anchors: [anchors_max]c.ch_trust_anchor,
        alpn: [protocols_max]c.ch_alpn_protocol,
        suites: [constants.cipher_suites_max]chapulin.Suite,
        /// What each session starts from; `start` sets the clock and the ticket.
        values: chapulin.Client,

        pub fn init(config: *Config, client: values.Client) Error!void {
            // chapulin's `build.h`: the object and the declarations colibri reads were built from
            // one define list, which the package guarantees and this checks once per configuration.
            assert(chapulin.buildMatches());
            const alpn = try protocols(chapulin, &config.alpn, client.alpn);
            const trust = try config.trust_of(client.trust);
            config.values = .{ .trust = trust, .alpn = alpn, .require_pq = client.require_pq };
            // Decided when the object is built, so an object that takes no answer never names
            // chapulin's `AesInstructions`, which exists in an `AES=runtime` object alone.
            if (comptime takes_answer(chapulin.Client)) config.values.aes_instructions = answer_of(chapulin, client.aes_instructions);
            if (has_suite_order) {
                config.values.cipher_suites = try suite_order(chapulin, &config.suites, client.cipher_suites);
            } else if (client.cipher_suites.len > 0) {
                // RFC 9846 §9.1: an object without AES-GCM has one suite, and no order to set.
                return error.SuitesUnavailable;
            }
        }

        /// Whether the object offers more than one suite, and so takes a client's order.
        const has_suite_order = @TypeOf(@as(chapulin.Client, undefined).cipher_suites) != void;

        fn trust_of(config: *Config, trust: values.Trust) Error!chapulin.Trust {
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
}

/// A server's values, converted for the object whose module is `chapulin`.
pub fn ServerConfig(comptime chapulin: type) type {
    const c = chapulin.c;
    comptime {
        assert(constants.server_key_len == c.CH_SRV_COOKIE_KEY_LEN);
        assert(constants.server_key_len == c.CH_SRV_TICKET_KEY_LEN);
        assert(constants.sha256_len == c.SHA256_LEN);
        assert(constants.ticket_identity_len_max == c.CH_TICKET_ID_MAX);
    }
    return struct {
        const Config = @This();

        /// The most ALPN protocols the values may name, chapulin's `CH_ALPN_MAX`: `init` refuses
        /// more.
        pub const protocols_max: usize = c.CH_ALPN_MAX;

        ecdsa_chain: [constants.certificate_chain_len_max]c.ch_cert,
        rsa_chain: [constants.certificate_chain_len_max]c.ch_cert,
        alpn: [protocols_max]c.ch_alpn_protocol,
        suites: [constants.cipher_suites_max]chapulin.Suite,
        /// What each session starts from; `start` sets the clock.
        values: chapulin.Server,

        pub fn init(config: *Config, server: values.Server) Error!void {
            assert(chapulin.buildMatches());
            config.values = .{
                .cookie_key = server.cookie_key,
                .ticket_key = server.ticket_key,
                .now_seconds = 0,
                .alpn = try protocols(chapulin, &config.alpn, server.alpn),
                .require_server_name = server.require_server_name,
            };
            // Decided when the object is built, so an object that takes no answer never names
            // chapulin's `AesInstructions`, which exists in an `AES=runtime` object alone.
            if (comptime takes_answer(chapulin.Server)) config.values.aes_instructions = answer_of(chapulin, server.aes_instructions);
            if (has_suite_order) {
                config.values.cipher_suites = try suite_order(chapulin, &config.suites, server.cipher_suites);
            } else if (server.cipher_suites.len > 0) {
                // RFC 9846 §9.1: an object without AES-GCM has one suite, and no order to set.
                return error.SuitesUnavailable;
            }
            if (server.ecdsa_p256) |identity| config.values.ecdsa_p256 = .{
                .chain = try certificates(chapulin, &config.ecdsa_chain, identity.chain),
                .public_key = identity.public_key,
                .private_key = identity.private_key,
            };
            if (server.rsa_pss) |identity| config.values.rsa_pss = .{
                .chain = try certificates(chapulin, &config.rsa_chain, identity.chain),
                .public_key = identity.public_key,
                .private_key = @ptrCast(@alignCast(identity.private_key)),
            };
        }

        /// Whether the object holds the AES-GCM suites beside ChaCha20, and so an order among them.
        const has_suite_order = @TypeOf(@as(chapulin.Server, undefined).cipher_suites) != void;

        /// chapulin's `ch_srv_check`: each provisioned key signs, and the signature verifies. It
        /// draws from `random`, for an RSA-PSS salt, and runs no I/O, so a program runs it once,
        /// before it serves.
        pub fn check(config: *const Config, random: values.Random) error{IdentityRefused}!void {
            var checked = config.values;
            checked.random = random;
            // RFC 9846 §4.5.2: a server's key signs its CertificateVerify, which its public key
            // must verify; a server with no identity has none.
            checked.check() catch return error.IdentityRefused;
        }
    };
}

/// Whether an object's `Values`, chapulin's `Client` or `Server`, take the caller's answer on the AES
/// instructions, which an `AES=runtime` object alone does (decision 97 as amended on 2026-09-29).
fn takes_answer(comptime Values: type) bool {
    return @TypeOf(@as(Values, undefined).aes_instructions) != void;
}

/// The caller's answer on the AES instructions in the object's own type. chapulin refuses a session
/// whose answer is unset, and colibri's values have no unset answer.
fn answer_of(comptime chapulin: type, answer: values.AesInstructions) chapulin.AesInstructions {
    return switch (answer) {
        .present => .present,
        .absent => .absent,
    };
}

/// Copies a role's suite order into chapulin's list; an empty order keeps chapulin's own.
/// chapulin's `init` refuses a suite the object does not hold and a suite named twice.
fn suite_order(comptime chapulin: type, storage: *[constants.cipher_suites_max]chapulin.Suite, codes: []const u16) Error![]const chapulin.Suite {
    // RFC 9846 §9.1: the suites in the role's order, copied into a list as long as the three
    // colibri admits (decision 45).
    if (codes.len > storage.len) return error.TooManySuites;
    for (codes, storage[0..codes.len]) |code, *suite| suite.* = @enumFromInt(code);
    return storage[0..codes.len];
}

/// Copies the protocol names into chapulin's list, which an empty list leaves empty: a program
/// that offers none sends no ALPN extension (RFC 7301 §3.1).
fn protocols(comptime chapulin: type, storage: *[chapulin.c.CH_ALPN_MAX]chapulin.c.ch_alpn_protocol, names: []const []const u8) Error![]const chapulin.c.ch_alpn_protocol {
    // RFC 7301 §3.1: the protocols, most preferred first, copied into a list of chapulin's
    // `CH_ALPN_MAX`.
    if (names.len > storage.len) return error.TooManyProtocols;
    for (names, storage[0..names.len]) |name, *protocol| protocol.* = chapulin.alpnProtocol(name);
    return storage[0..names.len];
}

/// Copies a chain into chapulin's list, the end-entity first (RFC 9846 §4.5.1).
fn certificates(comptime chapulin: type, storage: *[constants.certificate_chain_len_max]chapulin.c.ch_cert, chain: []const []const u8) Error![]const chapulin.c.ch_cert {
    // RFC 9846 §4.5.1: the certificate_list, copied into a list of `certificate_chain_len_max`.
    if (chain.len > storage.len) return error.TooManyCertificates;
    for (chain, storage[0..chain.len]) |der, *certificate| certificate.* = chapulin.cert(der);
    return storage[0..chain.len];
}
