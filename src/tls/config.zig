//! Step 16c's values converted, once, into one chapulin object's values (decision 97 as amended).
//! chapulin takes the chains and the ALPN names as the caller's slices
//! (https://github.com/c4milo/chapulin/issues/213). Its anchors are a type of each object, so a
//! configuration holds them, at colibri's limit, and every session of the object borrows it. The
//! caller places a configuration and does not move it after `init`: its values point into it.
//!
//! Each object's module is a type of its own, so each configuration is a function of the module:
//! `record` takes the TCP object's and `quic` the QUIC object's.
//!
//! A conversion refuses only a list longer than the one it copies into. Every other rule is
//! chapulin's, which a session's `start` or the server's `check` reports (design §8 step 16c).
const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const constants = @import("constants.zig");
const values = @import("values.zig");

pub const Error = error{
    /// More anchors than `constants.limits.anchors_max`.
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

/// What a server's conversion refuses beside `Error`: its identities (decision 147).
pub const ServerError = Error || error{
    /// Two identities of one scheme.
    IdentityRepeated,
    /// An identity whose key has no scheme, which no `pem.key` filled.
    IdentityUnfilled,
    /// An ML-DSA-87 identity for an object without chapulin's ML-DSA-87 slot, which one built for a
    /// target without its host object does.
    IdentityUnavailable,
};

/// A client's values, converted for the object whose module is `chapulin`.
pub fn ClientConfig(comptime chapulin: type) type {
    const c = chapulin.c;
    return struct {
        const Config = @This();

        /// The most anchors and ALPN protocols the values may name, `constants.limits.anchors_max` and
        /// chapulin's `CH_ALPN_MAX`: `init` refuses more.
        pub const anchors_max: usize = constants.limits.anchors_max;
        pub const protocols_max: usize = c.CH_ALPN_MAX;

        anchors: [anchors_max]chapulin.TrustAnchor,
        suites: [constants.limits.cipher_suites_max]chapulin.Suite,
        /// What each session starts from; `start` sets the clock and the ticket.
        values: chapulin.Client,

        pub fn init(config: *Config, client: values.Client) Error!void {
            // chapulin's `build.h`: the object and the declarations colibri reads were built from
            // one define list, which the package guarantees and this checks once per configuration.
            assert(chapulin.buildMatches());
            const alpn = try protocols(chapulin, client.alpn);
            const trust = try config.trust_of(client.trust);
            config.values = .{ .trust = trust, .alpn = alpn, .require_pq = client.require_pq, .takes_tickets = client.takes_tickets };
            // Decided when the object is built, so an object that takes no description of the
            // CPU never names chapulin's `Cpu`, which exists in a host object alone.
            if (comptime has_cpu(chapulin.Client)) config.values.cpu = cpu_of(chapulin, client.cpu);
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
                    // `constants.limits.anchors_max`.
                    if (judged.anchors.len > config.anchors.len) return error.TooManyAnchors;
                    const anchors = config.anchors[0..judged.anchors.len];
                    for (judged.anchors, anchors) |anchor, *converted| converted.* = .{ .name = anchor.subject, .spki = anchor.spki };
                    return .{ .web_pki = .{ .anchors = anchors, .server_name = judged.server_name, .clock = no_clock(chapulin), .pins = judged.pins } };
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
        assert(constants.protocol.server_key_len == c.CH_SRV_COOKIE_KEY_LEN);
        assert(constants.protocol.server_key_len == c.CH_SRV_TICKET_KEY_LEN);
        assert(constants.protocol.sha256_len == c.SHA256_LEN);
        assert(constants.limits.ticket_identity_len_max == c.CH_TICKET_ID_MAX);
    }
    return struct {
        const Config = @This();

        /// The most ALPN protocols the values may name, chapulin's `CH_ALPN_MAX`: `init` refuses
        /// more.
        pub const protocols_max: usize = c.CH_ALPN_MAX;

        suites: [constants.limits.cipher_suites_max]chapulin.Suite,
        /// What each session starts from; `start` sets the clock.
        values: chapulin.Server,

        pub fn init(config: *Config, server: values.Server) ServerError!void {
            assert(chapulin.buildMatches());
            config.values = .{
                .cookie_key = server.cookie_key,
                .ticket_key = server.ticket_key,
                .alpn = try protocols(chapulin, server.alpn),
                .require_server_name = server.require_server_name,
            };
            // Decided when the object is built, so an object that takes no description of the
            // CPU never names chapulin's `Cpu`, which exists in a host object alone.
            if (comptime has_cpu(chapulin.Server)) config.values.cpu = cpu_of(chapulin, server.cpu);
            if (has_suite_order) {
                config.values.cipher_suites = try suite_order(chapulin, &config.suites, server.cipher_suites);
            } else if (server.cipher_suites.len > 0) {
                // RFC 9846 §9.1: an object without AES-GCM has one suite, and no order to set.
                return error.SuitesUnavailable;
            }
            for (server.identities) |identity| try identity_into(chapulin, &config.values, identity);
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

/// chapulin's clock (its `cfg.h`): a C function that each session's `init` calls once, with
/// `clock_io`. colibri reads no clock (non-negotiable 3), so the function answers the instant the
/// caller read, which a session keeps in its `instant` until chapulin's `init` has read it.
pub fn clock_at(comptime chapulin: type, instant: *const u64) chapulin.Clock {
    return .{ .now_seconds = &answer_instant, .clock_io = @constCast(instant) };
}

fn answer_instant(clock_io: ?*anyopaque) callconv(.c) u64 {
    const instant: *const u64 = @ptrCast(@alignCast(clock_io.?));
    return instant.*;
}

/// The clock a client's values hold until `start` gives the session its own. It answers 0, which
/// chapulin reads as no clock, so a Web PKI session started without one fails closed.
fn no_clock(comptime chapulin: type) chapulin.Clock {
    return .{ .now_seconds = &answer_none };
}

fn answer_none(clock_io: ?*anyopaque) callconv(.c) u64 {
    assert(clock_io == null);
    return 0;
}

/// Whether an object's `Values`, chapulin's `Client` or `Server`, take the caller's description of
/// its CPU, which a host object alone does (chapulin's decision 89, decision 97 as amended for
/// chapulin 0.2.0).
fn has_cpu(comptime Values: type) bool {
    return @TypeOf(@as(Values, undefined).cpu) != void;
}

/// chapulin's description of the CPU from what the program said: each constant-time claim rests on
/// the program's statement of the thread's mode, and the AES claim on the probe's `yes` as well,
/// since `no` and `not_known` give no ground to run the instructions. chapulin refuses a session
/// whose description is unset, and colibri's values have none unset. The SHA claims follow the
/// AES rule on arm64 alone: chapulin refuses the SHA-512 and SHA-3 claims on x86-64, and its SHA-256
/// claim there needs SSSE3 and SSE4.1 too, which stdx's probe does not answer. `avx2` and `vaes`
/// stay false until the probe answers them (https://github.com/c4milo/stdx/issues/16).
fn cpu_of(comptime chapulin: type, cpu: values.Cpu) chapulin.Cpu {
    const stated = cpu.timing == .data_independent;
    const sha_stated = builtin.cpu.arch == .aarch64 and stated;
    return .{
        .constant_time_aes = stated and cpu.probe.aes_clmul == .yes,
        .constant_time_multiply = stated,
        .constant_time_sha256 = sha_stated and cpu.probe.sha256 == .yes,
        .constant_time_sha512 = sha_stated and cpu.probe.sha512 == .yes,
        .constant_time_sha3 = sha_stated and cpu.probe.sha3 == .yes,
    };
}

/// What chapulin's PEM key call takes for the CPU: `cpu_of`'s description in a host object, and
/// nothing in an object that takes none.
pub fn cpu_value(comptime chapulin: type, cpu: values.Cpu) if (has_cpu(chapulin.Server)) ?chapulin.Cpu else void {
    if (comptime !has_cpu(chapulin.Server)) return {};
    return cpu_of(chapulin, cpu);
}

/// Copies a role's suite order into chapulin's list; an empty order keeps chapulin's own.
/// chapulin's `init` refuses a suite the object does not hold and a suite named twice.
fn suite_order(comptime chapulin: type, storage: *[constants.limits.cipher_suites_max]chapulin.Suite, codes: []const u16) Error![]const chapulin.Suite {
    // RFC 9846 §9.1: the suites in the role's order, copied into a list as long as the three
    // colibri admits (decision 45).
    if (codes.len > storage.len) return error.TooManySuites;
    for (codes, storage[0..codes.len]) |code, *suite| suite.* = @enumFromInt(code);
    return storage[0..codes.len];
}

/// The protocol names, most preferred first, which chapulin takes as they are: an empty list
/// sends no ALPN extension (RFC 7301 §3.1).
fn protocols(comptime chapulin: type, names: []const []const u8) Error![]const []const u8 {
    // RFC 7301 §3.1: chapulin's list holds `CH_ALPN_MAX` protocols.
    if (names.len > chapulin.c.CH_ALPN_MAX) return error.TooManyProtocols;
    return names;
}

/// Sets the slot of chapulin's server that `identity`'s scheme names (decision 147). chapulin
/// signs with the key whose scheme the client offers, and colibri chooses none.
fn identity_into(comptime chapulin: type, server: *chapulin.Server, identity: values.Identity) ServerError!void {
    const key = identity.key;
    const chain = try certificates(identity.chain);
    // RFC 9846 §4.5.2: the server signs its CertificateVerify with the key, so a key that names
    // no scheme has nothing to sign with.
    const scheme = key.scheme orelse return error.IdentityUnfilled;
    switch (scheme) {
        .ecdsa_secp256r1_sha256 => {
            // RFC 9846 §4.5.1.2: the server picks the certificate by the client's signature schemes,
            // so two of one scheme leave the choice to no rule.
            if (server.ecdsa_p256 != null) return error.IdentityRepeated;
            server.ecdsa_p256 = .{
                .chain = chain,
                .public_key = key.public_key[0..constants.protocol.p256_public_key_len],
                .private_key = key.private_key[0..constants.protocol.p256_private_key_len],
            };
        },
        .rsa_pss_rsae_sha256 => {
            // RFC 9846 §4.5.1.2, as for P-256 above.
            if (server.rsa_pss != null) return error.IdentityRepeated;
            // `pem.key` wrote chapulin's `ch_rsa_priv` at the start of the private room, which is
            // aligned and large enough for it in every object colibri builds.
            comptime assert(@sizeOf(chapulin.c.ch_rsa_priv) <= @sizeOf(@FieldType(values.Key, "private_key")));
            comptime assert(@alignOf(chapulin.c.ch_rsa_priv) <= @alignOf(values.Key) and
                @offsetOf(values.Key, "private_key") % @alignOf(chapulin.c.ch_rsa_priv) == 0);
            const private_key: *const chapulin.c.ch_rsa_priv = @ptrCast(&key.private_key);
            server.rsa_pss = .{
                .chain = chain,
                .public_key = key.public_key[0..private_key.n_len],
                .private_key = private_key,
            };
        },
        .mldsa87 => {
            // An object without the slot holds `void` there, so its branch names no field.
            if (comptime !has_mldsa87(chapulin.Server)) {
                // RFC 9846 §4.5.1.2: a server presents a key only for a scheme it can sign with.
                return error.IdentityUnavailable;
            } else {
                // RFC 9846 §4.5.1.2, as for P-256 above.
                if (server.mldsa87 != null) return error.IdentityRepeated;
                server.mldsa87 = .{ .chain = chain, .public_key = &key.public_key, .private_key = &key.private_key };
            }
        },
    }
}

/// Whether the object's server holds chapulin's ML-DSA-87 slot, which a host object's does.
fn has_mldsa87(comptime Server: type) bool {
    return @FieldType(Server, "mldsa87") != void;
}

/// A chain, the end-entity first (RFC 9846 §4.5.1), which chapulin takes as it is.
fn certificates(chain: []const []const u8) Error![]const []const u8 {
    // RFC 9846 §4.5.1: the certificate_list, at most `certificate_chain_len_max` certificates.
    if (chain.len > constants.limits.certificate_chain_len_max) return error.TooManyCertificates;
    return chain;
}

/// The lengths a session of the object takes, colibri's: the longest chain and the most anchors
/// (chapulin's `Limits`).
pub fn limits_of(comptime chapulin: type) chapulin.Limits {
    return .{
        .chain_max = constants.limits.certificate_chain_len_max,
        .anchors_max = constants.limits.anchors_max,
    };
}
