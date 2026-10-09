//! The endpoint's configuration (decision 119): one TLS identity, the versions and limits every
//! connection serves under, and what QUIC connections alone take. `init` builds from it, in the
//! endpoint's own storage, the TLS configuration of its QUIC connections and the configuration
//! each borrows. `server.zig` exports `Config` as `EndpointConfig`. Split out of
//! `endpoint_connections.zig` for length.
const std = @import("std");
const assert = std.debug.assert;
const http = @import("http");
const h2 = @import("h2");
const quic = @import("quic");
const tls = @import("tls");
const constants = @import("../constants.zig");
const deadline = @import("../deadline.zig");
const versions_module = @import("../versions.zig");
const limits_module = @import("../limits.zig");
const coding_pool = @import("../coding/coding_pool.zig");
const connection_errors = @import("../connection/connection_errors.zig");
const quic_connection = @import("../quic/quic_connection.zig");
const endpoint_connections = @import("endpoint_connections.zig");

const StartError = connection_errors.StartError;

pub const Config = struct {
    /// The server's identity and keys, given once (RFC 9846 §4.4.2). Its `alpn` stays empty: the
    /// endpoint names the protocol `versions` allows, "h3" over QUIC (RFC 9114 §3.1).
    tls: ?tls.Server = null,
    /// The HTTP versions the endpoint serves (decision 117). A QUIC connection serves h3 alone.
    versions: versions_module.Versions = .{},
    /// Limits on what a peer may ask (decision 117). `requests_max` bounds an h3 connection's
    /// request streams too, up to `quic_requests_max`.
    limits: limits_module.Limits = .{},
    /// The limits each connection starts with (decision 110 as amended). Null turns a deadline
    /// off. `init` refuses limits `Deadlines.validate` or `validate_units` refuses, with
    /// `error.DeadlineInvalid`.
    deadlines: deadline.Deadlines = .{},
    /// The content codings the server applies to a response the caller marks `codable`, in its
    /// order of preference, and the pool their encoders come from (decision 101). Both or neither,
    /// and only `gzip` and `deflate`, which the server encodes.
    codings: []const http.content_coding.Coding = &.{},
    encoders: ?coding_pool.Encoders = null,
    /// QUIC connections alone. Decision 68: whether the caller reads each datagram's ECN codepoint
    /// and sets the one `send_datagram` names.
    ecn: bool = false,
    /// QUIC connections alone: the idle timeout the server advertises (RFC 9000 §10.1), in
    /// milliseconds.
    idle_timeout_ms: u64 = constants.quic_idle_timeout_ms_default,
    /// QUIC connections alone: the QUIC version the server switches a client to when the client
    /// lists it (RFC 9368 §2.3, decision 111), or null to keep every client in its first one.
    switch_to: ?quic.packet.header.Version = .v2,
    /// QUIC connections alone. When set, every client proves its address with a Retry token
    /// before a connection starts (RFC 9000 §8.1.2), which the endpoint seals and opens under this
    /// key (decision 55).
    retry: ?*const tls.quic.Retry = null,
    /// QUIC connections alone: where each connection's qlog log comes from (decision 102 as
    /// amended), or null for none.
    logs: ?endpoint_connections.LogProvider = null,
};

/// The protocol a QUIC connection's handshake names (RFC 9114 §3.1).
const alpn_h3 = [_][]const u8{"h3"};

/// Builds into `quic_tls` the TLS configuration of the endpoint's QUIC connections, checks that
/// its key signs, and fills `held` with what each connection borrows. `random` is the program's
/// source, which the check draws from for an RSA-PSS salt.
pub fn build(config: *const Config, quic_tls: *tls.quic.ServerConfig, held: *quic_connection.Config, random: tls.Random) StartError!void {
    assert((config.codings.len == 0) == (config.encoders == null));
    assert(config.limits.requests_max > 0 and config.limits.requests_max <= h2.constants.concurrent_streams_max);
    // RFC 9001 §3: QUIC's keys come from a TLS handshake, so an endpoint with no identity starts
    // no QUIC connection.
    const identity = config.tls orelse return error.NoVersion;
    // RFC 9114 §3.1: a QUIC connection serves h3 alone, which `versions` may turn off (decision
    // 117).
    if (!config.versions.h3) return error.NoVersion;
    assert(identity.alpn.len == 0);
    // A connection refuses limits `validate` refuses. An endpoint whose every connection refused
    // to start would answer no client and tell its program nothing, so the endpoint refuses them
    // here, once, where its program reads the error.
    try config.deadlines.validate();
    try config.deadlines.validate_units();
    var values = identity;
    values.alpn = &alpn_h3;
    quic_tls.init(values) catch |failure| switch (failure) {
        // The endpoint names one protocol, and a server's values name no anchor.
        error.TooManyProtocols, error.TooManyAnchors => unreachable,
        else => |refused| return refused,
    };
    try quic_tls.check(random);
    held.* = .{
        .tls = quic_tls,
        .ecn = config.ecn,
        .idle_timeout_ms = config.idle_timeout_ms,
        .codings = config.codings,
        .encoders = config.encoders,
        .switch_to = config.switch_to,
        .deadlines = config.deadlines,
        .requests_max = @min(config.limits.requests_max, constants.quic_requests_max),
    };
}

const testing = std.testing;
const support = @import("../quic/quic_test_support.zig");
const endpoint_support = support.endpoint_support;
const tcp_support = @import("../connection/connection_test_support.zig");

test "decision 119: an endpoint with no identity, or with h3 turned off, serves no version" {
    try support.start_endpoint(null);
    const config = &endpoint_support.endpoint_config;
    config.versions.h3 = false;
    try testing.expectError(error.NoVersion, endpoint_support.restart());
    config.versions.h3 = true;
    config.tls = null;
    try testing.expectError(error.NoVersion, endpoint_support.restart());
}

test "RFC 9846 §4.5.2: an endpoint whose key's signature does not verify refuses to start" {
    try support.start_endpoint(null);
    const config = &endpoint_support.endpoint_config;
    // Another point than the private key's, so its CertificateVerify fails.
    var other: [tls.constants.p256_public_key_len]u8 = tcp_support.public_key.*;
    other[other.len - 1] ^= 1;
    config.tls.?.ecdsa_p256.?.public_key = &other;
    try testing.expectError(error.IdentityRefused, endpoint_support.restart());
    // A chain longer than the configuration holds is the TLS configuration's own refusal.
    const long_chain: [tls.constants.certificate_chain_len_max + 1][]const u8 = @splat(tcp_support.chain[0]);
    config.tls = support.server_values();
    config.tls.?.ecdsa_p256.?.chain = &long_chain;
    try testing.expectError(error.TooManyCertificates, endpoint_support.restart());
}

test "RFC 9000 §4.6: requests_max bounds the request streams a client opens, up to h3's records" {
    try support.start_endpoint(null);
    try support.connect();
    // The default of 100 holds more requests than a QUIC connection's records.
    try testing.expectEqual(constants.quic_requests_max, support.client.peer_parameters.?.initial_max_streams_bidi);
    try support.start_endpoint(null);
    endpoint_support.endpoint_config.limits.requests_max = requests_few;
    try endpoint_support.restart();
    try support.connect();
    try testing.expectEqual(requests_few, support.client.peer_parameters.?.initial_max_streams_bidi);
}

/// A limit on requests lower than h3's records.
const requests_few: u32 = 2;
