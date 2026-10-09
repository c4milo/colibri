//! The endpoint's configuration (decision 119): one TLS identity, the versions and limits every
//! connection serves under, and what TCP or QUIC connections alone take. `init` builds from it, in
//! the endpoint's own storage, the TLS configuration of each transport the endpoint serves and the
//! configurations its connections borrow. `server.zig` exports `Config` as `EndpointConfig`. Split out of
//! `endpoint_connections.zig` for length.
const std = @import("std");
const assert = std.debug.assert;
const http = @import("http");
const h2 = @import("h2");
const h11 = @import("h11");
const tls_provider = @import("tls_provider");
const quic = @import("quic");
const tls = @import("tls");
const constants = @import("../constants.zig");
const deadline = @import("../deadline.zig");
const versions_module = @import("../versions.zig");
const limits_module = @import("../limits.zig");
const coding_pool = @import("../coding/coding_pool.zig");
const alt_svc = @import("../alt_svc.zig");
const connection_config = @import("../connection/connection_config.zig");
const connection_errors = @import("../connection/connection_errors.zig");
const quic_connection = @import("../quic/quic_connection.zig");
const endpoint_connections = @import("endpoint_connections.zig");

const StartError = connection_errors.StartError;

/// The endpoint reads it while it runs, so the caller keeps it alive and in place after `init`.
pub const Config = struct {
    /// The server's certificate chain and key, given once (RFC 9846 §4.5.1, §4.5.2). Its `alpn`
    /// stays empty: the endpoint names the protocol `versions` allows, "h3" over QUIC (RFC 9114
    /// §3.1).
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
    /// TCP connections alone: h11's decoders of the `gzip` and `deflate` transfer codings (decision
    /// 91), and where h11 decodes a body that carries either (decision 98).
    decoders: ?h11.coding.Storage = null,
    decoded: []u8 = &.{},
    /// TCP connections over TLS alone: the h3 endpoint each advertises (decision 100), or null.
    h3_alternative: ?alt_svc.Alternative = null,
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

/// How many slots of each kind an endpoint holds.
pub const Counts = struct { tcp: usize, quic: usize };

/// Which transports an endpoint serves: those it holds slots for whose versions `versions` allows.
pub const Served = struct { tcp: bool, quic: bool };

/// The configurations a TCP connection borrows, one for each `Security`, which differ in `tls`
/// alone.
pub const TcpConfigs = struct { cleartext: connection_config.Config, secure: connection_config.Config };

/// Where `build` writes: the TLS configuration of each transport, and what each connection borrows.
pub const Built = struct {
    quic_tls: *tls.quic.ServerConfig,
    quic: *quic_connection.Config,
    tcp_tls: *tls.record.ServerConfig,
    tcp: *TcpConfigs,
};

/// Builds the TLS configuration of each transport the endpoint serves, checks that its key signs,
/// and fills what each connection borrows. `random` is the program's source, which each check
/// draws from for an RSA-PSS salt.
pub fn build(config: *const Config, counts: Counts, built: Built, random: tls.Random) StartError!Served {
    assert((config.codings.len == 0) == (config.encoders == null));
    for (config.codings) |coding| assert(coding_pool.encodes(coding));
    assert(config.limits.requests_max > 0 and config.limits.requests_max <= h2.constants.concurrent_streams_max);
    assert(config.limits.data_frame_len_min <= h2.constants.max_frame_size_initial);
    if (config.tls) |identity| assert(identity.alpn.len == 0);
    // RFC 9114 §3.1: a TCP connection speaks h11 or h2, and `versions` may turn both off (decision
    // 117).
    const serves_tcp = counts.tcp > 0 and versions_module.tcp_choice(config.versions) != null;
    // RFC 9001 §3: QUIC's keys come from a TLS handshake, so an endpoint with no identity starts
    // no QUIC connection. RFC 9114 §3.1: its QUIC connections speak h3, under the token the
    // handshake names, and `versions` may turn h3 off (decision 117).
    const serves_quic = counts.quic > 0 and config.tls != null and config.versions.h3;
    // RFC 9114 §3.1 and RFC 9113 §3: the slots it holds speak none of the versions `versions`
    // allows, so the endpoint would serve no client.
    if (!serves_tcp and !serves_quic) return error.NoVersion;
    // A connection refuses limits `validate` refuses. An endpoint whose every connection refused
    // to start would answer no client and tell its program nothing, so the endpoint refuses them
    // here, once, where its program reads the error. Decision 110 as amended judges the body rate
    // in units only where a body may arrive in them.
    try config.deadlines.validate();
    const units = serves_quic or (serves_tcp and (config.tls != null or config.versions.h2));
    if (units) try config.deadlines.validate_units();
    if (serves_quic) try build_quic(config, built, random);
    if (serves_tcp) try build_tcp(config, built, random);
    return .{ .tcp = serves_tcp, .quic = serves_quic };
}

/// The protocol a QUIC connection's handshake names (RFC 9114 §3.1).
const alpn_h3 = [_][]const u8{"h3"};

fn build_quic(config: *const Config, built: Built, random: tls.Random) StartError!void {
    var values = config.tls.?;
    values.alpn = &alpn_h3;
    built.quic_tls.init(values) catch |failure| switch (failure) {
        // The endpoint names one protocol, and a server's values name no anchor.
        error.TooManyProtocols, error.TooManyAnchors => unreachable,
        else => |refused| return refused,
    };
    try built.quic_tls.check(random);
    built.quic.* = .{
        .tls = built.quic_tls,
        .ecn = config.ecn,
        .idle_timeout_ms = config.idle_timeout_ms,
        .codings = config.codings,
        .encoders = config.encoders,
        .switch_to = config.switch_to,
        .deadlines = config.deadlines,
        .requests_max = @min(config.limits.requests_max, constants.quic_requests_max),
    };
}

/// The protocols a TCP connection's handshake offers, in the server's order (RFC 7301 §3.2): h2
/// first (RFC 9113 §3.2), then h11 (decision 88), as `versions` allows them.
const alpn_both = [_][]const u8{ &tls_provider.constants.alpn_h2, tls_provider.constants.alpn_http_1_1 };
const alpn_h2 = [_][]const u8{&tls_provider.constants.alpn_h2};
const alpn_h11 = [_][]const u8{tls_provider.constants.alpn_http_1_1};

fn build_tcp(config: *const Config, built: Built, random: tls.Random) StartError!void {
    built.tcp.cleartext = .{
        .tls = null,
        .versions = config.versions,
        .decoders = config.decoders,
        .decoded = config.decoded,
        .h3_alternative = config.h3_alternative,
        .codings = config.codings,
        .encoders = config.encoders,
        .deadlines = config.deadlines,
        .limits = config.limits,
    };
    built.tcp.secure = built.tcp.cleartext;
    var values = config.tls orelse return;
    const versions = config.versions;
    values.alpn = if (versions.h11 and versions.h2) &alpn_both else if (versions.h2) &alpn_h2 else &alpn_h11;
    built.tcp_tls.init(values) catch |failure| switch (failure) {
        // The endpoint names two protocols at most, and a server's values name no anchor.
        error.TooManyProtocols, error.TooManyAnchors => unreachable,
        else => |refused| return refused,
    };
    try built.tcp_tls.check(random);
    built.tcp.secure.tls = built.tcp_tls;
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

/// An endpoint of one TCP slot and no QUIC slot. Test-only.
const TcpOnly = @import("endpoint.zig").EndpointOf(.{ .tcp_connections = 1, .quic_connections = 0 });
threadlocal var tcp_only: TcpOnly align(@alignOf(TcpOnly)) = undefined;
threadlocal var tcp_only_config: Config align(@alignOf(Config)) = undefined;

fn start_tcp_only(identity: ?tls.Server, deadlines: deadline.Deadlines) StartError!void {
    tcp_only_config = .{ .tls = identity, .versions = .{ .h2 = false }, .deadlines = deadlines };
    return tcp_only.init(&tcp_only_config, tcp_support.stream.random(), 0, tcp_support.now_ns);
}

test "decision 110 as amended: units are judged only where a body may arrive in them" {
    // h11 in cleartext reads a body octet by octet, so a rate no unit could meet is taken there.
    const slow: deadline.Deadlines = .{ .body_rate_min = 1 };
    try start_tcp_only(null, slow);
    // Over TLS a body arrives a record at a time, and the same rate is refused.
    try testing.expectError(error.DeadlineInvalid, start_tcp_only(support.server_values(), slow));
}

test "RFC 9846 §4.5.2: an endpoint of TCP slots alone refuses a key whose signature does not verify" {
    var identity = support.server_values();
    var other: [tls.constants.p256_public_key_len]u8 = tcp_support.public_key.*;
    other[other.len - 1] ^= 1;
    identity.ecdsa_p256.?.public_key = &other;
    try testing.expectError(error.IdentityRefused, start_tcp_only(identity, .{}));
    try start_tcp_only(support.server_values(), .{});
}
