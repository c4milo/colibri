//! A channel's configuration (decision 120, design §8 step 21c): one TLS value, the versions the
//! client speaks, and what its TCP or QUIC connections alone take. `Channel.init` builds from it,
//! in the channel's own storage, the TLS configuration of each transport the channel offers and
//! the configuration each connection borrows. `client.zig` exports `Config` as `ChannelConfig`
//! until step 21c.11, and `StartError` under its own name.
const std = @import("std");
const assert = std.debug.assert;
const tls = @import("tls");
const tls_provider = @import("tls_provider");
const h11 = @import("h11");
const http = @import("http");
const constants = @import("../constants.zig");
const coding = @import("../coding.zig");
const coding_pool = @import("../coding_pool.zig");
const versions_module = @import("../versions.zig");
const connection_module = @import("../connection/connection.zig");
const quic_connection = @import("../quic/quic_connection.zig");

/// What every channel to one origin borrows. The caller keeps it alive and in place while any
/// channel holds it.
pub const Config = struct {
    /// How the client judges the server, given once for TCP and QUIC, or null for cleartext. Its
    /// `alpn` stays empty: the channel names the protocols `versions` allows (decision 117).
    tls: ?tls.Client = null,
    /// The HTTP versions the client speaks (decision 117). A TCP connection speaks h11 or h2, and
    /// a QUIC connection h3 alone (RFC 9114 §3.1).
    versions: versions_module.Versions = .{},
    /// The authority every request names: `:authority` in h2 and h3 (RFC 9113 §8.3.1, RFC 9114
    /// §4.3.1) and Host in h11 (RFC 9112 §3.2).
    authority: []const u8,
    /// The content codings the client offers in each request's Accept-Encoding, in its order of
    /// preference, and the pools of decoders it removes them with, which channels may share
    /// (decision 101 as amended): `decoders` for `gzip` and `deflate`, `zstd_decoders` and
    /// `br_decoders`. Each coding is named once at most and has its pool, and each pool given serves
    /// a coding named.
    codings: []const http.content_coding.Coding = &.{},
    decoders: ?h11.coding.Storage = null,
    zstd_decoders: ?coding_pool.ZstdDecoders = null,
    br_decoders: ?coding_pool.BrotliDecoders = null,
    /// Whether QUIC goes first when neither an HTTPS record nor Alt-Svc says whether the origin
    /// speaks h3 (RFC 9114 §3.1). When false, QUIC waits for a TCP response's Alt-Svc.
    quic_first: bool = true,
    /// How long QUIC's handshake runs before TCP opens beside it, in nanoseconds.
    fallback_delay_ns: u64 = constants.fallback_delay_ns_default,
    /// QUIC connections alone. Decision 68: whether the caller reads each datagram's ECN codepoint
    /// and sets the one `send_datagram` names.
    ecn: bool = false,
    /// QUIC connections alone: the idle timeout the client advertises (RFC 9000 §10.1), in
    /// milliseconds.
    idle_timeout_ms: u64 = constants.quic_idle_timeout_ms_default,
};

/// Why `Channel.init`, `start_tcp` or `start_quic` refused. `init` returns every member but
/// `TlsRefused`, before the program opens a socket, and the two starts return `TlsRefused` alone.
pub const StartError = connection_module.StartError || quic_connection.StartError || error{
    /// The TLS value names more anchors than `tls.record.ClientConfig.anchors_max`.
    TooManyAnchors,
    /// The TLS value names more suites than `tls.constants.cipher_suites_max`.
    TooManySuites,
    /// The TLS value orders suites for an object that holds one suite alone (decision 97).
    SuitesUnavailable,
};

/// Which transports a channel offers: those `versions` allows a version on.
pub const Offered = struct { tcp: bool, quic: bool };

/// Where `build` writes: the TLS configuration of each transport, and what each connection
/// borrows. `build` writes only those of a transport the channel offers.
pub const Built = struct {
    tcp_tls: *tls.record.ClientConfig,
    quic_tls: *tls.quic.ClientConfig,
    tcp: *connection_module.Config,
    quic: *quic_connection.Config,
};

/// Builds the TLS configuration of each transport the channel offers and fills what each
/// connection borrows. `pool_given` says whether the program placed a receive pool, which QUIC's
/// connections need (decision 61).
pub fn build(config: *const Config, pool_given: bool, built: Built) StartError!Offered {
    assert(config.authority.len > 0);
    assert(coding.codings_valid(config.codings, .of(config)));
    // Decision 117: `versions` names the protocols, so the TLS value names none.
    if (config.tls) |values| assert(values.alpn.len == 0);
    const offers = offered(config, pool_given);
    // RFC 9114 §3.1: a client speaks h3 over QUIC and h11 or h2 over TCP, so a channel that
    // offers neither transport has no version to speak (decision 117).
    if (!offers.tcp and !offers.quic) return error.NoVersion;
    if (offers.quic) try build_quic(config, built);
    if (offers.tcp) try build_tcp(config, built);
    return offers;
}

fn offered(config: *const Config, pool_given: bool) Offered {
    return .{
        // RFC 9114 §3.1: a TCP connection speaks h11 or h2, never h3.
        .tcp = versions_module.cleartext(config.versions) != null,
        // RFC 9114 §3.1.2: h3 serves "https" origins alone, so QUIC needs the TLS value, and
        // `versions` may turn h3 off (decision 117).
        .quic = pool_given and config.tls != null and config.versions.h3,
    };
}

/// The protocol a QUIC connection's handshake offers (RFC 9114 §3.1).
const alpn_h3 = [_][]const u8{&tls_provider.constants.alpn_h3};

fn build_quic(config: *const Config, built: Built) StartError!void {
    var values = config.tls.?;
    values.alpn = &alpn_h3;
    try convert(built.quic_tls, values);
    // The channel names each connection's `server_address` as it starts it.
    built.quic.* = .{
        .tls = built.quic_tls,
        .authority = config.authority,
        .ecn = config.ecn,
        .idle_timeout_ms = config.idle_timeout_ms,
        .codings = config.codings,
        .decoders = config.decoders,
        .zstd_decoders = config.zstd_decoders,
        .br_decoders = config.br_decoders,
    };
}

/// The protocols a TCP connection's handshake offers, most preferred first (RFC 7301 §3.1): h2
/// (RFC 9113 §3.2), then h11 (decision 88), as `versions` allows them.
const alpn_both = [_][]const u8{ &tls_provider.constants.alpn_h2, tls_provider.constants.alpn_http_1_1 };
const alpn_h2 = [_][]const u8{&tls_provider.constants.alpn_h2};
const alpn_h11 = [_][]const u8{tls_provider.constants.alpn_http_1_1};

fn build_tcp(config: *const Config, built: Built) StartError!void {
    built.tcp.* = .{
        .tls = null,
        .versions = config.versions,
        .authority = config.authority,
        .codings = config.codings,
        .decoders = config.decoders,
        .zstd_decoders = config.zstd_decoders,
        .br_decoders = config.br_decoders,
    };
    var values = config.tls orelse return;
    const versions = config.versions;
    values.alpn = if (versions.h11 and versions.h2) &alpn_both else if (versions.h2) &alpn_h2 else &alpn_h11;
    try convert(built.tcp_tls, values);
    built.tcp.tls = built.tcp_tls;
}

/// Converts `values` into `tls_config`, the TCP object's configuration or the QUIC object's.
fn convert(tls_config: anytype, values: tls.Client) StartError!void {
    tls_config.init(values) catch |failure| switch (failure) {
        // The channel names two protocols at most, and a client's values name no chain.
        error.TooManyProtocols, error.TooManyCertificates => unreachable,
        else => |refused| return refused,
    };
}
