//! The TLS mode of design §9's client, which `tools/h2_interop.sh` runs against other
//! implementations' servers over TLS (design §8 step 5): the root the client trusts, read from the
//! files `tools/h2_interop/tls_identity.go` wrote, converted into the configuration the `client`
//! module's connections run the handshake from (design §8 step 17c).
//!
//! The client offers `h2` and then `http/1.1` through ALPN, or `http/1.1` alone, as decision 88
//! orders them, and each connection speaks what the server selected.
const std = @import("std");
const tls = @import("tls");
const cpu = @import("../cpu.zig");
const constants = @import("../constants.zig");
const check_file = @import("check_file.zig");
const alpn = @import("../alpn.zig");

/// The root the client trusts: its Subject Name and its SubjectPublicKeyInfo, each a whole DER TLV,
/// and the configuration converted from them.
pub const Anchors = struct {
    name: [constants.tls_der_len_max]u8,
    spki: [constants.tls_der_len_max]u8,
    anchors: [1]tls.Anchor,
    config: tls.record.ClientConfig,
};

/// What a run does once before its first connection: reads the root `prefix` names into `storage`,
/// and converts it, the name the server's certificate must carry and the protocols to offer.
pub fn load(storage: *Anchors, prefix: []const u8, hostname: []const u8, protocols: []const []const u8) !*const tls.record.ClientConfig {
    const name = try check_file.read_part(prefix, ".name", &storage.name);
    const spki = try check_file.read_part(prefix, ".spki", &storage.spki);
    storage.anchors[0] = .{ .subject = name, .spki = spki };
    try storage.config.init(.{
        .trust = .{ .web_pki = .{ .anchors = &storage.anchors, .server_name = hostname } },
        .alpn = protocols,
        .cpu = cpu.probe(),
    });
    return &storage.config;
}

/// The configuration the origin mode's QUIC connections run the handshake from: the root `load`
/// read into `storage`, the same name, and "h3" through ALPN (RFC 9114 §3.1).
pub fn load_quic(config: *tls.quic.ClientConfig, storage: *const Anchors, hostname: []const u8) !*const tls.quic.ClientConfig {
    try config.init(.{
        .trust = .{ .web_pki = .{ .anchors = &storage.anchors, .server_name = hostname } },
        .alpn = &alpn.alpn_h3,
        .cpu = cpu.probe(),
    });
    return config;
}
