//! The TLS mode of design §9's client, which `tools/h2_interop.sh` runs against other
//! implementations' servers over TLS (design §8 step 5): the root the client trusts, read from the
//! files `tools/h2_interop/tls_identity.go` wrote. `read` returns them as the TLS value a
//! `client.Pool` takes, which names no protocol: each pool offers through ALPN what its
//! versions allow (decision 120), `h2` and then `http/1.1` as decision 88 orders them, or
//! `http/1.1` alone, and each connection speaks what the server selected.
const std = @import("std");
const tls = @import("tls");
const cpu = @import("../cpu.zig");
const constants = @import("../constants.zig");
const check_file = @import("check_file.zig");

/// The root the client trusts: its Subject Name and its SubjectPublicKeyInfo, each a whole DER TLV.
pub const Anchors = struct {
    name: [constants.tls_der_len_max]u8,
    spki: [constants.tls_der_len_max]u8,
    anchors: [1]tls.Anchor,
};

/// What a run does once before its first connection: reads the root `prefix` names into
/// `storage`, and returns the TLS value that trusts it for `hostname`, the name the server's
/// certificate must carry. The value names no protocol and points into `storage`.
pub fn read(storage: *Anchors, prefix: []const u8, hostname: []const u8) !tls.Client {
    const name = try check_file.read_part(prefix, ".name", &storage.name);
    const spki = try check_file.read_part(prefix, ".spki", &storage.spki);
    storage.anchors[0] = .{ .subject = name, .spki = spki };
    return .{ .trust = .{ .web_pki = .{ .anchors = &storage.anchors, .server_name = hostname } }, .cpu = cpu.probe() };
}
