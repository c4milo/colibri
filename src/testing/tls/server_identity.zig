//! What a TLS server loads once at start, which `accept_check.zig` and the h2 server's TLS mode
//! share: RFC 9846 §4.3.2's cookie key, and the identity `tools/h2_interop/tls_identity.go` wrote,
//! as the values of a `tls.Server` (design §8 step 16c).
//!
//! This endpoint code may read the operating system's entropy; the library may not, and does not.
const std = @import("std");
const tls = @import("tls");
const constants = @import("../constants.zig");
const check_file = @import("check_file.zig");
const entropy = @import("../entropy.zig");
const cpu = @import("../cpu.zig");

/// How many certificates this server presents: the end-entity and the one root above it.
const chain_len: usize = 2;

/// The storage the loaded identity and cookie key are read into. It outlives every session,
/// because the configuration converted from them points into it (decision 35).
pub const Storage = struct {
    leaf: [constants.tls_der_len_max]u8,
    issuer: [constants.tls_der_len_max]u8,
    private_key: [tls.constants.p256_private_key_len]u8,
    public_key: [tls.constants.p256_public_key_len]u8,
    cookie_key: [tls.constants.server_key_len]u8,
    /// The end-entity first, then the root that signed it (RFC 9846 §4.4.2).
    chain: [chain_len][]const u8,
};

pub const LoadError = error{
    /// A key file is not the length ecdsa_secp256r1_sha256 fixes: a 32-octet scalar, or a
    /// 64-octet point X||Y.
    KeyLengthWrong,
};

/// Draws the cookie key. RFC 9846 §4.3.2 asks for one cookie key per deployment, and a run is one
/// deployment. Each session draws the rest from the source `entropy.zig` hands its `start`.
pub fn seed(storage: *Storage) void {
    entropy.fill(&storage.cookie_key);
}

/// Reads the four parts of the identity `tls_identity.go` minted, each raw DER or raw octets, as
/// the values of a server that offers `protocols` through ALPN.
pub fn load(prefix: []const u8, storage: *Storage, protocols: []const []const u8) !tls.Server {
    storage.chain = .{
        try check_file.read_part(prefix, ".leaf.der", &storage.leaf),
        try check_file.read_part(prefix, ".ca.der", &storage.issuer),
    };
    try read_key(prefix, ".priv", &storage.private_key);
    try read_key(prefix, ".pub", &storage.public_key);
    return .{
        .ecdsa_p256 = .{ .chain = &storage.chain, .public_key = &storage.public_key, .private_key = &storage.private_key },
        .cookie_key = &storage.cookie_key,
        .alpn = protocols,
        .cpu = cpu.probe(),
    };
}

/// Reads a key file, which must fill `into` exactly: one octet more is read to tell a longer file.
fn read_key(prefix: []const u8, suffix: []const u8, into: []u8) !void {
    var read_storage: [tls.constants.p256_public_key_len + 1]u8 = undefined;
    const read = try check_file.read_part(prefix, suffix, &read_storage);
    if (read.len != into.len) return LoadError.KeyLengthWrong;
    @memcpy(into, read);
}
