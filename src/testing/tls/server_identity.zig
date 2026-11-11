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
    /// The P-256 key the Go tool wrote as raw octets.
    key: tls.Key,
    cookie_key: [tls.constants.protocol.server_key_len]u8,
    /// The key the server seals its session tickets under, when the run gives it the time.
    ticket_key: [tls.constants.protocol.server_key_len]u8,
    /// The end-entity first, then the root that signed it (RFC 9846 §4.4.2).
    chain: [chain_len][]const u8,
    /// The identities the server presents, which point into this storage.
    identities: [constants.tls_identities_max]tls.Identity,
    /// The RSA and the ML-DSA-87 identity, when the run names them.
    rsa: PemStorage,
    mldsa87: PemStorage,
};

/// The rooms an identity read from PEM takes (decision 147): the files, the chain's DER, and the
/// key. A chain of two ML-DSA-87 certificates, the largest, is about 15,000 octets of DER.
pub const PemStorage = struct {
    file: [pem_file_len_max]u8,
    der: [pem_file_len_max]u8,
    certificates: [chain_len][]const u8,
    key: tls.Key,
};

/// The longest PEM file of an identity: an ML-DSA-87 chain's two certificates as base64.
const pem_file_len_max: usize = constants.tls_pem_file_len_max;

/// Reads `<prefix>.chain.pem` and `<prefix>.key.pem`, a chain and its key, through `tls.pem`, and
/// returns the identity that points into `storage`. The key must be of `scheme`.
pub fn load_pem(prefix: []const u8, scheme: tls.SignatureScheme, storage: *PemStorage, cpu_value: tls.Cpu) !tls.Identity {
    const chain_file = try check_file.read_part(prefix, ".chain.pem", &storage.file);
    const chain = try tls.pem.chain(chain_file, &storage.der, &storage.certificates);
    const key_file = try check_file.read_part(prefix, ".key.pem", &storage.file);
    defer std.crypto.secureZero(u8, &storage.file);
    try tls.pem.key(cpu_value, key_file, chain[0], &storage.key);
    if (storage.key.scheme != scheme) return error.KeySchemeWrong;
    return .{ .chain = chain, .key = &storage.key };
}

/// Adds the identity of `prefix`, of `scheme`, to the server `load` returned, after the
/// identities it holds.
pub fn add_pem(prefix: []const u8, scheme: tls.SignatureScheme, storage: *Storage, server: *tls.Server) !void {
    const room = if (scheme == .mldsa87) &storage.mldsa87 else &storage.rsa;
    const count = server.identities.len;
    std.debug.assert(count < storage.identities.len);
    storage.identities[count] = try load_pem(prefix, scheme, room, server.cpu);
    server.identities = storage.identities[0 .. count + 1];
}

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

/// Draws the ticket key, and has `server` issue session tickets sealed under it (RFC 9846 §4.7.1).
/// chapulin asks for one ticket key per deployment, and a ticket resumes only on a server that
/// holds it, which here is this process (decision 161).
pub fn issue_tickets(storage: *Storage, server: *tls.Server) void {
    entropy.fill(&storage.ticket_key);
    server.ticket_key = &storage.ticket_key;
}

/// Reads the four parts of the identity `tls_identity.go` minted, each raw DER or raw octets, as
/// the values of a server that offers `protocols` through ALPN.
pub fn load(prefix: []const u8, storage: *Storage, protocols: []const []const u8) !tls.Server {
    storage.chain = .{
        try check_file.read_part(prefix, ".leaf.der", &storage.leaf),
        try check_file.read_part(prefix, ".ca.der", &storage.issuer),
    };
    storage.key = .{ .scheme = .ecdsa_secp256r1_sha256 };
    try read_key(prefix, ".priv", storage.key.private_key[0..tls.constants.protocol.p256_private_key_len]);
    try read_key(prefix, ".pub", storage.key.public_key[0..tls.constants.protocol.p256_public_key_len]);
    storage.identities[0] = .{ .chain = &storage.chain, .key = &storage.key };
    return .{
        .identities = storage.identities[0..1],
        .cookie_key = &storage.cookie_key,
        .alpn = protocols,
        .cpu = cpu.probe(),
    };
}

/// Reads a key file, which must fill `into` exactly: one octet more is read to tell a longer file.
fn read_key(prefix: []const u8, suffix: []const u8, into: []u8) !void {
    var read_storage: [tls.constants.protocol.p256_public_key_len + 1]u8 = undefined;
    const read = try check_file.read_part(prefix, suffix, &read_storage);
    if (read.len != into.len) return LoadError.KeyLengthWrong;
    @memcpy(into, read);
}
