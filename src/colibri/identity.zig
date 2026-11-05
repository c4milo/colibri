//! A server's identity, read from PEM (RFC 7468) into memory the `Server` holds (decision 150):
//! the chain, its key, and the cookie key RFC 9846 §4.3.2 asks a server to hold.
const std = @import("std");
const assert = std.debug.assert;
const tls = @import("tls");
const constants = @import("constants.zig");

/// Where the server's certificate chain and key come from.
pub const Identity = union(enum) {
    /// The chain and the key as PEM text the program holds. The program may wipe the key's text
    /// once `init` returns.
    pem: Pem,
    /// The names of the chain's file and the key's file, read at `init` (design §8 step 37e).
    files: Files,

    pub const Pem = struct {
        chain: []const u8,
        key: []const u8,
    };
    pub const Files = struct {
        chain: []const u8,
        key: []const u8,
    };
};

/// The memory an identity is read into. The `tls.Server` that `load` returns points into it, so
/// it stays in place while the server runs.
pub const Storage = struct {
    der: [constants.limits.chain_der_len_max]u8,
    certificates: [constants.limits.chain_certificates_max][]const u8,
    key: tls.Key,
    identities: [1]tls.Identity,
    cookie_key: [tls.constants.protocol.server_key_len]u8,
};

pub const LoadError = error{
    /// A PEM file `tls.pem` refuses: a chain longer than the server's rooms is one.
    IdentityInvalid,
    /// `.files`, which design §8 step 37e reads, is not built yet.
    FilesUnavailable,
};

/// Reads `identity` into `storage`, draws the cookie key from `random`, and returns the TLS values
/// of a server that runs on `cpu`.
pub fn load(identity: Identity, storage: *Storage, cpu: tls.Cpu, random: tls.Random) LoadError!tls.Server {
    const pem = switch (identity) {
        .pem => |pem| pem,
        .files => return error.FilesUnavailable,
    };
    const chain = tls.pem.chain(pem.chain, &storage.der, &storage.certificates) catch return error.IdentityInvalid;
    assert(chain.len > 0);
    tls.pem.key(cpu, pem.key, chain[0], &storage.key) catch return error.IdentityInvalid;
    storage.identities[0] = .{ .chain = chain, .key = &storage.key };
    // RFC 9846 §4.3.2: one cookie key for the server, drawn from the program's source.
    random.bytes(&storage.cookie_key);
    return .{ .identities = &storage.identities, .cookie_key = &storage.cookie_key, .cpu = cpu };
}

const testing = std.testing;

const support = @import("test_support.zig");

test "decision 150: a file that is not PEM is refused, and `.files` waits for 37e" {
    var storage: Storage = undefined;
    var counter: support.Counter = .{};
    try testing.expectError(error.IdentityInvalid, load(.{ .pem = .{ .chain = "not PEM", .key = "" } }, &storage, support.cpu(), counter.random()));
    try testing.expectError(error.FilesUnavailable, load(.{ .files = .{ .chain = "a", .key = "b" } }, &storage, support.cpu(), counter.random()));
}
