//! A server's identity, read from PEM (RFC 7468) into memory the `Server` holds (decision 150):
//! the chain, its key, and the cookie key RFC 9846 §4.3.2 asks a server to hold.
const std = @import("std");
const assert = std.debug.assert;
const tls = @import("tls");
const constants = @import("constants.zig");

/// The server's certificate chain and key, as PEM text the program holds (decision 150 ruling 11).
/// The program reads its own files. `init` reads the key's text in place and keeps no copy, so
/// the program may wipe the text once `init` returns.
pub const Identity = struct {
    chain: []const u8,
    key: []const u8,
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
    /// PEM text `tls.pem` refuses: a chain longer than the server's rooms is one.
    IdentityInvalid,
};

/// Reads `identity` into `storage`, draws the cookie key from `random`, and returns the TLS values
/// of a server that runs on `cpu`.
pub fn load(identity: Identity, storage: *Storage, cpu: tls.Cpu, random: tls.Random) LoadError!tls.Server {
    const chain = tls.pem.chain(identity.chain, &storage.der, &storage.certificates) catch return error.IdentityInvalid;
    assert(chain.len > 0);
    tls.pem.key(cpu, identity.key, chain[0], &storage.key) catch return error.IdentityInvalid;
    storage.identities[0] = .{ .chain = chain, .key = &storage.key };
    // RFC 9846 §4.3.2: one cookie key for the server, drawn from the program's source.
    random.bytes(&storage.cookie_key);
    return .{ .identities = &storage.identities, .cookie_key = &storage.cookie_key, .cpu = cpu };
}

const testing = std.testing;

const support = @import("test_support.zig");
const testdata = @import("testdata");

test "decision 150: a chain or a key that is not PEM is refused" {
    var counter: support.Counter = .{};
    try testing.expectError(error.IdentityInvalid, load(.{ .chain = "not PEM", .key = testdata.key_pem }, &test_storage, support.cpu(), counter.random()));
    try testing.expectError(error.IdentityInvalid, load(.{ .chain = testdata.chain_pem, .key = "not a key" }, &test_storage, support.cpu(), counter.random()));
    // Neither refusal draws the cookie key.
    try testing.expectEqual(0, counter.next);
}

/// The storage the tests place, outside any stack frame. Test-only.
threadlocal var test_storage: Storage align(@alignOf(Storage)) = undefined;
