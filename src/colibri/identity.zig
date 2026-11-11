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
    /// The key the server seals its session tickets under (decision 161).
    ticket_key: [tls.constants.protocol.server_key_len]u8,
};

pub const LoadError = error{
    /// PEM text `tls.pem` refuses: a chain longer than the server's rooms is one.
    IdentityInvalid,
};

/// Reads `identity` into `storage`, draws the cookie key from `random`, and returns the TLS values
/// of a server that runs on `cpu`. It copies `ticket_key`, or draws one after the cookie key when
/// it is null (decision 161).
pub fn load(identity: Identity, storage: *Storage, cpu: tls.Cpu, random: tls.Random, ticket_key: ?[tls.constants.protocol.server_key_len]u8) LoadError!tls.Server {
    const chain = tls.pem.chain(identity.chain, &storage.der, &storage.certificates) catch return error.IdentityInvalid;
    assert(chain.len > 0);
    tls.pem.key(cpu, identity.key, chain[0], &storage.key) catch return error.IdentityInvalid;
    storage.identities[0] = .{ .chain = chain, .key = &storage.key };
    // RFC 9846 §4.3.2: one cookie key for the server, drawn from the program's source.
    random.bytes(&storage.cookie_key);
    // RFC 9846 §4.7.1: the tickets are sealed under one key, which several servers of one program
    // share when the program passes it.
    if (ticket_key) |key| storage.ticket_key = key else random.bytes(&storage.ticket_key);
    return .{ .identities = &storage.identities, .cookie_key = &storage.cookie_key, .ticket_key = &storage.ticket_key, .cpu = cpu };
}

const testing = std.testing;

const support = @import("test_support.zig");
const testdata = @import("testdata");

test "decision 150: a chain or a key that is not PEM is refused" {
    var counter: support.Counter = .{};
    try testing.expectError(error.IdentityInvalid, load(.{ .chain = "not PEM", .key = testdata.key_pem }, &test_storage, support.cpu(), counter.random(), null));
    try testing.expectError(error.IdentityInvalid, load(.{ .chain = testdata.chain_pem, .key = "not a key" }, &test_storage, support.cpu(), counter.random(), null));
    // Neither refusal draws the cookie key.
    try testing.expectEqual(0, counter.next);
}

test "decision 150: the chain's own check refuses a chain that is not PEM" {
    var counter: support.Counter = .{};
    _ = try load(.{ .chain = testdata.chain_pem, .key = testdata.key_pem }, &test_storage, support.cpu(), counter.random(), null);
    defer test_storage.key.wipe();
    // The storage still holds the chain the key matches. So only the chain's check can refuse the
    // text, and the key's check cannot.
    try testing.expectError(error.IdentityInvalid, load(.{ .chain = "not PEM", .key = testdata.key_pem }, &test_storage, support.cpu(), counter.random(), null));
}

test "decision 161: the ticket key is the program's copy, or drawn after the cookie key" {
    const identity: Identity = .{ .chain = testdata.chain_pem, .key = testdata.key_pem };
    var counter: support.Counter = .{};
    const drawn = try load(identity, &test_storage, support.cpu(), counter.random(), null);
    defer test_storage.key.wipe();
    // The counter gives the cookie key 0 to 31, and then the ticket key 32 to 63.
    const key_len = tls.constants.protocol.server_key_len;
    try testing.expectEqual(key_len, drawn.ticket_key.?[0]);
    try testing.expectEqual(2 * key_len, counter.next);
    const given: [key_len]u8 = @splat(0xa5);
    const copied = try load(identity, &test_storage, support.cpu(), counter.random(), given);
    // The values point at the server's copy, not at the program's key, and nothing more is drawn.
    try testing.expectEqualSlices(u8, &given, copied.ticket_key.?);
    try testing.expect(copied.ticket_key.? == &test_storage.ticket_key);
    try testing.expectEqual(3 * key_len, counter.next);
}

/// The storage the tests place, outside any stack frame. Test-only.
threadlocal var test_storage: Storage align(@alignOf(Storage)) = undefined;
