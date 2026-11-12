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
    ticket_key: TicketKey,
    /// The key the server sealed its tickets under before `ticket_key`, which still opens them
    /// (decision 161 as amended, https://github.com/c4milo/chapulin/issues/220).
    ticket_key_previous: TicketKey,
};

/// A session ticket key.
pub const TicketKey = [tls.constants.protocol.server_key_len]u8;

/// The ticket keys a program gives a server, each copied, or null to draw it.
pub const TicketKeys = struct {
    current: ?TicketKey = null,
    previous: ?TicketKey = null,
};

pub const LoadError = error{
    /// PEM text `tls.pem` refuses: a chain longer than the server's rooms is one.
    IdentityInvalid,
};

/// Reads `identity` into `storage`, draws the cookie key from `random`, and returns the TLS values
/// of a server that runs on `cpu`. It copies each ticket key of `keys`, or draws it when it is
/// null: the cookie key first, then the ticket key, then the previous key (decision 161).
pub fn load(identity: Identity, storage: *Storage, cpu: tls.Cpu, random: tls.Random, keys: TicketKeys) LoadError!tls.Server {
    const chain = tls.pem.chain(identity.chain, &storage.der, &storage.certificates) catch return error.IdentityInvalid;
    assert(chain.len > 0);
    tls.pem.key(cpu, identity.key, chain[0], &storage.key) catch return error.IdentityInvalid;
    storage.identities[0] = .{ .chain = chain, .key = &storage.key };
    // RFC 9846 §4.3.2: one cookie key for the server, drawn from the program's source.
    random.bytes(&storage.cookie_key);
    // RFC 9846 §4.7.1: the tickets are sealed under one key, which several servers of one program
    // share when the program passes it.
    if (keys.current) |key| storage.ticket_key = key else random.bytes(&storage.ticket_key);
    // chapulin reads both keys through pointers it keeps from each session's start, so the
    // previous key is set from the start, and `change_ticket_key` writes new bytes in place
    // (https://github.com/c4milo/chapulin/issues/220). A drawn key sealed no ticket, so it opens
    // none.
    if (keys.previous) |key| storage.ticket_key_previous = key else random.bytes(&storage.ticket_key_previous);
    return .{
        .identities = &storage.identities,
        .cookie_key = &storage.cookie_key,
        .ticket_key = &storage.ticket_key,
        .ticket_key_previous = &storage.ticket_key_previous,
        .cpu = cpu,
    };
}

/// Seals new tickets under `key` from the next session call, and keeps the current key to open
/// the tickets it sealed. It writes both keys in place, because each session reads them through
/// the pointers `load` gave (https://github.com/c4milo/chapulin/issues/220). A key equal to the
/// current one changes nothing.
pub fn change_ticket_key(storage: *Storage, key: *const TicketKey) void {
    // A key of zero octets is a program's error, which chapulin refuses at a session's start too.
    assert(!std.mem.allEqual(u8, key, 0));
    if (std.mem.eql(u8, key, &storage.ticket_key)) return;
    storage.ticket_key_previous = storage.ticket_key;
    storage.ticket_key = key.*;
    assert(!std.mem.eql(u8, &storage.ticket_key, &storage.ticket_key_previous));
}

const testing = std.testing;

const support = @import("test_support.zig");
const testdata = @import("testdata");

test "decision 150: a chain or a key that is not PEM is refused" {
    var counter: support.Counter = .{};
    try testing.expectError(error.IdentityInvalid, load(.{ .chain = "not PEM", .key = testdata.key_pem }, &test_storage, support.cpu(), counter.random(), .{}));
    try testing.expectError(error.IdentityInvalid, load(.{ .chain = testdata.chain_pem, .key = "not a key" }, &test_storage, support.cpu(), counter.random(), .{}));
    // Neither refusal draws the cookie key.
    try testing.expectEqual(0, counter.next);
}

test "decision 150: the chain's own check refuses a chain that is not PEM" {
    var counter: support.Counter = .{};
    _ = try load(.{ .chain = testdata.chain_pem, .key = testdata.key_pem }, &test_storage, support.cpu(), counter.random(), .{});
    defer test_storage.key.wipe();
    // The storage still holds the chain the key matches. So only the chain's check can refuse the
    // text, and the key's check cannot.
    try testing.expectError(error.IdentityInvalid, load(.{ .chain = "not PEM", .key = testdata.key_pem }, &test_storage, support.cpu(), counter.random(), .{}));
}

test "decision 161: each ticket key is the program's copy, or drawn after the cookie key" {
    const identity: Identity = .{ .chain = testdata.chain_pem, .key = testdata.key_pem };
    var counter: support.Counter = .{};
    const drawn = try load(identity, &test_storage, support.cpu(), counter.random(), .{});
    defer test_storage.key.wipe();
    // The counter gives the cookie key 0 to 31, the ticket key 32 to 63, and the previous key 64
    // to 95.
    const key_len = tls.constants.protocol.server_key_len;
    try testing.expectEqual(key_len, drawn.ticket_key.?[0]);
    try testing.expectEqual(2 * key_len, drawn.ticket_key_previous.?[0]);
    try testing.expectEqual(3 * key_len, counter.next);
    const given: TicketKey = @splat(0xa5);
    const before: TicketKey = @splat(0x5a);
    const copied = try load(identity, &test_storage, support.cpu(), counter.random(), .{ .current = given, .previous = before });
    // The values point at the server's copies, not at the program's keys, and only the cookie key
    // is drawn.
    try testing.expectEqualSlices(u8, &given, copied.ticket_key.?);
    try testing.expectEqualSlices(u8, &before, copied.ticket_key_previous.?);
    try testing.expect(copied.ticket_key.? == &test_storage.ticket_key);
    try testing.expect(copied.ticket_key_previous.? == &test_storage.ticket_key_previous);
    try testing.expectEqual(4 * key_len, counter.next);
}

test "chapulin's issue 220: a key change keeps the current key as the previous one, in place" {
    const identity: Identity = .{ .chain = testdata.chain_pem, .key = testdata.key_pem };
    var counter: support.Counter = .{};
    const first: TicketKey = @splat(0x11);
    const values = try load(identity, &test_storage, support.cpu(), counter.random(), .{ .current = first });
    defer test_storage.key.wipe();
    const second: TicketKey = @splat(0x22);
    change_ticket_key(&test_storage, &second);
    // The pointers a session keeps from its start now read the new bytes.
    try testing.expectEqualSlices(u8, &second, values.ticket_key.?);
    try testing.expectEqualSlices(u8, &first, values.ticket_key_previous.?);
    // A second change leaves no octet of the first key, and the same key again changes nothing.
    const third: TicketKey = @splat(0x33);
    change_ticket_key(&test_storage, &third);
    change_ticket_key(&test_storage, &third);
    try testing.expectEqualSlices(u8, &third, values.ticket_key.?);
    try testing.expectEqualSlices(u8, &second, values.ticket_key_previous.?);
}

/// The storage the tests place, outside any stack frame. Test-only.
threadlocal var test_storage: Storage align(@alignOf(Storage)) = undefined;
