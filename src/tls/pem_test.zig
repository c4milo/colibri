//! The tests of the PEM reader (`pem.zig`): the test identity of `src/testing/testdata/` as an
//! operator holds it, read into the values a server and a client take, and the files refused.
const std = @import("std");
const testdata = @import("testdata");
const pem = @import("pem.zig");
const values = @import("values.zig");
const constants = @import("constants.zig");
const support = @import("record/record_test_support.zig");

const testing = std.testing;

/// The rooms the reads fill, outside any stack frame: each holds the test identity's files with
/// room to spare. Test-only.
var der: [der_len]u8 = undefined;
var certificates: [constants.limits.certificate_chain_len_max][]const u8 = undefined;
var anchors: [anchors_len]values.Anchor align(@alignOf(values.Anchor)) = undefined;
const der_len: usize = 4096;
const anchors_len: usize = 4;
/// The certificates of the test chain: the leaf and the CA. Test-only.
const chain_len: usize = 2;

test "issue 97: a chain reads into the DER a server's identity takes, the end-entity first" {
    const chain = try pem.chain(testdata.chain_pem, &der, &certificates);
    try testing.expectEqual(chain_len, chain.len);
    try testing.expectEqualSlices(u8, testdata.leaf, chain[0]);
    try testing.expectEqualSlices(u8, testdata.root, chain[1]);
}

test "issue 97: a chain that passes either room, or a file of another label, is refused" {
    try testing.expectError(error.Invalid, pem.chain(testdata.chain_pem, &der, certificates[0 .. chain_len - 1]));
    try testing.expectError(error.Invalid, pem.chain(testdata.chain_pem, der[0 .. testdata.leaf.len + testdata.root.len - 1], &certificates));
    try testing.expectError(error.Invalid, pem.chain(testdata.key_pem, &der, &certificates));
}

/// A chain longer than colibri's limit, the test chain nine times, and a DER room that holds it.
/// Test-only.
const long_chain = testdata.chain_pem ** long_repeats;
const long_repeats: usize = 9;
var long_der: [long_der_len]u8 = undefined;
var long_room: [long_room_len][]const u8 = undefined;
const long_der_len: usize = 16384;
const long_room_len: usize = 20;

test "issue 97: a chain past certificate_chain_len_max is refused, whatever room it is given" {
    comptime std.debug.assert(chain_len * long_repeats > constants.limits.certificate_chain_len_max);
    comptime std.debug.assert(long_room_len >= chain_len * long_repeats);
    try testing.expectError(error.Invalid, pem.chain(long_chain, &long_der, &long_room));
}

/// The test identity's files with the text a tool writes around a block (RFC 7468 §5.2), and a
/// key file with a certificate after its key. Test-only.
const explained_chain = "Subject: CN=localhost\nIssuer: CN=colibri test CA\n" ++ testdata.chain_pem ++ "end of chain\n";
const explained_key = "the leaf's key\n" ++ testdata.key_pem;
const explained_sec1 = "the leaf's key, SEC 1\n" ++ testdata.key_sec1_pem ++ "\n";
const key_and_certificate = testdata.key_pem ++ testdata.chain_pem;

test "RFC 7468 §2: the text lines around a chain's or a key's blocks are skipped" {
    const chain = try pem.chain(explained_chain, &der, &certificates);
    try testing.expectEqual(chain_len, chain.len);
    try testing.expectEqualSlices(u8, testdata.leaf, chain[0]);
    for ([_][]const u8{ explained_key, explained_sec1 }) |file| {
        var key: values.Key = .{};
        defer key.wipe();
        try pem.key(support.cpu, file, testdata.leaf, &key);
        try testing.expectEqualSlices(u8, testdata.public_key, key.public_key[0..testdata.public_key.len]);
        try testing.expectEqual(.ecdsa_secp256r1_sha256, key.scheme.?);
    }
    // A block of another label still refuses a key file.
    var refused: values.Key = .{};
    try testing.expectError(error.Invalid, pem.key(support.cpu, key_and_certificate, testdata.leaf, &refused));
}

test "RFC 5958 and RFC 5915: a key under either label reads into the test identity's key pair" {
    for ([_][]const u8{ testdata.key_pem, testdata.key_sec1_pem }) |file| {
        var key: values.Key = .{};
        defer key.wipe();
        try pem.key(support.cpu, file, testdata.leaf, &key);
        try testing.expectEqualSlices(u8, testdata.private_key, key.private_key[0..testdata.private_key.len]);
        try testing.expectEqualSlices(u8, testdata.public_key, key.public_key[0..testdata.public_key.len]);
        try testing.expectEqual(.ecdsa_secp256r1_sha256, key.scheme.?);
        key.wipe();
        try testing.expectEqualSlices(u8, &@as([constants.protocol.mldsa87_private_key_len]u8, @splat(0)), &key.private_key);
    }
}

test "RFC 9846 §4.5.2: a key the leaf does not carry, or a file that holds none, is refused" {
    var key: values.Key = .{};
    try testing.expectError(error.Invalid, pem.key(support.cpu, testdata.key_pem, testdata.root, &key));
    try testing.expectError(error.Invalid, pem.key(support.cpu, testdata.chain_pem, testdata.leaf, &key));
    // A refused key leaves nothing of itself in the caller's key, and no scheme.
    try testing.expectEqualSlices(u8, &@as([constants.protocol.mldsa87_private_key_len]u8, @splat(0)), &key.private_key);
    try testing.expectEqual(null, key.scheme);
}

test "RFC 9846 §4.5.1.3: a CA bundle reads into anchors, past the title lines around its blocks" {
    const read = try pem.anchors(testdata.bundle_pem, &der, &anchors);
    try testing.expectEqual(1, read.len);
    try testing.expectEqualSlices(u8, testdata.root_name, read[0].subject);
    try testing.expectEqualSlices(u8, testdata.root_spki, read[0].spki);
    // A chain is a bundle too: each certificate gives its anchor, in order.
    try testing.expectEqual(chain_len, (try pem.anchors(testdata.chain_pem, &der, &anchors)).len);
    // A room of one anchor holds no bundle of two, and a key's label refuses the file.
    try testing.expectError(error.Invalid, pem.anchors(testdata.chain_pem, &der, anchors[0 .. chain_len - 1]));
    try testing.expectError(error.Invalid, pem.anchors(testdata.key_pem, &der, &anchors));
}

/// The DER room of the client's anchors, apart from the server's chain, which both stay in use
/// for the handshake. Test-only.
var anchor_der: [der_len]u8 = undefined;

test "issue 97: a server read from its PEM files and a client read from its bundle complete a handshake" {
    const chain = try pem.chain(testdata.chain_pem, &der, &certificates);
    var key: values.Key = .{};
    defer key.wipe();
    try pem.key(support.cpu, testdata.key_pem, chain[0], &key);
    const trusted = try pem.anchors(testdata.bundle_pem, &anchor_der, &anchors);
    var client_values = support.web_pki;
    client_values.trust = .{ .web_pki = .{ .anchors = trusted, .server_name = "localhost" } };
    try support.client_config.init(client_values);
    try support.server_config.init(.{
        .identities = &.{.{ .chain = chain, .key = &key }},
        .cookie_key = &support.cookie_key,
        .alpn = &support.protocols,
        .cpu = support.cpu,
    });
    try support.server_config.check(support.random());
    try support.handshake_both(null);
    try testing.expect(support.client.provider().is_complete());
}

/// The DER room of the ML-DSA-87 chain: two certificates of about 7,500 octets each. Test-only.
const mldsa87_der_len: usize = constants.limits.certificate_chain_len_max * der_len;
var mldsa87_der: [mldsa87_der_len]u8 = undefined;
var mldsa87_certificates: [chain_len][]const u8 = undefined;

test "decision 147: an ML-DSA-87 key reads with its scheme, and a leaf that does not carry it refuses" {
    const chain = try pem.chain(testdata.mldsa87_chain_pem, &mldsa87_der, &mldsa87_certificates);
    var key: values.Key = .{};
    defer key.wipe();
    try pem.key(support.cpu, testdata.mldsa87_key_pem, chain[0], &key);
    try testing.expectEqual(.mldsa87, key.scheme.?);
    // RFC 9881 §4: the leaf's subjectPublicKey is the ML-DSA-87 public key itself.
    try testing.expect(std.mem.indexOf(u8, chain[0], &key.public_key) != null);
    // RFC 9846 §4.5.2: the P-256 leaf carries another key, so the file is refused.
    var refused: values.Key = .{};
    try testing.expectError(error.Invalid, pem.key(support.cpu, testdata.mldsa87_key_pem, testdata.leaf, &refused));
    try testing.expectEqual(null, refused.scheme);
}

test "decision 147: a server holds one identity for each scheme, and chapulin's check signs with both" {
    const chain = try pem.chain(testdata.mldsa87_chain_pem, &mldsa87_der, &mldsa87_certificates);
    var key: values.Key = .{};
    defer key.wipe();
    try pem.key(support.cpu, testdata.mldsa87_key_pem, chain[0], &key);
    try support.configure(support.web_pki, .{});
    const both = [_]values.Identity{ support.identities[0], .{ .chain = chain, .key = &key } };
    try support.server_config.init(.{ .identities = &both, .cookie_key = &support.cookie_key, .alpn = &support.protocols, .cpu = support.cpu });
    // Each identity fills chapulin's slot of its scheme, which a program never reads.
    try testing.expect(support.server_config.values.ecdsa_p256 != null);
    try testing.expectEqual(&key.private_key, support.server_config.values.mldsa87.?.private_key);
    try support.server_config.check(support.random());
    // colibri's client offers no ML-DSA-87, so the handshake signs with the P-256 key.
    try support.handshake_both(null);
    try testing.expect(support.client.provider().is_complete());
    // Two of one scheme, and a key no call filled, are each refused.
    const twice = [_]values.Identity{ support.identities[0], support.identities[0] };
    try testing.expectError(error.IdentityRepeated, support.server_config.init(.{ .identities = &twice, .cookie_key = &support.cookie_key, .cpu = support.cpu }));
    const twice_mldsa87 = [_]values.Identity{ both[1], both[1] };
    try testing.expectError(error.IdentityRepeated, support.server_config.init(.{ .identities = &twice_mldsa87, .cookie_key = &support.cookie_key, .cpu = support.cpu }));
    const unfilled: values.Key = .{};
    try testing.expectError(error.IdentityUnfilled, support.server_config.init(.{ .identities = &.{.{ .chain = chain, .key = &unfilled }}, .cookie_key = &support.cookie_key, .cpu = support.cpu }));
}
