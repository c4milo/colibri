//! A server's identity, read from PEM (RFC 7468) into memory the `Server` holds (decision 150):
//! the chain, its key, and the cookie key RFC 9846 §4.3.2 asks a server to hold.
const std = @import("std");
const assert = std.debug.assert;
const tls = @import("tls");
const rotor = @import("rotor");
const constants = @import("constants.zig");
const identity_files = @import("identity_files.zig");

/// Where the server's certificate chain and key come from.
pub const Identity = union(enum) {
    /// The chain and the key as PEM text the program holds. The program may wipe the key's text
    /// once `init` returns.
    pem: Pem,
    /// The names of the chain's file and the key's file, read at `init` into the server's memory
    /// (design §8 step 37e). Each file holds at most `constants.limits.pem_file_len_max` octets.
    /// Rotor opens each file to read and to write, so the program needs both permissions.
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
    /// The text of `.files`. The key's text is wiped before `init` returns.
    files: identity_files.Text,
};

pub const LoadError = identity_files.ReadError || error{
    /// A PEM file `tls.pem` refuses: a chain longer than the server's rooms is one.
    IdentityInvalid,
};

/// Reads `identity` into `storage`, draws the cookie key from `random`, and returns the TLS values
/// of a server that runs on `cpu`. `.files` is read on a loop in `loop_memory`.
pub fn load(
    identity: Identity,
    storage: *Storage,
    loop_memory: []align(rotor.memory_alignment) u8,
    cpu: tls.Cpu,
    random: tls.Random,
) LoadError!tls.Server {
    // The key's octets stay in the server's memory only until `tls.pem.key` has read them, also
    // when a read or a parse fails.
    defer if (identity == .files) std.crypto.secureZero(u8, &storage.files.key);
    const pem = switch (identity) {
        .pem => |pem| pem,
        .files => |names| try identity_files.read(names, &storage.files, loop_memory),
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
const testdata = @import("testdata");

test "decision 150: a file that is not PEM is refused" {
    var counter: support.Counter = .{};
    try testing.expectError(error.IdentityInvalid, load(.{ .pem = .{ .chain = "not PEM", .key = "" } }, &test_storage, &test_loop_memory, support.cpu(), counter.random()));
}

test "design §8 step 37e: the key's text is wiped when a file is refused" {
    var directory: support.TestDirectory = .init();
    defer directory.deinit();
    var counter: support.Counter = .{};
    const chain = try directory.write(.chain, testdata.chain_pem);
    // `tls.pem.key` refuses the key after the read put its text in `files.key`.
    const key = try directory.write(.key, "not a key");
    try testing.expectError(error.IdentityInvalid, load(.{ .files = .{ .chain = chain, .key = key } }, &test_storage, &test_loop_memory, support.cpu(), counter.random()));
    try testing.expect(std.mem.allEqual(u8, &test_storage.files.key, 0));
    // `tls.pem.chain` refuses the chain, and the key's text is wiped before `tls.pem.key` reads it.
    const not_chain = try directory.write(.chain, "not PEM");
    const valid_key = try directory.write(.key, testdata.key_pem);
    try testing.expectError(error.IdentityInvalid, load(.{ .files = .{ .chain = not_chain, .key = valid_key } }, &test_storage, &test_loop_memory, support.cpu(), counter.random()));
    try testing.expect(std.mem.allEqual(u8, &test_storage.files.key, 0));
}

/// The storage and the loop memory the tests place, outside any stack frame. Test-only.
threadlocal var test_storage: Storage align(@alignOf(Storage)) = undefined;
threadlocal var test_loop_memory: [identity_files.loop_memory_bytes]u8 align(rotor.memory_alignment) = undefined;
