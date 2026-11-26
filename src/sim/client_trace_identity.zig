//! The identity the client trace run's servers present and the anchor its client trusts
//! (decision 105), which the TCP trace run's server and client use too
//! (https://github.com/c4milo/colibri/issues/79): the test identity of `src/testing/testdata/`.
//! Every handshake of either run judges the chain at `now_seconds`, so no run reads a clock
//! (non-negotiable 3).
const std = @import("std");
const builtin = @import("builtin");
const tls = @import("tls");
const stdx = @import("stdx");
const testdata = @import("testdata");

pub const leaf = testdata.leaf;
pub const root = testdata.root;
pub const root_name = testdata.root_name;
pub const root_spki = testdata.root_spki;
pub const private_key: *const [tls.constants.protocol.p256_private_key_len]u8 = testdata.private_key;
pub const public_key: *const [tls.constants.protocol.p256_public_key_len]u8 = testdata.public_key;

/// The test identity's key, as `tls.pem.key` fills it from `identity.key.pem` (decision 147).
pub const key: tls.Key = p256_key: {
    var filled: tls.Key = .{ .scheme = .ecdsa_secp256r1_sha256 };
    @memcpy(filled.private_key[0..private_key.len], private_key);
    @memcpy(filled.public_key[0..public_key.len], public_key);
    break :p256_key filled;
};

/// The instant every handshake of the run judges the chain at. Any instant inside the identity's
/// validity works, from `testdata.not_before_seconds` to `testdata.not_after_seconds`.
pub const now_seconds: u64 = testdata.now_seconds;
/// The type of a context's random source, `stdx.crypto.Context.random`, which each side of a run
/// builds over its own SplitMix64 stream.
pub const RandomSource = @FieldType(stdx.crypto.Context, "random");

/// The context of one side of a run, whose draws come from `random` (decision 175): the CPU
/// features the host reports, as a program detects them. On arm64 it first sets the thread's
/// PSTATE.DIT where the core has FEAT_DIT, as a program does on each thread that runs TLS, so
/// stdx states the timing there as it does on every x86-64 core.
pub fn crypto(random: RandomSource) stdx.crypto.Context {
    const features: stdx.platform.CpuFeatures = .detect();
    _ = stdx.platform.set_data_independent_timing(features, true);
    return stdx.crypto.init(features, random);
}

/// The cipher suite every session of a run holds on this host. Each suite puts other octets on the
/// wire, so a census pins one wire checksum for each, and one seed replays octet for octet on
/// every host that holds the same suite (decision 175 as the owner ruled on 2026-11-26).
pub const Suite = enum { aes_gcm, chacha20 };

/// AES-GCM where stdx's description of the CPU claims the AES instructions, and ChaCha20
/// otherwise, by stdx's rule (its decision 87 as amended): the timing stated, on every x86-64 core
/// and on an arm64 thread whose PSTATE.DIT is set, and the features holding AES and the
/// carry-less multiply. A virtual machine that hides FEAT_DIT holds ChaCha20. The `tls` tests
/// read the same rule (`record_test_support.aes_claimed`).
pub fn suite() Suite {
    const features: stdx.platform.CpuFeatures = .detect();
    _ = stdx.platform.set_data_independent_timing(features, true);
    return suite_of(features, builtin.cpu.arch);
}

/// `suite`'s rule for `features` on `arch`. `arch` is the target's, and a test passes another one,
/// whose thread it reads only where the features hold FEAT_DIT.
fn suite_of(features: stdx.platform.CpuFeatures, arch: std.Target.Cpu.Arch) Suite {
    const claimed = switch (arch) {
        .x86_64 => features.aes and features.pclmul,
        .aarch64 => features.dit and stdx.platform.data_independent_timing(features) and features.aes and features.pmull,
        else => false,
    };
    return if (claimed) .aes_gcm else .chacha20;
}

test "decision 175: a host holds AES-GCM only where stdx claims the AES instructions" {
    try std.testing.expectEqual(Suite.aes_gcm, suite_of(.{ .aes = true, .pclmul = true }, .x86_64));
    // AES-GCM runs the carry-less multiply beside AES's rounds.
    try std.testing.expectEqual(Suite.chacha20, suite_of(.{ .aes = true }, .x86_64));
    try std.testing.expectEqual(Suite.chacha20, suite_of(.none(), .x86_64));
    // An arm64 virtual machine that hides FEAT_DIT: stdx states no timing there.
    try std.testing.expectEqual(Suite.chacha20, suite_of(.{ .aes = true, .pmull = true }, .aarch64));
    try std.testing.expectEqual(Suite.chacha20, suite_of(.{ .aes = true, .pclmul = true }, .riscv64));
}
/// The authority the certificate names, which every request of the run carries.
pub const authority = "localhost";

pub const chain = [_][]const u8{ leaf, root };
/// The test identity as a server holds it: the chain and its key.
pub const identities = [_]tls.Identity{.{ .chain = &chain, .key = &key }};
pub const anchors = [_]tls.Anchor{.{ .subject = root_name, .spki = root_spki }};
pub const cookie_key: [tls.constants.protocol.server_key_len]u8 = @splat(cookie_key_octet);
const cookie_key_octet: u8 = 0x07;
