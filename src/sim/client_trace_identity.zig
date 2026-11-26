//! The identity the client trace run's servers present and the anchor its client trusts
//! (decision 105), which the TCP trace run's server and client use too
//! (https://github.com/c4milo/colibri/issues/79): the test identity of `src/testing/testdata/`.
//! Every handshake of either run judges the chain at `now_seconds`, so no run reads a clock
//! (non-negotiable 3).
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

/// The context of one side of a run, whose draws come from `random` (decision 175): the build
/// target's CPU features, as the tests pass them, so a host runs the suites a program runs. On
/// arm64 it first sets the thread's PSTATE.DIT where the core has FEAT_DIT, as a program does on
/// each thread that runs TLS, so stdx states the timing there as it does on every x86-64 core.
pub fn crypto(random: RandomSource) stdx.crypto.Context {
    _ = stdx.platform.set_data_independent_timing(stdx.platform.CpuFeatures.detect(), true);
    return stdx.crypto.init(.target(), random);
}
/// The authority the certificate names, which every request of the run carries.
pub const authority = "localhost";

pub const chain = [_][]const u8{ leaf, root };
/// The test identity as a server holds it: the chain and its key.
pub const identities = [_]tls.Identity{.{ .chain = &chain, .key = &key }};
pub const anchors = [_]tls.Anchor{.{ .subject = root_name, .spki = root_spki }};
pub const cookie_key: [tls.constants.protocol.server_key_len]u8 = @splat(cookie_key_octet);
const cookie_key_octet: u8 = 0x07;
