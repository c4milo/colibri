//! The identity the client trace run's servers present and the anchor its client trusts
//! (decision 105), which the TCP trace run's server and client use too
//! (https://github.com/c4milo/colibri/issues/79): the test identity of `src/testing/testdata/`.
//! Every handshake of either run judges the chain at `now_seconds`, so no run reads a clock
//! (non-negotiable 3).
const tls = @import("tls");
const testdata = @import("testdata");

pub const leaf = testdata.leaf;
pub const root = testdata.root;
pub const root_name = testdata.root_name;
pub const root_spki = testdata.root_spki;
pub const private_key: *const [tls.constants.p256_private_key_len]u8 = testdata.private_key;
pub const public_key: *const [tls.constants.p256_public_key_len]u8 = testdata.public_key;

/// The instant every handshake of the run judges the chain at. Any instant inside the identity's
/// validity works, from `testdata.not_before_seconds` to `testdata.not_after_seconds`.
pub const now_seconds: u64 = testdata.now_seconds;
/// The CPU the run describes: the build target's probe, as the tests pass it, and the thread's mode
/// stated, so a host runs the suites a program that states it runs (decision 97 as amended).
pub const cpu: tls.Cpu = .{
    .probe = .{ .aes_clmul = if (testdata.aes_instructions_present) .yes else .no, .dit = .not_known },
    .timing = .data_independent,
};
/// The authority the certificate names, which every request of the run carries.
pub const authority = "localhost";

pub const chain = [_][]const u8{ leaf, root };
pub const anchors = [_]tls.Anchor{.{ .subject = root_name, .spki = root_spki }};
pub const cookie_key: [tls.constants.server_key_len]u8 = @splat(cookie_key_octet);
const cookie_key_octet: u8 = 0x07;
