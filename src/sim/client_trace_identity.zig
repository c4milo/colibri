//! The identity the client trace run's servers present and the anchor its client trusts
//! (decision 105): `testdata/`, a copy of `src/client/testdata/`, which
//! `tools/h2_interop/tls_identity.go` minted at `now_seconds`. Every handshake of the run judges
//! the chain at that instant, so no run reads a clock (non-negotiable 3).
const tls = @import("tls");

pub const leaf = @embedFile("testdata/identity.leaf.der");
pub const root = @embedFile("testdata/identity.ca.der");
pub const root_name = @embedFile("testdata/identity.name");
pub const root_spki = @embedFile("testdata/identity.spki");
pub const private_key: *const [tls.constants.p256_private_key_len]u8 = @embedFile("testdata/identity.priv");
pub const public_key: *const [tls.constants.p256_public_key_len]u8 = @embedFile("testdata/identity.pub");

/// The instant the identity was minted, inside the 48 hours its certificates are valid for.
pub const now_seconds: u64 = 1_790_477_172;
/// The authority the certificate names, which every request of the run carries.
pub const authority = "localhost";

pub const chain = [_][]const u8{ leaf, root };
pub const anchors = [_]tls.Anchor{.{ .subject = root_name, .spki = root_spki }};
pub const cookie_key: [tls.constants.server_key_len]u8 = @splat(cookie_key_octet);
const cookie_key_octet: u8 = 0x07;
