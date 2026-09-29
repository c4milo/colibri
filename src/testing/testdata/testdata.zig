//! The TLS identity the tests of `tls`, `tls_keylog`, `server` and `client` read, and the client
//! trace run of `sim_run`: a root and a leaf for `localhost`, which
//! `tools/h2_interop/tls_identity.go` minted at `now_seconds`, and the leaf's key pair. One copy
//! serves every module (the owner's ruling of 2026-09-28). `@embedFile` reads only inside the
//! directory of the module that calls it, so the identity is a module of its own.
//!
//! Test-only. No packaged module imports it: the tests of `tls`, `server` and `client` compile from
//! roots of their own that do (build/modules_test_roots.zig), so a project that depends on colibri
//! never reaches this key.

/// The leaf, for `localhost` and 127.0.0.1, and the root that signed it, as DER.
pub const leaf = @embedFile("identity.leaf.der");
pub const root = @embedFile("identity.ca.der");
/// The root's Subject Name and SubjectPublicKeyInfo, as DER: what a client's anchor holds.
pub const root_name = @embedFile("identity.name");
pub const root_spki = @embedFile("identity.spki");
/// The leaf's P-256 key pair as chapulin reads it: the 32-octet private scalar, and the
/// uncompressed point X||Y without its 0x04 prefix.
pub const private_key = @embedFile("identity.priv");
pub const public_key = @embedFile("identity.pub");

/// The instant the identity was minted, inside the 48 hours its certificates are valid for.
pub const now_seconds: u64 = 1_790_477_172;
