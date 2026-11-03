//! The TLS identity the tests of `tls`, `tls_keylog`, `server` and `client` read, and the client
//! trace run of `sim_run`: a CA and a leaf for `localhost`, both valid from 2026-01-01 to
//! 2126-01-01, and the leaf's key pair. openssl made it once, by the commands in README.md, and
//! nothing mints it again. One copy serves every module (the owner's ruling of 2026-09-28).
//! `@embedFile` reads only inside the directory of the module that calls it, so the identity is a
//! module of its own.
//!
//! Test-only. No packaged module imports it: the tests of `tls`, `server` and `client` compile from
//! roots of their own that do (build/modules_test_roots.zig), so a project that depends on colibri
//! never reaches this key.
const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;

/// The leaf, for `localhost` and 127.0.0.1, and the root: the CA's own certificate, which signed
/// the leaf. Both are DER.
pub const leaf = @embedFile("identity.leaf.der");
pub const root = @embedFile("identity.ca.der");
/// The CA's Subject Name and SubjectPublicKeyInfo, as DER: what a client's anchor holds.
pub const root_name = @embedFile("identity.name");
pub const root_spki = @embedFile("identity.spki");
/// The leaf's P-256 key pair as chapulin reads it: the 32-octet private scalar, and the
/// uncompressed point X||Y without its 0x04 prefix.
pub const private_key = @embedFile("identity.priv");
pub const public_key = @embedFile("identity.pub");
/// The same identity as the PEM files an operator holds (RFC 7468): the chain, the leaf first; the
/// leaf's key as PKCS #8 (RFC 5958) and as SEC 1 (RFC 5915); and a CA bundle of the root, with
/// the title lines a curl-style bundle carries.
pub const chain_pem = @embedFile("identity.chain.pem");
pub const key_pem = @embedFile("identity.key.pem");
pub const key_sec1_pem = @embedFile("identity.key.sec1.pem");
pub const bundle_pem = @embedFile("identity.bundle.pem");
/// An ML-DSA-87 identity for `localhost` and 127.0.0.1 under a CA of its own, as PEM: the chain,
/// the leaf first, and the leaf's key as PKCS #8 in RFC 9881 §6's both form (decision 147).
pub const mldsa87_chain_pem = @embedFile("identity.mldsa87.chain.pem");
pub const mldsa87_key_pem = @embedFile("identity.mldsa87.key.pem");
/// An RSA-3072 identity for `localhost` and 127.0.0.1 under an RSA CA of its own, as PEM: the chain,
/// the leaf first, and the leaf's key as PKCS #8 (RFC 5958), which `rsa_pss_rsae_sha256` signs
/// with (decision 147).
pub const rsa_chain_pem = @embedFile("identity.rsa.chain.pem");
pub const rsa_key_pem = @embedFile("identity.rsa.key.pem");

/// The first and the last instant both certificates are valid at, in Unix seconds: their
/// notBefore, 2026-01-01T00:00:00Z, and their notAfter, 2126-01-01T00:00:00Z. chapulin counts both
/// ends inside the validity.
pub const not_before_seconds: u64 = 1_767_225_600;
pub const not_after_seconds: u64 = 4_922_899_200;

/// The instant a test judges the chain at when any instant would do: 2026-09-28T00:00:00Z. Any
/// instant from `not_before_seconds` to `not_after_seconds` works.
pub const now_seconds: u64 = 1_790_553_600;

/// Whether the build target has the AES instructions and the carry-less multiply: aes and pclmul
/// on x86-64, and aes on arm64, whose AES extension holds the 64-bit PMULL. The TLS tests give
/// colibri's values it as the probe's `aes_clmul` (decision 97 as amended on 2026-09-30), because a
/// test runs on the machine it was built for. A program probes the CPU it runs on instead.
pub const aes_instructions_present: bool = switch (builtin.cpu.arch) {
    .x86_64 => std.Target.x86.featureSetHasAll(builtin.cpu.features, .{ .aes, .pclmul }),
    .aarch64 => std.Target.aarch64.featureSetHas(builtin.cpu.features, .aes),
    else => false,
};

/// Whether the build target has the SHA-256, SHA-512 and SHA-3 instructions: arm64's sha2 and sha3
/// features, the second of which holds FEAT_SHA512 and FEAT_SHA3. The TLS tests give it as the
/// probe's `sha256`, `sha512` and `sha3`, as they give the AES answer. colibri states the SHA
/// instructions on arm64 alone, so every other target answers no.
pub const sha_instructions_present: bool = switch (builtin.cpu.arch) {
    .aarch64 => std.Target.aarch64.featureSetHasAll(builtin.cpu.features, .{ .sha2, .sha3 }),
    else => false,
};

comptime {
    assert(not_before_seconds <= now_seconds and now_seconds <= not_after_seconds);
}
