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

comptime {
    assert(not_before_seconds <= now_seconds and now_seconds <= not_after_seconds);
}
