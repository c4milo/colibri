//! DNSSEC's signature checks (decision 142, design §8 step 31): which algorithms and digest types
//! colibri checks, a hash of signed data or a plain digest fed in pieces, and the check of a
//! signature under a DNSKEY's key. chapulin does the cryptography, in the TCP object `tls` links,
//! so a program that links both links one object. Nothing allocates, reads a clock or does I/O.
//!
//! This root is the module's API file (decision 115). It exports the names code outside the
//! module uses: a type under its own name, a function or a constant under the namespace of its
//! file, and no file but `constants`.
const std = @import("std");

pub const constants = @import("constants.zig");

/// Every file of the module. None of these is exported: the names below are.
const files = struct {
    pub const algorithm = @import("algorithm.zig");
    pub const digest_type = @import("digest_type.zig");
    pub const hash = @import("hash.zig");
    pub const verify = @import("verify.zig");
};

pub const Algorithm = files.algorithm.Algorithm;
pub const DigestType = files.digest_type.DigestType;
pub const Hash = files.hash.Hash;
pub const Error = files.hash.Error;

pub const algorithm = files.algorithm.algorithm;
pub const digest_type = files.digest_type.digest_type;
pub const verify = files.verify.verify;

test "decision 115: the root exports the names code outside the module uses" {
    const public_names = @import("core").public_names;
    try public_names.expect(@This(), &.{
        "constants", "Algorithm",   "DigestType", "Hash", "Error",
        "algorithm", "digest_type", "verify",
    });
    try public_names.expect(Hash, &.{ "init", "digest", "update", "final" });
}

test {
    std.testing.refAllDecls(files);
    // The hook a test binary defines, as every program that links chapulin does.
    _ = @import("test_hooks.zig");
    _ = @import("dnssec_test.zig");
}
