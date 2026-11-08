//! The check of an RRSIG's signature (decision 142): the signature over the digest `Hash.final`
//! wrote, under a DNSKEY's key. chapulin verifies; colibri holds no key of its own.
const std = @import("std");
const assert = std.debug.assert;
const chapulin = @import("chapulin_tcp");
const algorithm_file = @import("algorithm.zig");
const hash_file = @import("hash.zig");

const Algorithm = algorithm_file.Algorithm;
const Error = hash_file.Error;

/// Whether `signature` signs `digest` under `key`, the DNSKEY's Public Key field as it arrives:
/// RFC 3110 §2's form for RSA, and the points of RFC 6605 §4 and RFC 8080 §3. `digest` is what
/// `Hash.final` wrote for the same algorithm, key and signature. The algorithm must be one
/// `algorithm` names.
pub fn verify(algorithm: Algorithm, key: []const u8, digest: []const u8, signature: []const u8) Error!void {
    assert(algorithm_file.available);
    // RFC 4034 §3.1.8.1 and the algorithm's RFC: chapulin refuses a key or a signature of the
    // wrong form with Invalid, and a signature the key does not verify with Auth.
    chapulin.dnssec.verify(algorithm_file.chapulin_of(algorithm), key, digest, signature) catch |failure| return switch (failure) {
        error.Auth => error.SignatureVerificationFailed,
        error.Invalid => error.InvalidEncoding,
    };
}
