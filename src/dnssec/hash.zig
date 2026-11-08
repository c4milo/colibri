//! A hash the caller holds and feeds in pieces (decision 142): of an RRSIG's signed data, which
//! `verify` then checks, or a plain digest, for a DS record or one round of NSEC3's hash. chapulin
//! hashes; colibri allocates nothing, and the caller places the state.
const std = @import("std");
const assert = std.debug.assert;
const chapulin = @import("chapulin_tcp");
const protocol = @import("constants.zig").protocol;
const algorithm_file = @import("algorithm.zig");
const digest_type_file = @import("digest_type.zig");

const Algorithm = algorithm_file.Algorithm;
const DigestType = digest_type_file.DigestType;

/// Why a check failed, as `std.crypto.errors` names each failure (decision 158 ruling 11).
pub const Error = error{
    /// A signature the key does not verify.
    SignatureVerificationFailed,
    /// A key, a digest or a signature of a form its algorithm refuses.
    InvalidEncoding,
};

pub const Hash = struct {
    state: State = undefined,

    const State = if (algorithm_file.available) chapulin.dnssec.Hash else void;

    /// Starts the hash of an RRSIG's signed data under `algorithm`. `key` is the DNSKEY's Public
    /// Key field and `signature` the RRSIG's Signature field, each as it arrives: Ed25519 hashes
    /// R and the key before the data (RFC 8080 §4, RFC 8032 §5.1.7). The algorithm must be one
    /// `algorithm` names.
    pub fn init(algorithm: Algorithm, key: []const u8, signature: []const u8) Error!Hash {
        assert(algorithm_file.available);
        // RFC 8080 §3 and §4: an Ed25519 key is 32 octets and its signature 64, which chapulin
        // checks here.
        const state = chapulin.dnssec.Hash.init(algorithm_file.chapulin_of(algorithm), key, signature) catch return error.InvalidEncoding;
        return .{ .state = state };
    }

    /// Starts a plain digest of `digest_type`, for a DS record (RFC 4034 §5.1.4) or one round of
    /// NSEC3's hash (RFC 5155 §5). The type must be one `digest_type` names.
    pub fn digest(digest_type: DigestType) Hash {
        assert(algorithm_file.available);
        return .{ .state = chapulin.dnssec.Hash.init_digest(digest_type_file.chapulin_of(digest_type)) };
    }

    /// Adds `bytes` to what the hash has read.
    pub fn update(hash: *Hash, bytes: []const u8) void {
        hash.state.update(bytes);
    }

    /// Writes the digest into `out` and returns it: 20, 32, 48 or 64 octets. The state is wiped,
    /// so the hash takes nothing more.
    pub fn final(hash: *Hash, out: *[protocol.digest_len_max]u8) []const u8 {
        const written = hash.state.final(out);
        assert(written.len > 0 and written.len <= out.len);
        return written;
    }
};
