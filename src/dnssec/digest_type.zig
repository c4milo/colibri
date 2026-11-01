//! The digests colibri computes, each by its number in IANA's DS RR Type Digest Algorithms
//! registry (decision 142): a DS record's digest, and the hash of an NSEC3 round, whose hash
//! algorithm 1 is SHA-1 (RFC 5155 §5).
const std = @import("std");
const assert = std.debug.assert;
const chapulin = @import("chapulin_tcp");
const protocol = @import("constants.zig").protocol;
const algorithm_file = @import("algorithm.zig");

pub const DigestType = enum(u8) {
    sha1 = protocol.digest_sha1,
    sha256 = protocol.digest_sha256,
    sha384 = protocol.digest_sha384,
};

/// The digest a DS record's Digest Type field names, or null for one colibri cannot compute.
pub fn digest_type(number: u8) ?DigestType {
    if (comptime !algorithm_file.available) return null;
    return std.enums.fromInt(DigestType, number);
}

/// The same digest type in chapulin's type, whose values are the registry's too.
pub fn chapulin_of(chosen: DigestType) chapulin.dnssec.DigestType {
    comptime assert(algorithm_file.available);
    return @enumFromInt(@intFromEnum(chosen));
}

comptime {
    if (algorithm_file.available) {
        assert(protocol.digest_sha1 == chapulin.c.CH_DNSSEC_DIGEST_SHA1);
        assert(protocol.digest_sha256 == chapulin.c.CH_DNSSEC_DIGEST_SHA256);
        assert(protocol.digest_sha384 == chapulin.c.CH_DNSSEC_DIGEST_SHA384);
        assert(protocol.digest_len_max == chapulin.c.CH_DNSSEC_DIGEST_MAX);
    }
}
