//! The DNSSEC algorithms colibri checks, each by its number in IANA's DNS Security Algorithm
//! Numbers registry (decision 142). A host object of chapulin, built with DNSSEC=on, checks them
//! all. A device object holds no DNSSEC, so there `algorithm` names none.
const std = @import("std");
const assert = std.debug.assert;
const chapulin = @import("chapulin_tcp");
const protocol = @import("constants.zig").protocol;

/// Whether the object colibri links holds chapulin's DNSSEC calls: a host object does.
pub const available = @hasDecl(chapulin.c, "ch_dnssec_verify");

pub const Algorithm = enum(u8) {
    rsasha256 = protocol.algorithm_rsasha256,
    rsasha512 = protocol.algorithm_rsasha512,
    ecdsap256sha256 = protocol.algorithm_ecdsap256sha256,
    ecdsap384sha384 = protocol.algorithm_ecdsap384sha384,
    ed25519 = protocol.algorithm_ed25519,
};

/// The algorithm a DNSKEY's or an RRSIG's Algorithm field names, or null for one colibri cannot
/// check, such as RSA/SHA-1 (5) or NSEC3RSASHA1 (7).
pub fn algorithm(number: u8) ?Algorithm {
    if (comptime !available) return null;
    return std.enums.fromInt(Algorithm, number);
}

/// The same algorithm in chapulin's type, whose values are the registry's too.
pub fn chapulin_of(chosen: Algorithm) chapulin.dnssec.Algorithm {
    comptime assert(available);
    return @enumFromInt(@intFromEnum(chosen));
}

comptime {
    if (available) {
        assert(protocol.algorithm_rsasha256 == chapulin.c.CH_DNSSEC_ALG_RSASHA256);
        assert(protocol.algorithm_rsasha512 == chapulin.c.CH_DNSSEC_ALG_RSASHA512);
        assert(protocol.algorithm_ecdsap256sha256 == chapulin.c.CH_DNSSEC_ALG_ECDSAP256SHA256);
        assert(protocol.algorithm_ecdsap384sha384 == chapulin.c.CH_DNSSEC_ALG_ECDSAP384SHA384);
        assert(protocol.algorithm_ed25519 == chapulin.c.CH_DNSSEC_ALG_ED25519);
    }
}
