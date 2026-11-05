//! The bounds `colibri` chose (decision 137), which size the memory a `Server` holds. Ask the
//! owner before changing one (CLAUDE.md).
const std = @import("std");
const assert = std.debug.assert;
const tls = @import("tls");

/// The longest PEM file of a server's chain or key: an ML-DSA-87 chain's two certificates, about
/// 7,500 octets of DER each, as base64 (RFC 7468 §2).
pub const pem_file_len_max: usize = 24 * 1024;
/// The DER room that holds any chain file of `pem_file_len_max` octets: base64 carries three
/// octets in four characters (RFC 4648 §4).
pub const chain_der_len_max: usize = pem_file_len_max / 4 * 3;
/// The certificates of a chain, as many as `tls` reads.
pub const chain_certificates_max: usize = tls.constants.limits.certificate_chain_len_max;

comptime {
    assert(chain_der_len_max > 0 and chain_der_len_max < pem_file_len_max);
    assert(chain_certificates_max > 0);
}

test "decision 137: the limits of colibri" {
    try std.testing.expectEqual(24 * 1024, pem_file_len_max);
    try std.testing.expectEqual(18 * 1024, chain_der_len_max);
    try std.testing.expectEqual(16, chain_certificates_max);
}
