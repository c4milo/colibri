//! The values colibri chose for tls_provider within what the RFCs allow, which size nothing.
//! Decision 137 groups them, and `constants.zig` exports this file as `policy`.
const protocol = @import("constants_protocol.zig");

pub const cipher_suites_admitted = [_]u16{
    protocol.cipher_suite_aes_128_gcm_sha256,
    protocol.cipher_suite_aes_256_gcm_sha384,
    protocol.cipher_suite_chacha20_poly1305_sha256,
};
