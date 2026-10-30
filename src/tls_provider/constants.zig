//! The constants of `tls_provider` (docs/design.md §7), never written inline (CLAUDE.md
//! non-negotiable 4). Decision 137 puts each in a file by who sets it, and this file exports
//! the files:
//! - `protocol`: the values the RFCs fix, which no one may change.
//! - `policy`: the values colibri chose within what the RFCs allow, which size nothing.
const std = @import("std");
const assert = std.debug.assert;

pub const protocol = @import("constants_protocol.zig");
pub const policy = @import("constants_policy.zig");

comptime {
    // RFC 9846 Appendix B.4: the TLS 1.3 suites are 0x1301 to 0x1305, and colibri admits the
    // first three. Neither CCM suite is here: RFC 9001 §5.3 excludes TLS_AES_128_CCM_8_SHA256,
    // and RFC 9846 §9.1 makes neither CCM suite a MUST or a SHOULD.
    for (policy.cipher_suites_admitted) |suite| {
        assert(suite >= protocol.cipher_suite_aes_128_gcm_sha256 and suite <= protocol.cipher_suite_chacha20_poly1305_sha256);
    }
}

test "constants compile" {
    try std.testing.expect(true);
}
