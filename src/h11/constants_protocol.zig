//! The values the RFCs fix for h11, which no one may change.
//! Decision 137 groups them, and `constants.zig` exports this file as `protocol`.
const std = @import("std");
const assert = std.debug.assert;

/// The octets RFC 9112 §2.3 gives an HTTP-version: `HTTP-name "/" DIGIT "." DIGIT`.
pub const version_len: u32 = 8;

/// The HTTP-name of RFC 9112 §2.3, which compares case-sensitively.
pub const version_name = "HTTP/";

/// The major version this module speaks (RFC 9112 §2.3).
pub const version_major: u8 = 1;

comptime {
    assert(version_name.len + "1.1".len == version_len);
}
