//! The values the RFCs fix for qlog, which no one may change.
//! Decision 137 groups them, and `constants.zig` exports this file as `protocol`.
const std = @import("std");
const assert = std.debug.assert;

/// Printable ASCII, the space through the tilde: the octets h3-events §4.2.2 logs a field line's
/// name and value as text in.
pub const printable_first: u8 = 0x20;
pub const printable_last: u8 = 0x7e;

/// The digits of that fraction: microseconds of a millisecond.
pub const millisecond_fraction_digits: u5 = 3;

/// The QUIC error codes RFC 9000 §20.1 reserves for TLS alerts, CRYPTO_ERROR: 0x100 plus the
/// alert's description. Quic-events §8.13.26 names each one as its code in hex.
pub const crypto_error_first: u64 = 0x100;
pub const crypto_error_last: u64 = 0x1ff;

/// Hex digits in the name of a CRYPTO_ERROR's code, `crypto_error_0x1XX` (quic-events §8.13.26).
pub const crypto_error_digits: usize = 3;

comptime {
    assert(crypto_error_last - crypto_error_first == 0xff);
    // RFC 8259 §7: a string escapes U+0000 through U+001F, and ASCII ends before 0x80.
    assert(printable_first > 0x1f and printable_last < 0x80);
}
