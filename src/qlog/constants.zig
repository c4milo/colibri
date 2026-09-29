//! The fixed values and limits of `qlog` (decision 102). Each is named here and none is written
//! inline (CLAUDE.md non-negotiable 4).
const std = @import("std");
const assert = std.debug.assert;

/// Printable ASCII, the space through the tilde: the octets h3-events §4.2.2 logs a field line's
/// name and value as text in.
pub const printable_first: u8 = 0x20;
pub const printable_last: u8 = 0x7e;

/// A qlog time is milliseconds with a fraction (main schema §1.2, §7.1). colibri's instants are
/// nanoseconds, and it writes microseconds as the fraction.
pub const nanoseconds_per_millisecond: u64 = 1_000_000;
pub const nanoseconds_per_microsecond: u64 = 1_000;

/// The digits of that fraction: microseconds of a millisecond.
pub const millisecond_fraction_digits: u5 = 3;

/// Decimal digits of the largest tuple number, a `u32`, which a TupleID holds as text (main
/// schema §7.2, quic-events §4.7).
pub const tuple_id_len_max: usize = 10;

/// Smallest buffer a log may be given, in octets: the header record fits with room for events.
/// Policy.
pub const log_len_min: usize = 1024;

/// The QUIC error codes RFC 9000 §20.1 reserves for TLS alerts, CRYPTO_ERROR: 0x100 plus the
/// alert's description. Quic-events §8.13.26 names each one as its code in hex.
pub const crypto_error_first: u64 = 0x100;
pub const crypto_error_last: u64 = 0x1ff;

/// Hex digits in the name of a CRYPTO_ERROR's code, `crypto_error_0x1XX` (quic-events §8.13.26).
pub const crypto_error_digits: usize = 3;

comptime {
    assert(nanoseconds_per_millisecond % nanoseconds_per_microsecond == 0);
    assert(std.math.pow(u64, 10, millisecond_fraction_digits) == nanoseconds_per_millisecond / nanoseconds_per_microsecond);
    assert(log_len_min > 0);
    assert(std.fmt.count("{d}", .{std.math.maxInt(u32)}) == tuple_id_len_max);
    assert(crypto_error_last - crypto_error_first == 0xff);
    // RFC 8259 §7: a string escapes U+0000 through U+001F, and ASCII ends before 0x80.
    assert(printable_first > 0x1f and printable_last < 0x80);
}
