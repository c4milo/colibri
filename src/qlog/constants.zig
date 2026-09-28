//! The fixed values and limits of `qlog` (decision 102). Each is named here and none is written
//! inline (CLAUDE.md non-negotiable 4).
const std = @import("std");
const assert = std.debug.assert;

/// The octet before each record of a log (RFC 7464 §2.2).
pub const record_separator: u8 = 0x1e;

/// The octet after each record (RFC 7464 §2.2).
pub const line_feed: u8 = 0x0a;

/// The last of the control characters RFC 8259 §7 requires a string to escape, U+0000 through
/// U+001F.
pub const control_character_last: u8 = 0x1f;

/// The first octet that is not ASCII. colibri writes its own ASCII as text and a peer's octets as
/// hexstrings, never as text (decision 102).
pub const ascii_end: u8 = 0x80;

/// The digits of a hexstring, lowercase as main schema §1.2 defines the type.
pub const hex_digits = "0123456789abcdef";

/// Bits in one hex digit.
pub const nibble_bits: u3 = 4;

/// Deepest nesting of objects and arrays a record may have. Policy: a QUIC frame's `raw` object
/// inside a packet's `frames` array inside an event's `data` is four deep.
pub const json_depth_max: u8 = 8;

/// A qlog time is milliseconds with a fraction (main schema §1.2, §7.1). colibri's instants are
/// nanoseconds, and it writes microseconds as the fraction.
pub const nanoseconds_per_millisecond: u64 = 1_000_000;
pub const nanoseconds_per_microsecond: u64 = 1_000;

/// Smallest buffer a log may be given, in octets: the header record fits with room for events.
/// Policy.
pub const log_len_min: usize = 1024;

comptime {
    assert(record_separator != line_feed);
    assert(record_separator <= control_character_last and line_feed <= control_character_last);
    assert(hex_digits.len == 1 << nibble_bits);
    assert(json_depth_max >= 4);
    assert(nanoseconds_per_millisecond % nanoseconds_per_microsecond == 0);
    assert(log_len_min > 0);
}
