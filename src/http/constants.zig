//! Limits and format constants http owns (docs/design.md §7). Never written inline (CLAUDE.md
//! non-negotiable 4). The field-length limits h2 and h3 share live in `core` and are imported from
//! there.
const std = @import("std");
const assert = std.debug.assert;

/// The lowest and highest valid status codes. RFC 9110 §15 states that all valid status codes are
/// within 100 to 599 inclusive, and that values outside that range are invalid.
pub const status_code_min: u16 = 100;
pub const status_code_max: u16 = 599;

/// Octets in a status code written as text: RFC 9110 §15 makes it a three-digit integer.
pub const status_digits_len: u8 = 3;

/// The step between status classes: the first digit is the class (RFC 9110 §15).
pub const status_class_size: u16 = 100;

comptime {
    assert(status_code_min / status_class_size == 1);
    assert(status_code_max / status_class_size == 5);
    assert(std.math.pow(u16, 10, status_digits_len - 1) == status_code_min);
}

test "the status range spans exactly five classes" {
    try std.testing.expectEqual(5, (status_code_max + 1 - status_code_min) / status_class_size);
}
