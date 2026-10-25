//! Percent-decoding of one octet (RFC 3986 §2.1), which a query's pairs and the server's router
//! share (decision 127).
const std = @import("std");

/// The octets of one percent-encoded octet: "%" and two hex digits (RFC 3986 §2.1).
pub const encoded_len = 3;
/// The octets of its hex digits.
const digits_len = encoded_len - 1;
/// The base of a hex digit.
const hex_radix = 16;

/// The octet that the "%" at `index` and the two hex digits after it name, or null when no such
/// "%" stands there. A "%" that two hex digits do not follow is no encoded octet, and its caller
/// keeps it as written (decision 127).
pub fn decoded_at(encoded: []const u8, index: usize) ?u8 {
    if (encoded[index] != '%' or index + encoded_len > encoded.len) return null;
    const digits = encoded[index + 1 ..][0..digits_len];
    const high = std.fmt.charToDigit(digits[0], hex_radix) catch return null;
    const low = std.fmt.charToDigit(digits[1], hex_radix) catch return null;
    return high * hex_radix + low;
}

const testing = std.testing;

test "RFC 3986 §2.1: %XX names its octet in either case, and a short or bad % names none" {
    try testing.expectEqual(0x2f, decoded_at("%2F", 0).?);
    try testing.expectEqual(0xab, decoded_at("x%aB", 1).?);
    try testing.expectEqual(null, decoded_at("%2", 0));
    try testing.expectEqual(null, decoded_at("%zz", 0));
    try testing.expectEqual(null, decoded_at("%2g", 0));
    try testing.expectEqual(null, decoded_at("a%41", 0));
}
