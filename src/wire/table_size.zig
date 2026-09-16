//! The dynamic-table size formula HPACK and QPACK share (decision 11): an entry's size is its
//! name's length plus its value's length plus 32, measured on the unencoded strings, and a
//! table's size is the sum over its entries. RFC 7541 §4.1 and RFC 9204 §3.2.1 give the rule
//! word for word. The tables themselves are not shared (decision 12); only this arithmetic is.
//!
//! The lengths are measured before any Huffman coding. Accounting the encoded length instead
//! passes every round-trip test against itself and fails against every other implementation
//! (invariant 11).
const std = @import("std");
const constants = @import("constants.zig");

/// The size of one entry: `name_len + value_len + 32` (RFC 7541 §4.1, RFC 9204 §3.2.1).
pub fn entry_size(name_len: usize, value_len: usize) u64 {
    return @as(u64, name_len) + value_len + constants.table_entry_overhead;
}

const testing = std.testing;

test "RFC 7541 Appendix C.3.1's first entry measures 57" {
    try testing.expectEqual(57, entry_size(":authority".len, "www.example.com".len));
}

test "an entry with nothing in it still costs the overhead" {
    try testing.expectEqual(constants.table_entry_overhead, entry_size(0, 0));
}
