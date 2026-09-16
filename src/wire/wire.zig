//! Every integer and string encoding both protocol families read: the QUIC variable-length
//! integer of RFC 9000 §16 for framing, and the prefixed integer, string literal and Huffman code
//! of RFC 7541 §5.1, §5.2 and Appendix B for field compression (decision 11).
const std = @import("std");

pub const core = @import("core");
pub const constants = @import("constants.zig");

pub const varint = @import("varint.zig");
pub const prefixed_integer = @import("prefixed_integer.zig");
pub const huffman = @import("huffman.zig");
pub const huffman_table = @import("huffman_table.zig");
pub const string_literal = @import("string_literal.zig");

test {
    std.testing.refAllDecls(@This());
    _ = constants;
    _ = varint;
    _ = prefixed_integer;
    _ = huffman;
    _ = huffman_table;
    _ = string_literal;
}
