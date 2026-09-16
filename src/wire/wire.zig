//! Every integer and string encoding both protocol families read: the QUIC variable-length
//! integer of RFC 9000 §16 for framing, and the prefixed integer, string literal and Huffman code
//! of RFC 7541 §5.1, §5.2 and Appendix B for field compression (decision 11).
const std = @import("std");

pub const core = @import("core");
pub const constants = @import("constants.zig");

test {
    std.testing.refAllDecls(@This());
    _ = constants;
}
