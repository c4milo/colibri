//! HPACK, RFC 7541. Shares the Huffman coder and the prefixed integer with QPACK through `wire`;
//! shares neither the static table nor a representation (decisions 11 and 12).
const std = @import("std");

pub const core = @import("core");
pub const wire = @import("wire");
pub const http = @import("http");
pub const constants = @import("constants.zig");

test {
    std.testing.refAllDecls(@This());
    _ = constants;
}
