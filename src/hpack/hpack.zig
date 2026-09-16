//! HPACK, RFC 7541. Shares the Huffman coder, the prefixed integer, the string literal and the
//! table-size arithmetic with QPACK through `wire`; shares neither the static table nor a
//! representation (decisions 11 and 12).
//!
//! `Decoder` turns a field block into field lines; `Encoder` turns field lines into a field
//! block. Each holds a `DynamicTable`, and the caller places both (decision 35).
const std = @import("std");

pub const core = @import("core");
pub const wire = @import("wire");
pub const http = @import("http");
pub const constants = @import("constants.zig");

pub const static_table = @import("static_table.zig");
pub const dynamic_table = @import("dynamic_table.zig");
pub const decoder = @import("decoder.zig");
pub const encoder = @import("encoder.zig");

pub const Field = dynamic_table.Field;
pub const DynamicTable = dynamic_table.DynamicTable;
pub const Decoder = decoder.Decoder;
pub const FieldLine = decoder.FieldLine;
pub const Encoder = encoder.Encoder;
pub const Indexing = encoder.Indexing;

test {
    std.testing.refAllDecls(@This());
    _ = constants;
    _ = static_table;
    _ = dynamic_table;
    _ = decoder;
    _ = @import("decoder_block.zig");
    _ = encoder;
}

test "the static table is exactly the 61 entries of RFC 7541 Appendix A, from :authority" {
    try std.testing.expectEqual(constants.static_table_len, static_table.entries.len);
    try std.testing.expectEqualStrings(":authority", static_table.entries[0].name);
    try std.testing.expectEqualStrings("www-authenticate", static_table.entries[constants.static_table_len - 1].name);
    for (static_table.entries) |entry| {
        for (entry.name) |octet| try std.testing.expect(!std.ascii.isUpper(octet));
    }
}
