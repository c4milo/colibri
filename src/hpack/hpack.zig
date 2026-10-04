//! HPACK, RFC 7541. Shares the Huffman coder, the prefixed integer, the string literal and the
//! table-size arithmetic with QPACK through `wire`; shares neither the static table nor a
//! representation (decisions 11 and 12).
//!
//! `Decoder` turns a field block into field lines; `Encoder` turns field lines into a field
//! block. Each holds a `DynamicTable`, and the caller places both (decision 35).
//!
//! This root is the module's API file (decision 115). It exports the names code outside the
//! module uses: a type under its own name, a function or a constant under the namespace of its
//! file, and no file but `constants`.
const std = @import("std");

pub const core = @import("core");
pub const wire = @import("wire");
pub const http = @import("http");
pub const constants = @import("constants.zig");

/// Every file of the module. None of these is exported: the names below are.
const files = struct {
    pub const static_table = @import("static_table.zig");
    pub const dynamic_table = @import("dynamic_table.zig");
    pub const decoder = @import("decoder.zig");
    pub const encoder = @import("encoder.zig");
};

pub const Field = files.dynamic_table.Field;
pub const DynamicTable = files.dynamic_table.DynamicTable;
pub const Decoder = files.decoder.Decoder;
pub const FieldLine = files.decoder.FieldLine;
pub const Encoder = files.encoder.Encoder;
pub const Indexing = files.encoder.Indexing;

pub const decoder = struct {
    pub const Error = files.decoder.Error;
    pub const expect_lines = files.decoder.expect_lines;
    /// A variable of the file, which a test of another module shares. Test-only.
    pub fn test_decoder() *@TypeOf(files.decoder.test_decoder) {
        return &files.decoder.test_decoder;
    }
};

pub const encoder = struct {
    pub const Error = files.encoder.Error;
    pub const Indexing = files.encoder.Indexing;
};

test "decision 115: the root exports the names code outside the module uses" {
    try core.public_names.expect(@This(), &.{
        "core",    "wire",         "http",    "constants",
        "Field",   "DynamicTable", "Decoder", "FieldLine",
        "Encoder", "Indexing",     "decoder", "encoder",
    });
}

test {
    // Every file's tests run, whether or not the root exports a name of it.
    std.testing.refAllDecls(files);
    // Every name the root exports resolves, in each namespace it declares.
    _ = core.public_names.reference(@This(), &.{ "core", "wire", "http" });
    _ = @import("decoder_block.zig");
}

test "the static table is exactly the 61 entries of RFC 7541 Appendix A, from :authority" {
    try std.testing.expectEqual(constants.static_table_len, files.static_table.entries.len);
    try std.testing.expectEqualStrings(":authority", files.static_table.entries[0].name);
    try std.testing.expectEqualStrings("www-authenticate", files.static_table.entries[constants.static_table_len - 1].name);
    for (files.static_table.entries) |entry| {
        for (entry.name) |octet| try std.testing.expect(!std.ascii.isUpper(octet));
    }
}
