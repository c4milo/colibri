//! Every integer and string encoding both protocol families read: the QUIC variable-length
//! integer of RFC 9000 §16 for framing, and the prefixed integer, string literal and Huffman code
//! of RFC 7541 §5.1, §5.2 and Appendix B for field compression (decision 11).
//!
//! This root is the module's API file (decision 115). It exports the names code outside the
//! module uses: a type under its own name, a function or a constant under the namespace of its
//! file, and no file but `constants`.
const std = @import("std");

pub const core = @import("core");
pub const constants = @import("constants.zig");

/// Every file of the module. None of these is exported: the names below are.
const files = struct {
    pub const varint = @import("varint.zig");
    pub const prefixed_integer = @import("prefixed_integer.zig");
    pub const huffman = @import("huffman.zig");
    pub const huffman_table = @import("huffman_table.zig");
    pub const string_literal = @import("string_literal.zig");
    pub const table_size = @import("table_size.zig");
};

pub const varint = struct {
    pub const decode = files.varint.decode;
    pub const encode = files.varint.encode;
    pub const encode_with_len = files.varint.encode_with_len;
    pub const encoded_len_minimal = files.varint.encoded_len_minimal;
};

pub const prefixed_integer = struct {
    pub const DecodeError = files.prefixed_integer.DecodeError;
    pub const decode = files.prefixed_integer.decode;
    pub const encode = files.prefixed_integer.encode;
};

pub const huffman = struct {
    pub const DecodeError = files.huffman.DecodeError;
    pub const decode = files.huffman.decode;
    pub const encode = files.huffman.encode;
    pub const encoded_len = files.huffman.encoded_len;
    pub const encoded_len_max = files.huffman.encoded_len_max;
};

pub const string_literal = struct {
    pub const Coding = files.string_literal.Coding;
    pub const DecodeError = files.string_literal.DecodeError;
    pub const decode = files.string_literal.decode;
    pub const encode = files.string_literal.encode;
};

pub const table_size = struct {
    pub const entry_size = files.table_size.entry_size;
};

test "decision 115: the root exports the names code outside the module uses" {
    try core.public_names.expect(@This(), &.{
        "core",    "constants",      "varint",     "prefixed_integer",
        "huffman", "string_literal", "table_size",
    });
}

test {
    // Every file's tests run, whether or not the root exports a name of it.
    std.testing.refAllDecls(files);
    // Every name the root exports resolves, in each namespace it declares.
    _ = core.public_names.reference(@This(), &.{"core"});
}
