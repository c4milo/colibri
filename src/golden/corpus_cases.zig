//! The golden corpus as a pure table (decision 26, design §8 steps 1 and 3): what each case is built from
//! and the verdict its decoder must return. `corpus.zig` builds, decodes and describes the cases;
//! `tools/golden.zig` writes them to disk; `golden.zig` checks the files against this table.
//!
//! Valid and invalid cases both, because a parser that accepts everything passes a valid-only
//! corpus. The check of design §8 step 1 asks for one case per varint length, one per Huffman
//! decode error, and RFC 9000 Appendix A.1's sample decodings. The published vectors of RFC 7541
//! Appendix C are here beside them (decision 25).
const wire = @import("wire");

pub const Format = enum {
    varint,
    prefixed_integer,
    huffman,
    string_literal,
    /// An HPACK field block, decoded by a fresh `hpack.Decoder` of the case's `capacity`.
    hpack,
};

/// How a case's octets are made.
pub const Construction = union(enum) {
    /// Octets as the case gives them: an invalid encoding no encoder produces.
    literal: []const u8,
    /// `wire.varint.encode_with_len`.
    varint: struct { value: u64, encoded_len: u8 },
    /// `wire.prefixed_integer.encode` at the case's prefix size.
    prefixed_integer: struct { value: u64, high_bits: u8 = 0 },
    /// `wire.huffman.encode` of this text.
    huffman: []const u8,
    /// `wire.string_literal.encode` at the case's prefix size.
    string_literal: struct {
        text: []const u8,
        coding: wire.string_literal.Coding,
        high_bits: u8 = 0,
    },
    /// The octets of another case in the same format, less the last `drop`.
    truncated: struct { case_name: []const u8, drop: u8 },
};

pub const Case = struct {
    name: []const u8,
    /// N, the prefix size a prefixed integer or string literal decodes at. Unused by the other
    /// formats.
    prefix_size: u4 = 8,
    /// The dynamic table capacity an hpack case's decoder starts with. Unused by the other
    /// formats.
    capacity: u32 = 4096,
    construction: Construction,
    /// Null when the case must decode and consume every octet; otherwise the error its decoder
    /// must return.
    rejection: ?anyerror = null,
};

/// A case that must decode and consume every octet.
fn accept(name: []const u8, construction: Construction) Case {
    return .{ .name = name, .construction = construction };
}

/// A case whose decoder must return `rejection`.
fn reject(name: []const u8, construction: Construction, rejection: anyerror) Case {
    return .{ .name = name, .construction = construction, .rejection = rejection };
}

/// `case`, decoded at prefix size `prefix_size`.
fn at_prefix(prefix_size: u4, case: Case) Case {
    var result = case;
    result.prefix_size = prefix_size;
    return result;
}

/// `case`, decoded by an HPACK decoder whose table starts at `capacity`.
fn at_capacity(capacity: u32, case: Case) Case {
    var result = case;
    result.capacity = capacity;
    return result;
}

/// The octets of the case named `case_name`, less the last one.
fn truncated_from(case_name: []const u8) Construction {
    return .{ .truncated = .{ .case_name = case_name, .drop = 1 } };
}

const integer_value_max = wire.constants.integer_value_max;

pub const varint = [_]Case{
    // RFC 9000 Appendix A.1's five sample decodings: one of each length, and a non-minimal 37.
    accept("varint_1_octet_37", .{ .varint = .{ .value = 37, .encoded_len = 1 } }),
    accept("varint_2_octets_37", .{ .varint = .{ .value = 37, .encoded_len = 2 } }),
    accept("varint_2_octets_15293", .{ .varint = .{ .value = 15_293, .encoded_len = 2 } }),
    accept("varint_4_octets_494878333", .{ .varint = .{ .value = 494_878_333, .encoded_len = 4 } }),
    accept("varint_8_octets_151288809941952652", .{
        .varint = .{ .value = 151_288_809_941_952_652, .encoded_len = 8 },
    }),
    // The largest value, which needs all 62 bits.
    accept("varint_8_octets_max", .{
        .varint = .{ .value = wire.constants.varint_value_max, .encoded_len = 8 },
    }),
    // One truncation per length: the first octet declares more octets than are present.
    reject("varint_empty", .{ .literal = &.{} }, error.Truncated),
    reject("varint_2_octets_truncated", truncated_from("varint_2_octets_15293"), error.Truncated),
    reject(
        "varint_4_octets_truncated",
        truncated_from("varint_4_octets_494878333"),
        error.Truncated,
    ),
    reject(
        "varint_8_octets_truncated",
        truncated_from("varint_8_octets_151288809941952652"),
        error.Truncated,
    ),
};

pub const prefixed_integer = [_]Case{
    // RFC 7541 Appendix C.1's three examples.
    at_prefix(5, accept("prefixed_integer_5_bit_10", .{ .prefixed_integer = .{ .value = 10 } })),
    at_prefix(5, accept("prefixed_integer_5_bit_1337", .{
        .prefixed_integer = .{ .value = 1337 },
    })),
    at_prefix(8, accept("prefixed_integer_8_bit_42", .{ .prefixed_integer = .{ .value = 42 } })),
    // The caller's high bits beside a 5-bit prefix, and the 62-bit maximum at both prefix extremes.
    at_prefix(5, accept("prefixed_integer_5_bit_1337_high_bits", .{
        .prefixed_integer = .{ .value = 1337, .high_bits = 0xe0 },
    })),
    at_prefix(1, accept("prefixed_integer_1_bit_max", .{
        .prefixed_integer = .{ .value = integer_value_max },
    })),
    at_prefix(8, accept("prefixed_integer_8_bit_max", .{
        .prefixed_integer = .{ .value = integer_value_max },
    })),
    // 2^62 with a 1-bit prefix: one past what RFC 9204 §4.1.1 requires and colibri accepts.
    at_prefix(1, reject("prefixed_integer_1_bit_too_large", .{
        .literal = &.{ 0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f },
    }, error.IntegerTooLarge)),
    // A full prefix and nine zero-valued continuation octets that each set the continuation flag.
    at_prefix(5, reject("prefixed_integer_5_bit_too_long", .{
        .literal = &.{ 0x1f, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00 },
    }, error.IntegerTooLong)),
    at_prefix(5, reject(
        "prefixed_integer_5_bit_truncated",
        truncated_from("prefixed_integer_5_bit_1337"),
        error.Truncated,
    )),
};

pub const huffman = [_]Case{
    // RFC 7541 Appendix C.4.1 and C.4.2.
    accept("huffman_www_example_com", .{ .huffman = "www.example.com" }),
    accept("huffman_no_cache", .{ .huffman = "no-cache" }),
    // Octets 204 and 22: a run of thirty-four ones with no EOS in it (decision 11, invariant 12).
    accept("huffman_octets_204_22", .{ .huffman = &.{ 0xcc, 0x16 } }),
    accept("huffman_empty", .{ .huffman = "" }),
    // One case per decode error of RFC 7541 §5.2.
    reject(
        "huffman_eos_in_data",
        .{ .literal = &.{ 0xff, 0xff, 0xff, 0xff } },
        error.HuffmanEosInData,
    ),
    reject(
        "huffman_padding_too_long",
        .{ .literal = &.{ 0x1f, 0xff } },
        error.HuffmanPaddingTooLong,
    ),
    reject("huffman_padding_not_eos", .{ .literal = &.{0x18} }, error.HuffmanPaddingNotEos),
};

pub const string_literal = [_]Case{
    // RFC 7541 Appendix C.2.1's raw name and C.4.1's Huffman authority.
    accept("string_literal_raw_custom_key", .{
        .string_literal = .{ .text = "custom-key", .coding = .raw },
    }),
    accept("string_literal_huffman_www_example_com", .{
        .string_literal = .{ .text = "www.example.com", .coding = .huffman },
    }),
    // RFC 9204 §4.1.2's mid-octet form: a 4-bit prefix below four bits of the previous field, and
    // the narrowest, a 2-bit prefix.
    at_prefix(4, accept("string_literal_4_bit_huffman_no_cache", .{
        .string_literal = .{ .text = "no-cache", .coding = .huffman, .high_bits = 0x20 },
    })),
    at_prefix(2, accept("string_literal_2_bit_raw_custom_key", .{
        .string_literal = .{ .text = "custom-key", .coding = .raw, .high_bits = 0xfc },
    })),
    // A length one past the data present, and Huffman data with bad padding.
    reject(
        "string_literal_truncated",
        truncated_from("string_literal_raw_custom_key"),
        error.Truncated,
    ),
    reject(
        "string_literal_huffman_padding_not_eos",
        .{ .literal = &.{ 0x81, 0x18 } },
        error.HuffmanPaddingNotEos,
    ),
};

/// Every format's cases, in the order the manifest and the tool visit them.
/// The interop breaks design §6.2 names, each with a named error, beside their legal twins.
pub const hpack = [_]Case{
    // RFC 7541 §6.1: index 0 in an indexed field is a decoding error.
    reject("hpack_indexed_index_zero", .{ .literal = "\x80" }, error.IndexZero),
    // RFC 7541 §6.2.1: index 0 in a literal is the new-name discriminator, not an error.
    accept("hpack_literal_name_index_zero", .{ .literal = "\x40\x0acustom-key\x0ccustom-value" }),
    // RFC 7541 §2.3.3: index 62 is the first dynamic entry, absent from an empty table.
    reject("hpack_index_past_empty_table", .{ .literal = "\xbe" }, error.IndexOutOfRange),
    // RFC 7541 §2.3.3: after one insert, index 62 is that entry.
    at_capacity(40, accept("hpack_insert_fits_then_indexed", .{ .literal = "\x40\x01a\x01b\xbe" })),
    // RFC 7541 §4.4: an insert larger than the capacity is not an error; it empties the table,
    // so the index that was valid before the insert is now past it.
    at_capacity(40, reject(
        "hpack_insert_larger_than_capacity_empties",
        .{ .literal = "\x40\x01a\x01b\x40\x01c\x08dddddddd\xbe" },
        error.IndexOutOfRange,
    )),
    // RFC 7541 §6.3: a size update above the protocol's limit, here 4,097 over 4,096.
    reject("hpack_size_update_above_limit", .{ .literal = "\x3f\xe2\x1f" }, error.SizeUpdateTooLarge),
};

pub const all = [_]struct { format: Format, cases: []const Case }{
    .{ .format = .varint, .cases = &varint },
    .{ .format = .prefixed_integer, .cases = &prefixed_integer },
    .{ .format = .huffman, .cases = &huffman },
    .{ .format = .string_literal, .cases = &string_literal },
    .{ .format = .hpack, .cases = &hpack },
};
