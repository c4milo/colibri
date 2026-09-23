//! The corpus mutations (CLAUDE.md, "Tests are proved by mutation"). Each one edits the committed
//! octets of one corpus case and names the verdict the edited octets must produce. A mutation is a
//! rule written down as a counterexample: if a decoder change stops the edit producing its verdict,
//! `golden.zig` fails and names the rule that broke.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const constants = @import("constants.zig");
const cases = @import("corpus_cases.zig");

const Writer = core.Writer;
const Format = cases.Format;

pub const Edit = union(enum) {
    /// Replace the octet at `offset` with `value`.
    set: struct { offset: u8, value: u8 },
    /// Remove the last `count` octets.
    truncate: u8,
    /// Append these octets.
    append: []const u8,
};

pub const Mutation = struct {
    format: Format,
    case_name: []const u8,
    /// The rule the mutation guards, in words.
    rule: []const u8,
    edit: Edit,
    /// Null when the edited octets must still decode; otherwise the error they must produce.
    rejection: ?anyerror,
};

pub const all = [_]Mutation{
    .{
        .format = .hpack,
        .case_name = "hpack_indexed_index_zero",
        .rule = "RFC 7541 §6.1: index 1 is the first static entry, where 0 was the decoding error",
        .edit = .{ .set = .{ .offset = 0, .value = 0x81 } },
        .rejection = null,
    },
    .{
        .format = .hpack,
        .case_name = "hpack_literal_name_index_zero",
        .rule = "RFC 7541 §6.1: the same index 0 that named a new name is an error once indexed",
        .edit = .{ .set = .{ .offset = 0, .value = 0x80 } },
        .rejection = error.IndexZero,
    },
    .{
        .format = .hpack,
        .case_name = "hpack_insert_fits_then_indexed",
        .rule = "RFC 7541 §2.3.3: one past the sum of both tables' lengths is a decoding error",
        .edit = .{ .set = .{ .offset = 5, .value = 0xbf } },
        .rejection = error.IndexOutOfRange,
    },
    .{
        .format = .hpack,
        .case_name = "hpack_insert_larger_than_capacity_empties",
        .rule = "RFC 7541 §4.4: the oversized insert itself is not an error, only the index after it",
        .edit = .{ .truncate = 1 },
        .rejection = null,
    },
    .{
        .format = .hpack,
        .case_name = "hpack_size_update_above_limit",
        .rule = "RFC 7541 §6.3: a size equal to the limit is allowed; one above it is not",
        .edit = .{ .set = .{ .offset = 1, .value = 0xe1 } },
        .rejection = null,
    },
    .{
        .format = .varint,
        .case_name = "varint_1_octet_37",
        .rule = "RFC 9000 §16: the two high bits of the first octet give the length; 01 is two octets",
        .edit = .{ .set = .{ .offset = 0, .value = 0x65 } },
        .rejection = error.Truncated,
    },
    .{
        .format = .varint,
        .case_name = "varint_2_octets_37",
        .rule = "RFC 9000 §16: 00 in the high bits is a one-octet integer, so one octet is left",
        .edit = .{ .set = .{ .offset = 0, .value = 0x00 } },
        .rejection = error.TrailingOctets,
    },
    .{
        .format = .varint,
        .case_name = "varint_8_octets_max",
        .rule = "invariant 9: an eight-octet integer with seven octets present is truncated",
        .edit = .{ .truncate = 1 },
        .rejection = error.Truncated,
    },
    .{
        .format = .prefixed_integer,
        .case_name = "prefixed_integer_5_bit_10",
        .rule = "RFC 7541 §5.1: a prefix of all ones means continuation octets follow",
        .edit = .{ .set = .{ .offset = 0, .value = 0x1f } },
        .rejection = error.Truncated,
    },
    .{
        .format = .prefixed_integer,
        .case_name = "prefixed_integer_5_bit_1337",
        .rule = "RFC 7541 §5.1: the continuation flag set on the last octet promises another",
        .edit = .{ .set = .{ .offset = 2, .value = 0x8a } },
        .rejection = error.Truncated,
    },
    .{
        .format = .prefixed_integer,
        .case_name = "prefixed_integer_1_bit_max",
        .rule = "RFC 9204 §4.1.1, RFC 7541 §5.1: one bit past 62 is over colibri's limit",
        .edit = .{ .set = .{ .offset = 9, .value = 0x40 } },
        .rejection = error.IntegerTooLarge,
    },
    .{
        .format = .prefixed_integer,
        .case_name = "prefixed_integer_5_bit_too_long",
        .rule = "RFC 7541 §5.1: the octet limit fires on the tenth octet, before input runs out",
        .edit = .{ .truncate = 1 },
        .rejection = error.IntegerTooLong,
    },
    .{
        .format = .huffman,
        .case_name = "huffman_www_example_com",
        .rule = "RFC 7541 §5.2: padding must be the high bits of EOS, so a zero in it is refused",
        .edit = .{ .set = .{ .offset = 11, .value = 0xfe } },
        .rejection = error.HuffmanPaddingNotEos,
    },
    .{
        .format = .huffman,
        .case_name = "huffman_octets_204_22",
        .rule = "RFC 7541 §5.2: eight more ones after the padding make padding longer than 7 bits",
        .edit = .{ .append = &.{0xff} },
        .rejection = error.HuffmanPaddingTooLong,
    },
    .{
        .format = .huffman,
        .case_name = "huffman_empty",
        .rule = "RFC 7541 §5.2: an octet of ones with no symbol before it is padding over 7 bits",
        .edit = .{ .append = &.{0xff} },
        .rejection = error.HuffmanPaddingTooLong,
    },
    .{
        .format = .huffman,
        .case_name = "huffman_eos_in_data",
        .rule = "invariant 12: EOS completes at its thirtieth bit, whatever follows it",
        .edit = .{ .set = .{ .offset = 3, .value = 0xfc } },
        .rejection = error.HuffmanEosInData,
    },
    .{
        .format = .string_literal,
        .case_name = "string_literal_raw_custom_key",
        .rule = "invariant 9: a length one past the data present is truncated",
        .edit = .{ .set = .{ .offset = 0, .value = 0x0b } },
        .rejection = error.Truncated,
    },
    .{
        .format = .string_literal,
        .case_name = "string_literal_raw_custom_key",
        .rule = "RFC 7541 §5.2: the length counts every octet of data, so one short leaves one",
        .edit = .{ .set = .{ .offset = 0, .value = 0x09 } },
        .rejection = error.TrailingOctets,
    },
    .{
        .format = .string_literal,
        .case_name = "string_literal_huffman_www_example_com",
        .rule = "RFC 7541 §5.2: the H flag alone selects Huffman, so clearing it reads data raw",
        .edit = .{ .set = .{ .offset = 0, .value = 0x0c } },
        .rejection = null,
    },
    .{
        .format = .string_literal,
        .case_name = "string_literal_4_bit_huffman_no_cache",
        .rule = "RFC 9204 §4.1.2: the bits above the N-bit prefix belong to the previous field",
        .edit = .{ .set = .{ .offset = 0, .value = 0xde } },
        .rejection = null,
    },
    .{
        .format = .quic_invariant,
        .case_name = "quic_invariant_unknown_version_ids_21",
        .rule = "invariant 22: the version-independent reader applies no version 1 rule, so the same 21-octet connection IDs parse under version 1 too",
        .edit = .{ .set = .{ .offset = 4, .value = 0x01 } },
        .rejection = null,
    },
    .{
        .format = .quic_packet,
        .case_name = "quic_packet_other_version_ids_21",
        .rule = "RFC 9000 §17.2: the version 1 reader drops what the octet above handed over, once the version is 1",
        .edit = .{ .set = .{ .offset = 4, .value = 0x01 } },
        .rejection = error.ConnectionIdTooLong,
    },
    .{
        .format = .quic_packet,
        .case_name = "quic_packet_dcid_20",
        .rule = "RFC 9000 §17.2: the maximum is 20 octets, so a length octet of 21 is dropped before the octets it counts are looked for",
        .edit = .{ .set = .{ .offset = 5, .value = 21 } },
        .rejection = error.ConnectionIdTooLong,
    },
    .{
        .format = .quic_packet,
        .case_name = "quic_packet_handshake",
        .rule = "RFC 9000 §12.2: a Length one past the datagram names a packet that is not whole",
        .edit = .{ .set = .{ .offset = 10, .value = 6 } },
        .rejection = error.LengthPastDatagram,
    },
    .{
        .format = .quic_packet,
        .case_name = "quic_packet_handshake",
        .rule = "RFC 9000 §12.2: a Length one short leaves an octet that is read as the next packet, and one octet is no short header here",
        .edit = .{ .set = .{ .offset = 10, .value = 4 } },
        .rejection = error.FixedBitClear,
    },
    .{
        .format = .quic_packet,
        .case_name = "quic_packet_version_negotiation",
        .rule = "RFC 8999 §6: the seven bits after the Header Form bit are unused and ignored, the Fixed Bit among them",
        .edit = .{ .set = .{ .offset = 0, .value = 0xbf } },
        .rejection = null,
    },
    .{
        .format = .quic_packet,
        .case_name = "quic_packet_initial_token",
        .rule = "RFC 9000 §17.2.2: only an Initial packet carries a token, so as a Handshake packet the same octets have a Length of 3 and leave three octets behind it",
        .edit = .{ .set = .{ .offset = 0, .value = 0xe0 } },
        .rejection = error.FixedBitClear,
    },
    .{
        .format = .quic_receive,
        .case_name = "quic_receive_initial",
        .rule = "RFC 9001 §5.5: a tag no key verifies is a packet to drop, not a connection error",
        .edit = .{ .set = .{ .offset = 28, .value = 0x44 } },
        .rejection = error.WouldNotOpen,
    },
    .{
        .format = .quic_receive,
        .case_name = "quic_receive_initial",
        .rule = "RFC 9001 §6.1: Initial keys are never updated, so the next keys open no Initial",
        .edit = .{ .set = .{ .offset = 28, .value = 0x22 } },
        .rejection = error.WouldNotOpen,
    },
    .{
        .format = .quic_receive,
        .case_name = "quic_receive_key_update",
        .rule = "RFC 9001 §6.5: previous keys open nothing before any update left some to hold",
        .edit = .{ .set = .{ .offset = 19, .value = 0x33 } },
        .rejection = error.WouldNotOpen,
    },
    .{
        .format = .quic_receive,
        .case_name = "quic_receive_other_connection",
        .rule = "RFC 9000 §12.2: a later packet to the first one's connection ID is read on",
        .edit = .{ .set = .{ .offset = 35, .value = 0x0c } },
        .rejection = null,
    },
    .{
        .format = .quic_receive,
        .case_name = "quic_receive_other_source",
        .rule = "RFC 9000 §7.2: the Source Connection ID the client first accepted is accepted again",
        .edit = .{ .set = .{ .offset = 37, .value = 0x5e } },
        .rejection = null,
    },
    .{
        .format = .quic_receive,
        .case_name = "quic_receive_duplicate",
        .rule = "RFC 9000 §12.3: a packet number not yet processed in the space is new",
        .edit = .{ .set = .{ .offset = 40, .value = 1 } },
        .rejection = null,
    },
    .{
        .format = .quic_receive,
        .case_name = "quic_receive_unreadable_header",
        .rule = "RFC 9000 §17.3.1: with the Fixed Bit set the same octets are a packet",
        .edit = .{ .set = .{ .offset = 0, .value = 0x40 } },
        .rejection = null,
    },
    .{
        .format = .quic_receive,
        .case_name = "quic_receive_update_twice",
        .rule = "RFC 9001 §6.2: only a packet under the next keys is a second update",
        .edit = .{ .set = .{ .offset = 19, .value = 0x11 } },
        .rejection = null,
    },
    .{
        .format = .quic_receive,
        .case_name = "quic_receive_old_above_current",
        .rule = "RFC 9001 §6.4: old keys may open a packet numbered below the current phase's first",
        .edit = .{ .set = .{ .offset = 2, .value = 3 } },
        .rejection = null,
    },
};

comptime {
    assert(all.len <= constants.mutations_max);
}

/// Writes `octets` with `mutation`'s edit applied.
pub fn apply(
    mutation: *const Mutation,
    octets: []const u8,
    output: *Writer,
) core.writer.Error!void {
    switch (mutation.edit) {
        .set => |set| {
            assert(set.offset < octets.len);
            assert(octets[set.offset] != set.value);
            try output.write_bytes(octets[0..set.offset]);
            try output.write_byte(set.value);
            try output.write_bytes(octets[set.offset + 1 ..]);
        },
        .truncate => |count| {
            assert(count > 0 and count <= octets.len);
            try output.write_bytes(octets[0 .. octets.len - count]);
        },
        .append => |extra| {
            assert(extra.len > 0);
            try output.write_bytes(octets);
            try output.write_bytes(extra);
        },
    }
}
