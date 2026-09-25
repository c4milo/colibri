//! The golden corpus as a pure table (decision 26, design §8 steps 1 and 3): what each case is built from
//! and the verdict its decoder must return. `corpus.zig` builds, decodes and describes the cases;
//! `tools/golden.zig` writes them to disk; `golden.zig` checks the files against this table.
//!
//! Valid and invalid cases both, because a parser that accepts everything passes a valid-only
//! corpus. The check of design §8 step 1 asks for one case per varint length, one per Huffman
//! decode error, and RFC 9000 Appendix A.1's sample decodings. The published vectors of RFC 7541
//! Appendix C are here beside them (decision 25).
const wire = @import("wire");
const corpus_h11 = @import("corpus_h11.zig");

pub const Format = enum {
    varint,
    prefixed_integer,
    huffman,
    string_literal,
    /// An HPACK field block, decoded by a fresh `hpack.Decoder` of the case's `capacity`.
    hpack,
    /// The start of a datagram, read by the version-independent reader of RFC 8999 alone
    /// (invariant 22): a long header, and the Supported Version list when it is a Version
    /// Negotiation packet.
    quic_invariant,
    /// A whole datagram, read packet by packet by the version 1 reader (RFC 9000 §17, §12.2), at
    /// an endpoint whose connection IDs are the case's `connection_id_len` octets long.
    quic_packet,
    /// A whole datagram, walked by the version 1 receive path at a client in the case's
    /// `receive_state` (`corpus_receive.zig`). Its verdict is the first packet's discard, or the
    /// connection error the walk returns.
    quic_receive,
    /// A whole HTTP/1.1 request, read by an h11 server: its head, then the body its length names
    /// (`corpus_h11.zig`, design §8 step 15a).
    h11_request,
    /// A whole HTTP/1.1 response, read by an h11 client that asked nothing special.
    h11_response,
};

/// The client a `quic_receive` case's datagram arrives at (`corpus_receive.zig`).
pub const ReceiveState = enum {
    /// Every level readable and the handshake complete.
    complete,
    /// Every level's keys installed and the handshake not complete (RFC 9001 §5.7).
    handshake_pending,
    /// The Initial keys alone (RFC 9001 §4.9).
    initial_only,
    /// A key update answered and not yet acknowledged under the new keys (RFC 9001 §6.2).
    update_unacknowledged,
    /// The previous phase's keys held and the current phase begun at packet 4 (RFC 9001 §6.5).
    current_phase_from_4,
    /// More packets failed than the integrity limit permits (RFC 9001 §6.6).
    integrity_exhausted,
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
    /// Octets of the connection IDs the endpoint reading a quic_packet case issued, which a short
    /// header does not carry (RFC 8999 §5.2). Unused by the other formats.
    connection_id_len: u8 = 0,
    /// The client a quic_receive case's datagram arrives at. Unused by the other formats.
    receive_state: ReceiveState = .complete,
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

/// `case`, read by an endpoint whose connection IDs are `connection_id_len` octets long.
fn at_connection_id_len(connection_id_len: u8, case: Case) Case {
    var result = case;
    result.connection_id_len = connection_id_len;
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

/// A connection ID one octet past the 20 version 1 permits (RFC 9000 §17.2), and one at it.
const connection_id_21 = [_]u8{0xd1} ** 21;
const connection_id_20 = [_]u8{0xd1} ** 20;

/// A long header of version 0x00000002, which no endpoint here knows, with both connection IDs 21
/// octets long. One octet away from version 1, so a mutation can move it there.
const unknown_version_long_ids = [_]u8{ 0xc0, 0x00, 0x00, 0x00, 0x02, 21 } ++ connection_id_21 ++
    [_]u8{21} ++ [_]u8{0x5c} ** 21 ++ [_]u8{ 0x01, 0x02, 0x03 };

/// A Version Negotiation packet offering version 1 and a reserved version (RFC 9000 §15).
const version_negotiation_two = [_]u8{ 0x80, 0, 0, 0, 0, 1, 0xaa, 1, 0xbb, 0, 0, 0, 1, 0x1a, 0x2a, 0x3a, 0x4a };

/// A version 1 Handshake packet: connection IDs of 2 and 1 octets, and a Length of 5.
const handshake_packet = [_]u8{ 0xe0, 0, 0, 0, 1, 2, 0xaa, 0xbb, 1, 0xcc, 5, 1, 2, 3, 4, 5 };

/// RFC 9001 Appendix A.4's Retry packet, as published.
const retry_packet = [_]u8{
    0xff, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0xf0, 0x67, 0xa5, 0x50, 0x2a,
    0x42, 0x62, 0xb5, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x04, 0xa2, 0x65, 0xba,
    0x2e, 0xff, 0x4d, 0x82, 0x90, 0x58, 0xfb, 0x3f, 0x0f, 0x24, 0x96, 0xba,
};

pub const quic_invariant = [_]Case{
    // Invariant 22, RFC 9000 §17.2.1: before the version is known, no connection ID the length
    // octet can carry is refused, because a version 1 rule must not decide whether a Version
    // Negotiation packet is sent.
    accept("quic_invariant_unknown_version_ids_21", .{ .literal = &unknown_version_long_ids }),
    accept("quic_invariant_reserved_version_dcid_21", .{
        .literal = &([_]u8{ 0xc0, 0x1a, 0x2a, 0x3a, 0x4a, 21 } ++ connection_id_21 ++ [_]u8{0}),
    }),
    // RFC 9001 Appendix A.2's client Initial header, as far as RFC 8999 reads it.
    accept("quic_invariant_version_1_client_initial", .{
        .literal = "\xc3\x00\x00\x00\x01\x08\x83\x94\xc8\xf0\x3e\x51\x57\x08\x00\x00\x44\x9e\x00\x00\x00\x02",
    }),
    accept("quic_invariant_version_negotiation", .{ .literal = &version_negotiation_two }),
    // RFC 8999 §6: a packet with no Supported Version, or a cut one, MUST be ignored.
    reject("quic_invariant_version_negotiation_empty", .{
        .literal = &.{ 0x80, 0, 0, 0, 0, 1, 0xaa, 1, 0xbb },
    }, error.NoSupportedVersion),
    reject("quic_invariant_version_negotiation_cut", truncated_from("quic_invariant_version_negotiation"), error.TruncatedSupportedVersion),
    // RFC 8999 §5.1: a connection ID cut short of its length octet.
    reject("quic_invariant_scid_truncated", .{
        .truncated = .{ .case_name = "quic_invariant_unknown_version_ids_21", .drop = 4 },
    }, error.Truncated),
    // RFC 8999 §5: the Header Form bit is clear, so this is not a long header.
    reject("quic_invariant_short_form", .{ .literal = &.{ 0x40, 0, 0, 0, 1, 0, 0 } }, error.WrongForm),
};

pub const quic_packet = [_]Case{
    accept("quic_packet_initial_token", .{
        .literal = &.{ 0xc0, 0, 0, 0, 1, 0, 0, 3, 'a', 'b', 'c', 2, 7, 7 },
    }),
    accept("quic_packet_zero_rtt", .{ .literal = &.{ 0xd0, 0, 0, 0, 1, 0, 0, 2, 7, 7 } }),
    accept("quic_packet_handshake", .{ .literal = &handshake_packet }),
    // RFC 9000 §12.2: two packets in one datagram, each ended by its Length.
    accept("quic_packet_coalesced", .{ .literal = &(handshake_packet ++ handshake_packet) }),
    accept("quic_packet_retry_rfc9001_a4", .{ .literal = &retry_packet }),
    at_connection_id_len(4, accept("quic_packet_short", .{
        .literal = &.{ 0x41, 0xaa, 0xbb, 0xcc, 0xdd, 0x01, 0x02 },
    })),
    accept("quic_packet_version_negotiation", .{ .literal = &version_negotiation_two }),
    // RFC 9000 §17.2.1: a long header of another version is handed over, whatever its
    // connection IDs, so the server can answer it.
    accept("quic_packet_other_version_ids_21", .{ .literal = &unknown_version_long_ids }),
    // RFC 9000 §17.2: 20 octets is the most version 1 permits, and 21 MUST be dropped.
    accept("quic_packet_dcid_20", .{
        .literal = &([_]u8{ 0xc0, 0, 0, 0, 1, 20 } ++ connection_id_20 ++ [_]u8{ 0, 0, 1, 9 }),
    }),
    reject("quic_packet_dcid_21", .{
        .literal = &([_]u8{ 0xc0, 0, 0, 0, 1, 21 } ++ connection_id_21 ++ [_]u8{ 0, 0, 1, 9 }),
    }, error.ConnectionIdTooLong),
    reject("quic_packet_scid_21", .{
        .literal = &([_]u8{ 0xc0, 0, 0, 0, 1, 0, 21 } ++ connection_id_21 ++ [_]u8{ 0, 1, 9 }),
    }, error.ConnectionIdTooLong),
    // RFC 9000 §17.2, §17.3.1: a zero Fixed Bit MUST be discarded, in both header forms.
    reject("quic_packet_long_fixed_bit_clear", .{
        .literal = &.{ 0xa0, 0, 0, 0, 1, 2, 0xaa, 0xbb, 1, 0xcc, 5, 1, 2, 3, 4, 5 },
    }, error.FixedBitClear),
    at_connection_id_len(4, reject("quic_packet_short_fixed_bit_clear", .{
        .literal = &.{ 0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0x01, 0x02 },
    }, error.FixedBitClear)),
    // RFC 9001 Appendix A.2's client Initial header alone: its Length counts 1182 octets that
    // are not here (RFC 9000 §12.2).
    reject("quic_packet_length_past_datagram", .{
        .literal = "\xc3\x00\x00\x00\x01\x08\x83\x94\xc8\xf0\x3e\x51\x57\x08\x00\x00\x44\x9e\x00\x00\x00\x02",
    }, error.LengthPastDatagram),
    // RFC 9000 §17.2.2: a Token Length of 128 over three octets.
    reject("quic_packet_token_past_datagram", .{
        .literal = &.{ 0xc0, 0, 0, 0, 1, 0, 0, 0x40, 0x80, 1, 2, 3 },
    }, error.Truncated),
    // RFC 9000 §17.2.5: fifteen octets after the connection IDs cannot hold the 16-octet tag.
    reject("quic_packet_retry_tag_cut", .{
        .truncated = .{ .case_name = "quic_packet_retry_rfc9001_a4", .drop = 6 },
    }, error.RetryTagMissing),
    // RFC 9000 §17.2.5.2: sixteen octets after them are all tag, which leaves no token.
    reject("quic_packet_retry_token_empty", .{
        .truncated = .{ .case_name = "quic_packet_retry_rfc9001_a4", .drop = 5 },
    }, error.RetryTokenEmpty),
    // RFC 9000 §12.2: a second packet is read by the same rules as the first.
    reject("quic_packet_coalesced_second_refused", .{
        .literal = &(handshake_packet ++ [_]u8{ 0xa0, 0, 0, 0, 1, 0, 0, 1, 9 }),
    }, error.FixedBitClear),
};

/// `case`, received at a client in `state`.
fn in_state(state: ReceiveState, case: Case) Case {
    var result = case;
    result.receive_state = state;
    return result;
}

/// The last octet of a quic_receive packet's 16-octet tag, which names the keys that open it
/// (`corpus_receive.zig`). Any other value is a packet no key opens (RFC 9001 §5.5).
pub const marker_current: u8 = 0x11;
pub const marker_next: u8 = 0x22;
pub const marker_previous: u8 = 0x33;
const marker_none: u8 = 0x44;

/// The connection IDs quic_receive packets carry: the client's own, the server's, and another.
/// One octet each, the least RFC 9000 §17.2 lets colibri issue, so two long headers and their
/// tags fit in one case.
pub const receive_client_id = [_]u8{0x0c};
const receive_server_id = [_]u8{0x5e};
const receive_other_id = [_]u8{0x77};

/// The tag of a quic_receive packet: fifteen octets that say nothing and the marker.
fn receive_tag(marker: u8) [16]u8 {
    return [_]u8{0} ** 15 ++ [_]u8{marker};
}

/// A version 1 Initial packet to the client: no token, a Length of eighteen, the number, one octet
/// of PADDING and the tag (RFC 9000 §17.2.2).
fn receive_initial(dcid: [1]u8, scid: [1]u8, number: u8, marker: u8) [29]u8 {
    return [_]u8{ 0xc0, 0, 0, 0, 1, 1 } ++ dcid ++ [_]u8{1} ++ scid ++ [_]u8{ 0, 18, number, 0 } ++ receive_tag(marker);
}

/// A Handshake packet, which carries no token (RFC 9000 §17.2.4).
fn receive_handshake(dcid: [1]u8, scid: [1]u8, number: u8, marker: u8) [28]u8 {
    return [_]u8{ 0xe0, 0, 0, 0, 1, 1 } ++ dcid ++ [_]u8{1} ++ scid ++ [_]u8{ 18, number, 0 } ++ receive_tag(marker);
}

/// A 1-RTT packet to the client (RFC 9000 §17.3.1).
fn receive_short(number: u8, marker: u8) [20]u8 {
    return [_]u8{0x40} ++ receive_client_id ++ [_]u8{ number, 0 } ++ receive_tag(marker);
}

const receive_first = receive_initial(receive_client_id, receive_server_id, 0, marker_current);

pub const quic_receive = [_]Case{
    accept("quic_receive_initial", .{ .literal = &receive_first }),
    // RFC 9000 §12.2: both packets of a datagram are processed.
    accept("quic_receive_coalesced", .{
        .literal = &(receive_first ++ receive_handshake(receive_client_id, receive_server_id, 0, marker_current)),
    }),
    accept("quic_receive_short", .{ .literal = &receive_short(0, marker_current) }),
    // RFC 9001 §6.2: a packet under the next keys starts an update, which the client answers.
    accept("quic_receive_key_update", .{ .literal = &receive_short(0, marker_next) }),
    // RFC 9001 §6.5: a delayed packet of the previous phase, numbered below the current one's.
    in_state(.current_phase_from_4, accept("quic_receive_previous_below_current", .{
        .literal = &receive_short(3, marker_previous),
    })),
    // RFC 9001 §5.5: a packet that will not open is discarded, not a connection error.
    reject("quic_receive_not_opened", .{
        .literal = &receive_initial(receive_client_id, receive_server_id, 0, marker_none),
    }, error.WouldNotOpen),
    reject("quic_receive_second_not_opened", .{
        .literal = &(receive_first ++ receive_handshake(receive_client_id, receive_server_id, 0, marker_none)),
    }, error.WouldNotOpen),
    // RFC 9000 §12.2: a later packet with another Destination Connection ID is ignored.
    reject("quic_receive_other_connection", .{
        .literal = &(receive_first ++ receive_handshake(receive_other_id, receive_server_id, 0, marker_current)),
    }, error.OtherConnection),
    // RFC 9000 §7.2: a Source Connection ID other than the first the client accepted.
    reject("quic_receive_other_source", .{
        .literal = &(receive_first ++ receive_handshake(receive_client_id, receive_other_id, 0, marker_current)),
    }, error.OtherSource),
    // RFC 9000 §12.3: a packet number already processed in the space.
    reject("quic_receive_duplicate", .{ .literal = &(receive_first ++ receive_first) }, error.AlreadyProcessed),
    // RFC 9001 §4.9: a level whose keys the client does not hold.
    in_state(.initial_only, reject("quic_receive_handshake_without_keys", .{
        .literal = &receive_handshake(receive_client_id, receive_server_id, 0, marker_current),
    }, error.NoKeys)),
    // RFC 9001 §5.7: no 1-RTT packet is read before the handshake completes.
    in_state(.handshake_pending, reject("quic_receive_short_before_complete", .{
        .literal = &receive_short(0, marker_current),
    }, error.NoKeys)),
    // RFC 9000 §17.3.1: a zero Fixed Bit leaves nothing to say where the packet ends.
    reject("quic_receive_unreadable_header", .{
        .literal = &([_]u8{0x00} ++ receive_client_id ++ [_]u8{ 0, 0 } ++ receive_tag(marker_current)),
    }, error.UnreadableHeader),
    // RFC 9000 §12.2: a Retry carries no Length and is not a packet this walk reads.
    reject("quic_receive_retry", .{ .literal = &retry_packet }, error.NotForThisWalk),
    // RFC 9001 §6.2: a second update before the first was acknowledged.
    in_state(.update_unacknowledged, reject("quic_receive_update_twice", .{
        .literal = &receive_short(0, marker_next),
    }, error.ConsecutiveKeyUpdate)),
    // RFC 9001 §6.4: old keys opened a packet numbered above one the new keys opened.
    in_state(.current_phase_from_4, reject("quic_receive_old_above_current", .{
        .literal = &receive_short(6, marker_previous),
    }, error.OldKeysAboveCurrentPhase)),
    // RFC 9001 §6.6: past the integrity limit the connection closes.
    in_state(.integrity_exhausted, reject("quic_receive_integrity_exhausted", .{
        .literal = &receive_first,
    }, error.AeadLimitReached)),
};

pub const all = [_]struct { format: Format, cases: []const Case }{
    .{ .format = .varint, .cases = &varint },
    .{ .format = .prefixed_integer, .cases = &prefixed_integer },
    .{ .format = .huffman, .cases = &huffman },
    .{ .format = .string_literal, .cases = &string_literal },
    .{ .format = .hpack, .cases = &hpack },
    .{ .format = .quic_invariant, .cases = &quic_invariant },
    .{ .format = .quic_packet, .cases = &quic_packet },
    .{ .format = .quic_receive, .cases = &quic_receive },
    .{ .format = .h11_request, .cases = &corpus_h11.request },
    .{ .format = .h11_response, .cases = &corpus_h11.response },
};
