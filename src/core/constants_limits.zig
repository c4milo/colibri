//! The bounds colibri chose for core, which size memory or bound a loop or a queue. Ask the
//! owner before changing one (CLAUDE.md): the test at the end pins each value.
//! Decision 137 groups them, and `constants.zig` exports this file as `limits`.
const std = @import("std");
const assert = std.debug.assert;
const protocol = @import("constants_protocol.zig");

/// Longest field name colibri will emit or accept, in octets. RFC 9110 §5.4 states that HTTP
/// places no predefined limit on a field line, so this is colibri's policy and not a protocol
/// constant. RFC 9110 §5.4 also requires a server that cannot accept what it was sent to answer
/// 4xx rather than truncate, so a local limit is conformant.
pub const field_name_len_max: u32 = 256;

/// Longest field value colibri will emit or accept, in octets. Policy, for the reason above.
pub const field_value_len_max: u32 = 8192;

/// Most field lines in one field section. Policy. A section is a fixed array of this length, so
/// the limit sets its size.
pub const field_count_max: u32 = 128;

/// Largest field section colibri will accept, measured the way both protocols measure it: the sum
/// over field lines of `name_len + value_len + 32`, on the unencoded strings (RFC 9113 §6.5.2,
/// RFC 9114 §4.2.2). colibri advertises this value to the peer and enforces it locally; RFC 9113
/// §10.5.1 states there is no hard limit on field block size, so a peer may exceed it and the
/// decoder must still consume every octet (invariant 10).
pub const field_section_size_max: u32 = 16384;

/// Most TLS records in a row that may carry no application data, in h2 and in h11. A
/// NewSessionTicket, a KeyUpdate and a `user_canceled` alert each yield none and each is
/// legitimate (RFC 9846 §4.7.1, §4.7.3, §6.1), and RFC 9846 §6.1 obliges a receiver to keep
/// reading past a `user_canceled` rather than close. So the peer chooses how much work colibri
/// does for nothing, and one past this bound fails the connection: in h2 with ENHANCE_YOUR_CALM
/// (RFC 9113 §10.5), and in h11 with a close. The owner set it at 32 on 2026-09-20 to match h2's
/// `continuation_count_max`, which bounds the same kind of peer-chosen run.
pub const records_without_data_max: u32 = 32;

/// Most connections one endpoint holds at once. The caller owns every connection struct and places
/// it where it chooses; colibri exposes the struct's size as a comptime constant, allocates none
/// of them and grows nothing (decision 35, invariant 1).
pub const connections_max: u32 = 1024;

/// Most concurrent streams one connection holds at once, in either protocol. h2 advertises it as
/// `SETTINGS_MAX_CONCURRENT_STREAMS`, whose initial value RFC 9113 §6.5.2 leaves unlimited — so
/// an endpoint that does not advertise a value has bounded nothing. QUIC advertises it through
/// `initial_max_streams_bidi` and `initial_max_streams_uni` (RFC 9000 §18.2).
pub const streams_per_connection_max: u32 = 128;

comptime {
    // A fixed array of this many field lines is the section's storage; keep it representable.
    assert(field_count_max > 0);
    assert(connections_max > 0);
    assert(streams_per_connection_max > 0);
}

test "every named limit is non-zero" {
    inline for (.{
        field_name_len_max,
        field_value_len_max,
        field_count_max,
        field_section_size_max,
        connections_max,
        streams_per_connection_max,
    }) |limit| {
        try std.testing.expect(limit > 0);
    }
}

test "decision 137: each limit holds the value the owner ruled" {
    // A failure here is a changed limit, which the owner rules on before this test changes.
    const expectEqual = @import("std").testing.expectEqual;
    try expectEqual(256, field_name_len_max);
    try expectEqual(8192, field_value_len_max);
    try expectEqual(128, field_count_max);
    try expectEqual(16384, field_section_size_max);
    try expectEqual(32, records_without_data_max);
    try expectEqual(1024, connections_max);
    try expectEqual(128, streams_per_connection_max);
}
