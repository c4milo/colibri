//! Limits two or more modules share (docs/design.md §7). Every limit colibri enforces is named
//! here or in its own module's `constants.zig`, and never written inline (CLAUDE.md
//! non-negotiable 4).
//!
//! Several of these exist precisely because an RFC declines to bound something and hands the job
//! to the implementation. Each such limit names the section that declines, so a reader can tell a
//! limit colibri chose from a limit a protocol fixed.
const std = @import("std");
const assert = std.debug.assert;

/// Longest field name colibri will emit or accept, in octets. RFC 9110 §5.4 states that HTTP
/// places no predefined limit on a field line, so this is colibri's policy and not a protocol
/// constant. RFC 9110 §5.4 also requires a server that cannot accept what it was sent to answer
/// 4xx rather than truncate, which is what makes a local limit conformant.
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
    // A field section that could not hold one maximal field line would make the two limits
    // disagree, and the disagreement would surface as a refusal the peer cannot diagnose.
    assert(field_section_size_max >= field_name_len_max + field_value_len_max + 32);
    // The per-line limits must fit the accounting type the size formula uses.
    assert(@as(u64, field_name_len_max) + field_value_len_max + 32 <= std.math.maxInt(u32));
    // A fixed array of this many field lines is the section's storage; keep it representable.
    assert(field_count_max > 0);
    assert(connections_max > 0);
    assert(streams_per_connection_max > 0);
}

test "field_section_size_max admits one maximal field line" {
    const line_size: u64 = @as(u64, field_name_len_max) + field_value_len_max + 32;
    try std.testing.expect(line_size <= field_section_size_max);
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
