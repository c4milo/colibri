//! h11's limits (design §8 step 15). A limit h11 shares with h2 or h3, such as the field limits,
//! is in `core.constants`; these are the limits only HTTP/1.1's text framing needs.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");

/// Longest start line colibri reads, in octets, not counting its CRLF. RFC 9112 §3 places no
/// predefined limit on a request line and RECOMMENDS that every recipient support at least 8000
/// octets, so this is colibri's policy and meets that floor.
pub const start_line_len_max: u32 = 8192;

/// Longest head colibri reads, in octets: an optional leading empty line, the start line, every
/// field line with its colon, whitespace and CRLF, and the empty line that ends the head. RFC 9110
/// §5.4 places no predefined limit on a field section and lets a server that cannot accept one
/// answer 4xx, so this is policy. It bounds how far `message_scan` looks for the end of a head.
pub const head_len_max: u32 = 32768;

/// Longest line colibri reads before a chunk's data, in octets, not counting its CRLF: the
/// chunk-size and its chunk extensions (RFC 9112 §7.1). RFC 9112 §7.1.1 says a server ought to
/// limit the total length of chunk extensions it accepts and answer 4xx past it, so this is policy.
pub const chunk_line_len_max: u32 = 4096;

/// Longest trailer section colibri reads, in octets, its closing empty line included
/// (RFC 9112 §7.1.2). A trailer section holds field lines as a head does, so it is bounded as a
/// head is, less the start line.
pub const trailer_len_max: u32 = head_len_max - start_line_len_max;

/// The octets RFC 9112 §2.3 gives an HTTP-version: `HTTP-name "/" DIGIT "." DIGIT`.
pub const version_len: u32 = 8;

/// The HTTP-name of RFC 9112 §2.3, which compares case-sensitively.
pub const version_name = "HTTP/";

/// The major version this module speaks (RFC 9112 §2.3).
pub const version_major: u8 = 1;

comptime {
    // A head holds its start line, so a start line of the longest length must fit in one.
    assert(head_len_max > start_line_len_max);
    // A head of the longest length holds a start line of the longest length and a field section
    // of the largest size colibri accepts. A field line's wire form without padding, its name, a
    // colon, a space, its value and a CRLF, is shorter than the size the section counts for it.
    assert(head_len_max >= start_line_len_max + core.constants.field_section_size_max);
    assert(version_name.len + "1.1".len == version_len);
}
