//! The bounds colibri chose for h11, which size memory or bound a loop or a queue. Ask the
//! owner before changing one (CLAUDE.md): the test at the end pins each value.
//! Decision 137 groups them, and `constants.zig` exports this file as `limits`.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");

/// Longest start line colibri reads, in bytes, not counting its CRLF. RFC 9112 §3 places no
/// predefined limit on a request line and RECOMMENDS that every recipient support at least 8000
/// bytes, so this is colibri's policy and meets that floor.
pub const start_line_len_max: u32 = 8192;

/// Bytes of the CR and LF that end each line of a head (RFC 9112 §2.1).
const line_end_len: u32 = 2;

/// Longest request head colibri reads as a server, in bytes: the one leading empty line a request
/// may carry, the longest start line and its CRLF, the largest field section colibri accepts, and
/// the empty line that ends the head. RFC 9110 §5.4 places no predefined limit and lets a server
/// answer 4xx past its own, so this is policy. The owner ruled on 2026-11-18 (decision 166 as
/// amended) the smallest head that holds every section the section limit admits, where 32,768 was
/// the policy before.
pub const request_head_len_max: u32 = line_end_len + start_line_len_max + line_end_len +
    core.constants.limits.field_section_size_max + line_end_len;

/// Longest response head colibri reads as a client, in bytes, as `request_head_len_max` counts
/// it. Policy, as before decision 166 was amended: a client cannot choose its server's headers.
pub const response_head_len_max: u32 = 32768;

/// The longer of the two heads, which sizes what both roles share: the scan of a head and the
/// lines of its field section. `message_scan` bounds each head by its role's own limit.
pub const head_len_max: u32 = @max(request_head_len_max, response_head_len_max);

/// Bytes `message_scan` compares at once when it looks for a line's CR or LF. 16 bytes fill one
/// NEON or SSE2 register, which every arm64 and x86-64 core has.
pub const scan_vector_len: u32 = 16;

/// Longest line colibri reads before a chunk's data, in bytes, not counting its CRLF: the
/// chunk-size and its chunk extensions (RFC 9112 §7.1). RFC 9112 §7.1.1 says a server ought to
/// limit the total length of chunk extensions it accepts and answer 4xx past it, so this is policy.
pub const chunk_line_len_max: u32 = 4096;

/// Longest trailer section colibri reads, in bytes, its closing empty line included
/// (RFC 9112 §7.1.2). A trailer section holds field lines as a head does, so it is bounded as a
/// head is, less the start line.
pub const trailer_len_max: u32 = head_len_max - start_line_len_max;

/// Most requests a client connection has outstanding at once: sent, with no final response yet
/// (RFC 9112 §9.3.2). RFC 9112 places no limit on a pipeline, so this is policy, and it sets the
/// size of the queue `connection_client` keeps (RFC 9112 §9.2).
pub const pipeline_depth_max: u32 = 16;

/// Decoders in a `coding.DefaultPool`: how many messages carrying `gzip` or `deflate` the
/// connections given one pool decode at once (decision 91). RFC 9112 sets no number, so this is
/// policy. Each decoder holds a window of 32,768 bytes (RFC 1951 §2), so the pool costs about
/// that times this, whatever the number of connections.
pub const decoders_default: u32 = 16;

comptime {
    // A head holds its start line, so a start line of the longest length must fit in one.
    assert(head_len_max > start_line_len_max);
    // A head of either role holds a start line of the longest length and a field section of the
    // largest size colibri accepts. A field line's wire form without padding, its name, a colon, a
    // space, its value and a CRLF, is shorter than the size the section counts for it.
    assert(request_head_len_max >= start_line_len_max + core.constants.limits.field_section_size_max);
    assert(response_head_len_max >= start_line_len_max + core.constants.limits.field_section_size_max);
}

test "decision 137: each limit holds the value the owner ruled" {
    // A failure here is a changed limit, which the owner rules on before this test changes.
    const expectEqual = @import("std").testing.expectEqual;
    try expectEqual(8192, start_line_len_max);
    try expectEqual(24582, request_head_len_max);
    try expectEqual(32768, response_head_len_max);
    try expectEqual(32768, head_len_max);
    try expectEqual(16, scan_vector_len);
    try expectEqual(4096, chunk_line_len_max);
    try expectEqual(24576, trailer_len_max);
    try expectEqual(16, pipeline_depth_max);
    try expectEqual(16, decoders_default);
}
