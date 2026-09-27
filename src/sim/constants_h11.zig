//! The limits of the h11 coding check (design §8 step 15c), split off `constants.zig` because a
//! hand-written source file stays at or under 500 lines (CLAUDE.md). `constants.zig` exports them
//! as `h11_coding`.
const std = @import("std");
const assert = std.debug.assert;
const constants = @import("constants.zig");

/// The messages one seed sends.
pub const messages_max: u32 = 4;

/// The longest body, decoded.
pub const body_len_max: u32 = 256;

/// The longest run the plan copies from earlier in a body, and the farthest back it reaches, so
/// DEFLATE finds matches to code.
pub const copy_len_max: u32 = 32;
pub const copy_distance_max: u32 = 64;

/// The longest body, coded: RFC 1951's stored blocks and the containers' headers and trailers never
/// double a body this long, with a margin. The check asserts the encoders' own bound against it.
pub const coded_len_max: u32 = coded_len_factor * body_len_max + coded_len_margin;
const coded_len_factor: u32 = 2;
const coded_len_margin: u32 = 64;

/// The longest chunk of coded octets (RFC 9112 §7.1).
pub const chunk_len_max: u32 = 24;

/// The most octets of room one call to `receive` gets for decoding, drawn from one up.
pub const room_max: u32 = 48;

/// One gzip body in this many is written as two members (RFC 1952 §2.2).
pub const two_members_one_in: u64 = 3;

/// One seed in this many plants a defect in its last message.
pub const defect_one_in: u64 = 2;

/// Octets of a chunk's framing: its size in hex, at most four digits here, CRLF, and the CRLF
/// after its data (RFC 9112 §7.1).
pub const chunk_framing_len_max: u32 = 8;

/// The longest head the plan writes, a request's or a response's.
pub const head_len_max: u32 = 128;

/// The octets of the last chunk and the empty trailer section: `0`, CRLF, CRLF (RFC 9112 §7.1).
pub const last_chunk_len: u32 = 5;

/// The longest message: its head, a chunk for every coded octet at the worst, and the last chunk.
pub const message_len_max: u32 = head_len_max + coded_len_max * (1 + chunk_framing_len_max) + last_chunk_len;

/// The longest stream one seed sends.
pub const stream_len_max: u32 = messages_max * message_len_max;

/// Most octets one trace holds: a record per message, and three more lines: a refusal, and the
/// first and last lines.
pub const trace_len_max: u32 = (messages_max + trace_lines_beside_messages) * constants.trace_record_len_max;
const trace_lines_beside_messages: u32 = 3;

comptime {
    assert(messages_max > 0 and body_len_max > copy_len_max);
    assert(chunk_len_max > 0 and room_max > 0);
    // A chunk's size fits the four hex digits the framing counts.
    assert(chunk_len_max < 1 << 16);
    assert(two_members_one_in > 0 and defect_one_in > 0);
}
