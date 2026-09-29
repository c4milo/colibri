//! The limits of the content-coding check (design §8 step 17e, decision 101), split off
//! `constants.zig` because a hand-written source file stays at or under 500 lines (CLAUDE.md).
//! `constants.zig` exports them as `content_coding`.
const std = @import("std");
const assert = std.debug.assert;

/// The exchanges one seed makes, each on its own request.
pub const exchanges_max: u32 = 4;

/// The longest content one response carries: past the 64 KiB ring an encoder of the server's pool
/// holds, so a coded response waits for its ring to empty (the owner's ruling of 2026-09-28).
pub const content_len_max: u32 = 81_920;

/// The most octets the server's caller hands `write_body` in one call.
pub const write_len_max: u32 = 16_384;

/// The longest piece either direction delivers at once.
pub const piece_len_max: u32 = 24_576;

/// The octets each direction holds: every response of a seed, coded or not, with its framing.
pub const stream_len_max: u32 = exchanges_max * (content_len_max + response_overhead_max);
/// A response's head and framing, and what coding adds to incompressible content: stored blocks
/// and the containers' headers and trailers (RFC 1951 §3.2.4, RFC 1952 §2.3).
const response_overhead_max: u32 = 16_384;

/// Room for a body the client passes on coded: the content, coded, never passes this.
pub const coded_len_max: u32 = content_len_max + response_overhead_max;

/// The rounds one run takes at most: each moves octets both ways, and a response of the longest
/// content in the shortest pieces takes the most.
pub const rounds_max: u32 = 4096;

/// The seeds `run_check` covers when its caller names none, and which the census test pins.
pub const check_seeds_default: u64 = 32;

/// The chance, one in this many, that a draw takes its rarer branch: a HEAD, a 204 or 206, a body
/// one octet short, or the caller's own Accept-Encoding.
pub const rare_one_in: u32 = 5;

comptime {
    assert(exchanges_max > 0 and content_len_max > 0);
    assert(write_len_max > 0 and piece_len_max > 0);
    assert(stream_len_max > exchanges_max * content_len_max);
    assert(rare_one_in > 1);
}
