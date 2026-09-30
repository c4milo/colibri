//! The limits of the deadline check (design §8 step 20b, decision 110), split off `constants.zig`
//! because a hand-written source file stays at or under 500 lines (CLAUDE.md). `constants.zig`
//! exports them as `deadline`.
const std = @import("std");
const assert = std.debug.assert;

/// Nanoseconds in a millisecond, the unit a plan's instants are drawn in, and milliseconds in a
/// second, the unit of a rate.
pub const ns_per_ms: u64 = 1_000_000;
pub const ms_per_s: u64 = 1_000;

/// The seeds `run_check` covers when its caller names none, and which the census test pins.
pub const check_seeds_default: u64 = 256;

/// The simulated time one run lasts at most, in milliseconds: well past every deadline decision
/// 110 names, so a connection the server never ends is still open here.
pub const horizon_ms: u64 = 600_000;

/// The exchanges an honest peer makes.
pub const exchanges_max: u32 = 3;

/// The longest the application takes to answer a request, in milliseconds: past the head deadline,
/// so a request the application holds is one no deadline may end (decision 110).
pub const answer_delay_ms_max: u64 = 25_000;

/// The longest content a response carries to a peer that reads it at once.
pub const content_len_max: u32 = 2_048;

/// The octets the socket between the server and its peer holds that the peer has not read: the
/// server's send buffer, the network and the peer's receive buffer together.
pub const socket_len: u32 = 16_384;

/// The content of an answer to a peer that reads slowly, or not at all: longer than the socket and
/// the server's output together, so the server's sends wait on the peer.
pub const read_content_len_min: u32 = 98_304;
pub const read_content_len_max: u32 = 163_840;

/// An honest slow reader's pace: a piece every gap, at two to four times the plan's minimum send
/// rate.
pub const read_gap_ms_min: u64 = 50;
pub const read_gap_ms_max: u64 = 250;
pub const read_rate_factor_min: u32 = 2;
pub const read_rate_factor_max: u32 = 4;

/// A hostile slow reader's rate in octets a second, so slow that its first window always falls
/// short of the quota under the limits a plan draws (`deadline_plan.zig` asserts it).
pub const slow_read_rate_min: u32 = 8;
pub const slow_read_rate_max: u32 = 24;

/// The gaps between the pieces a slow honest peer sends, in milliseconds, and the octets in each:
/// its requests arrive within half the head deadline.
pub const honest_gap_ms_min: u64 = 20;
pub const honest_gap_ms_max: u64 = 200;
pub const honest_piece_len_min: u32 = 8;
pub const honest_piece_len_max: u32 = 16;

/// The gaps between a hostile peer's pieces or PINGs, in milliseconds, and the octets in each
/// piece: its request head takes longer than any deadline to arrive.
pub const hostile_gap_ms_min: u64 = 1_000;
pub const hostile_gap_ms_max: u64 = 4_000;
pub const hostile_piece_len_max: u32 = 4;

/// How long after its first response a peer that ends slow starts its next head, in milliseconds.
pub const second_head_after_ms: u64 = 1_000;

/// A run's instants start at a base drawn below this, in milliseconds, so the server counts no
/// deadline from the instant 0.
pub const base_ms_max: u64 = 1_000_000;

/// The shortest limit a plan gives the server when it shortens decision 110's defaults, as a
/// server short of connections does, in milliseconds. An honest peer's head takes less to arrive.
pub const short_limit_ms_min: u64 = 5_000;

/// The shortest grace period, the highest minimum rate of a body or a send, and the shortest body
/// cap a plan gives the server when it makes decision 110's defaults stricter. The cap stays past
/// the longest honest upload, `upload_len_max` octets at twice the default minimum rate.
pub const short_rate_ms_min: u64 = 2_000;
pub const short_rate_max: u32 = 2_048;
pub const short_body_ms_min: u64 = 60_000;

/// The shortest linger a plan draws when it makes the defaults stricter, in milliseconds.
pub const short_linger_ms_min: u64 = 500;

/// The octets a window owes at its minimum rate, at least, in the limits a plan draws. A body
/// arrives a unit at a time, an h2 DATA frame of up to 16,384 octets, so an honest peer at twice
/// the rate brings a whole one each window only when the quota is half a unit or more; this is
/// half a unit, and a piece of an honest peer's more.
pub const window_quota_min: u64 = 9_216;

/// The octets of content an uploading peer's request carries at most.
pub const upload_len_max: u32 = 49_152;

/// An honest upload's pace: a piece every gap, at two to four times the plan's minimum body rate.
pub const upload_gap_ms_min: u64 = 50;
pub const upload_gap_ms_max: u64 = 250;
pub const upload_rate_factor_min: u32 = 2;
pub const upload_rate_factor_max: u32 = 4;

/// A slow body's rate in octets a second, below decision 110's minimum of 1,024, and how long it
/// lasts in milliseconds: past the last instant a body deadline can pass at the default limits,
/// a grace period and two windows after the head.
pub const slow_body_rate_min: u32 = 16;
pub const slow_body_rate_max: u32 = 960;
pub const slow_body_ms: u64 = 60_000;

/// A long body's server allows slow bodies, `long_body_rate_min` octets a second, and caps them.
/// The body keeps twice that rate, a piece every gap, for
/// `long_body_ms`: past its cap, which its plan draws from `long_body_cap_ms_min` to
/// `long_body_cap_ms_max`. Its gaps are short, so every window, the shortest included, holds
/// pieces.
pub const long_body_gap_ms_min: u64 = 250;
pub const long_body_gap_ms_max: u64 = 500;
pub const long_body_ms: u64 = 100_000;
pub const long_body_cap_ms_min: u64 = 60_000;
pub const long_body_cap_ms_max: u64 = 90_000;
pub const long_body_rate_min: u32 = 256;
pub const long_body_rate: u32 = long_body_rate_factor * long_body_rate_min;
const long_body_rate_factor: u32 = 2;

/// The octets a hostile peer's script holds: its opening, and a slow or long body with a DATA
/// frame's header on each piece.
pub const script_len_max: u32 = 65_536;

/// The CONTINUATION frames a hostile h2 peer cuts its field block into, after its HEADERS frame.
pub const continuation_frames: u32 = 16;

/// The pieces a hostile peer's script holds at most: a PING for each gap of the run.
pub const pieces_max: u32 = horizon_ms / hostile_gap_ms_min + pieces_extra;
const pieces_extra: u32 = 256;

/// The octets each direction holds: every request and response of a run, with its framing, and
/// every PING a pinger sends.
pub const stream_len_max: u32 = 524_288;

/// The instants one run visits at most, and the passes one instant takes at most before nothing
/// moves.
pub const instants_max: u32 = 4_096;
pub const passes_per_instant_max: u32 = 64;

/// Octets of a check's trace line, and of a trace: its first line, a line for each answer, and
/// the line of its end.
pub const line_len_max: u32 = 256;
pub const trace_len_max: u32 = line_len_max * (exchanges_max + trace_lines_besides_answers);
const trace_lines_besides_answers: u32 = 2;

comptime {
    assert(honest_gap_ms_min <= honest_gap_ms_max and honest_piece_len_min <= honest_piece_len_max);
    assert(hostile_gap_ms_min <= hostile_gap_ms_max and hostile_piece_len_max > 0);
    assert(pieces_max > horizon_ms / hostile_gap_ms_min);
    assert(exchanges_max > 0 and content_len_max > 0 and continuation_frames > 0);
    assert(upload_gap_ms_min <= upload_gap_ms_max and upload_rate_factor_min <= upload_rate_factor_max);
    assert(slow_body_rate_min <= slow_body_rate_max and slow_body_rate_max * slow_body_ms / ms_per_s < script_len_max);
    assert(exchanges_max * (upload_len_max + content_len_max) < stream_len_max);
    assert(short_rate_ms_min <= short_limit_ms_min and long_body_rate_min > 0);
    assert(long_body_cap_ms_max < long_body_ms and long_body_gap_ms_max * 4 <= short_rate_ms_min);
    assert(exchanges_max * read_content_len_max < stream_len_max and read_content_len_min <= read_content_len_max);
    assert(read_gap_ms_min <= read_gap_ms_max and read_rate_factor_min <= read_rate_factor_max);
    assert(slow_read_rate_min <= slow_read_rate_max);
    assert(long_body_rate * long_body_ms / ms_per_s + long_body_ms / long_body_gap_ms_min * data_frame_header_len < script_len_max);
}

/// The header of an h2 DATA frame, which each piece of a body carries in h2 (RFC 9113 §4.1).
const data_frame_header_len: u64 = 9;
