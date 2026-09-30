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

/// The longest content a response carries.
pub const content_len_max: u32 = 2_048;

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

/// The shortest grace period and window, the lowest minimum body rate and the shortest body cap a
/// plan gives the server when it shortens decision 110's defaults. The cap stays past the longest
/// honest upload, `upload_len_max` octets at `upload_rate_min`.
pub const short_rate_ms_min: u64 = 2_000;
pub const short_body_rate_min: u32 = 256;
pub const short_body_ms_min: u64 = 60_000;

/// The octets of content an uploading peer's request carries at most.
pub const upload_len_max: u32 = 49_152;

/// An honest upload's pace: a piece every gap, at two to four times decision 110's minimum body
/// rate of 1,024 octets a second.
pub const upload_gap_ms_min: u64 = 50;
pub const upload_gap_ms_max: u64 = 250;
pub const upload_rate_min: u32 = 2_048;
pub const upload_rate_max: u32 = 4_096;

/// A slow body's rate in octets a second, below decision 110's minimum of 1,024, and how long it
/// lasts in milliseconds: past the last instant a body deadline can pass at the default limits,
/// a grace period and two windows after the head.
pub const slow_body_rate_min: u32 = 16;
pub const slow_body_rate_max: u32 = 960;
pub const slow_body_ms: u64 = 60_000;

/// A long body keeps twice the lowest minimum rate a plan draws, a piece every gap, for
/// `long_body_ms`: past its cap, which its plan draws from `long_body_cap_ms_min` to
/// `long_body_cap_ms_max`. Its gaps are short, so every window, the shortest included, holds
/// pieces.
pub const long_body_gap_ms_min: u64 = 250;
pub const long_body_gap_ms_max: u64 = 500;
pub const long_body_ms: u64 = 100_000;
pub const long_body_cap_ms_min: u64 = 60_000;
pub const long_body_cap_ms_max: u64 = 90_000;
pub const long_body_rate: u32 = long_body_rate_factor * short_body_rate_min;
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
pub const stream_len_max: u32 = 196_608;

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
    assert(upload_gap_ms_min <= upload_gap_ms_max and upload_rate_min <= upload_rate_max);
    assert(slow_body_rate_min <= slow_body_rate_max and slow_body_rate_max * slow_body_ms / ms_per_s < script_len_max);
    assert(exchanges_max * (upload_len_max + content_len_max) < stream_len_max);
    assert(short_body_ms_min > upload_len_max * ms_per_s / upload_rate_min);
    assert(short_rate_ms_min <= short_limit_ms_min and short_body_rate_min > 0);
    assert(long_body_cap_ms_max < long_body_ms and long_body_gap_ms_max * 4 <= short_rate_ms_min);
    assert(long_body_rate * long_body_ms / ms_per_s + long_body_ms / long_body_gap_ms_min * data_frame_header_len < script_len_max);
}

/// The header of an h2 DATA frame, which each piece of a body carries in h2 (RFC 9113 §4.1).
const data_frame_header_len: u64 = 9;
