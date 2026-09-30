//! The limits of the deadline check (design §8 step 20b, decision 110), split off `constants.zig`
//! because a hand-written source file stays at or under 500 lines (CLAUDE.md). `constants.zig`
//! exports them as `deadline`.
const std = @import("std");
const assert = std.debug.assert;

/// Nanoseconds in a millisecond, the unit a plan's instants are drawn in.
pub const ns_per_ms: u64 = 1_000_000;

/// The seeds `run_check` covers when its caller names none, and which the census test pins.
pub const check_seeds_default: u64 = 64;

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

/// The CONTINUATION frames a hostile h2 peer cuts its field block into, after its HEADERS frame.
pub const continuation_frames: u32 = 16;

/// The pieces a hostile peer's script holds at most: a PING for each gap of the run.
pub const pieces_max: u32 = horizon_ms / hostile_gap_ms_min + pieces_extra;
const pieces_extra: u32 = 256;

/// The octets each direction holds: every request and response of a run, with its framing, and
/// every PING a pinger sends.
pub const stream_len_max: u32 = 32_768;

/// The instants one run visits at most, and the passes one instant takes at most before nothing
/// moves.
pub const instants_max: u32 = 4_096;
pub const passes_per_instant_max: u32 = 64;

/// Octets of a check's trace line, and of a trace: its first line, a line for each answer, and
/// the line of its end.
pub const line_len_max: u32 = 160;
pub const trace_len_max: u32 = line_len_max * (exchanges_max + trace_lines_besides_answers);
const trace_lines_besides_answers: u32 = 2;

comptime {
    assert(honest_gap_ms_min <= honest_gap_ms_max and honest_piece_len_min <= honest_piece_len_max);
    assert(hostile_gap_ms_min <= hostile_gap_ms_max and hostile_piece_len_max > 0);
    assert(pieces_max > horizon_ms / hostile_gap_ms_min);
    assert(exchanges_max > 0 and content_len_max > 0 and continuation_frames > 0);
}
