//! The limits of the h3 deadline check (design §8 step 20c, decision 110 as amended), split off
//! `constants.zig` because a hand-written source file stays at or under 500 lines (CLAUDE.md).
//! `constants.zig` exports them as `h3_deadline`.
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

/// QUIC's own idle timeout on both sides, in milliseconds: past the horizon, so the deadlines of
/// decision 110 are what ends a run, and not RFC 9000 §10.1's silence.
pub const quic_idle_timeout_ms: u64 = 1_200_000;

/// The exchanges an honest peer makes.
pub const exchanges_max: u32 = 3;

/// The requests a run holds at most: an honest peer's exchanges, or the streams a peer that
/// floods opens before the server closes its connection.
pub const requests_max: u32 = 128;

/// The longest the application takes to answer a request, in milliseconds: past the head deadline,
/// so a request the application holds is one no deadline may end (decision 110).
pub const answer_delay_ms_max: u64 = 25_000;

/// The longest the application waits between the two halves of an answer it writes in two, in
/// milliseconds: past the first window of a rate, so a response the application holds open is
/// one no deadline may end either (decision 110).
pub const answer_gap_ms_max: u64 = 25_000;

/// The longest content a response carries to a peer that reads it at once.
pub const content_len_max: u32 = 2_048;

/// The content of an answer to a peer that reads slowly, or not at all: many times the credit its
/// stream starts with, so the server's octets wait on the peer.
pub const read_content_len_min: u32 = 98_304;
pub const read_content_len_max: u32 = 163_840;

/// The credit a peer that reads slowly gives each of its streams (RFC 9000 §4.1). QUIC raises a
/// stream's limit once half its window is read, so a small window makes the credit grow in small
/// steps, as the reading does.
pub const reader_stream_window: u64 = 8_192;

/// An honest slow reader's pace: a piece every gap, at two to four times the plan's minimum send
/// rate.
pub const read_gap_ms_min: u64 = 50;
pub const read_gap_ms_max: u64 = 250;
pub const read_rate_factor_min: u32 = 2;
pub const read_rate_factor_max: u32 = 4;

/// A hostile slow reader's rate in octets a second, so slow that its first window always falls
/// short of the quota under the limits a plan draws.
pub const slow_read_rate_min: u32 = 8;
pub const slow_read_rate_max: u32 = 24;

/// A slow link from the server to its peer: it carries four to eight times the plan's minimum
/// send rate, so a peer behind it acknowledges well over the rate, though lost datagrams are
/// sent again. Its queue holds this many datagrams, fewer than the ten QUIC first sends (RFC 9002
/// §7.2), so the link drops some.
pub const link_rate_factor_min: u32 = 4;
pub const link_rate_factor_max: u32 = 8;
pub const link_queue_len: u32 = 8;

/// The octets of content an uploading peer's request carries at most.
pub const upload_len_max: u32 = 49_152;

/// An honest upload's pace: a piece every gap, at two to four times the plan's minimum body rate.
pub const upload_gap_ms_min: u64 = 50;
pub const upload_gap_ms_max: u64 = 250;
pub const upload_rate_factor_min: u32 = 2;
pub const upload_rate_factor_max: u32 = 4;

/// A slow body's rate in octets a second, so far below decision 110's minimum of 1,024 that its
/// first window, the grace period included, falls short of the quota under the limits a plan
/// draws. Its request declares more content than ever arrives.
pub const slow_body_rate_min: u32 = 16;
pub const slow_body_rate_max: u32 = 256;
pub const slow_body_len: u32 = 65_536;

/// The gap between two PINGs, or two pieces of a slow body, in milliseconds.
pub const hostile_gap_ms_min: u64 = 1_000;
pub const hostile_gap_ms_max: u64 = 4_000;

/// A peer that ends slow starts its next head a gap after its first response ended: this long at
/// least, and this long before the idle deadline at the latest, in milliseconds. So the idle
/// deadline finds some of these heads late and answered, and some not yet late.
pub const second_head_after_ms_min: u64 = 1_000;
pub const second_head_before_idle_ms: u64 = 1_000;

/// How long after its first request a peer with many bodies opens its second, in milliseconds.
pub const second_body_after_ms: u64 = 1_000;

/// A peer that floods opens a batch of requests and cancels them, every `flood_gap_ms`, until the
/// server closes its connection: past the server's limit inside one of its periods. A plan draws
/// the requests in a batch, up to `flood_batch_len_max`. A batch of one finds the limit exactly.
pub const flood_batch_len_max: u32 = 4;
pub const flood_gap_ms: u64 = 1;

/// An honest peer whose request heads arrive late: all of a head but its last octet at once, and
/// the last octet this long after, in milliseconds. Twice the longest is no more than the
/// shortest limit a plan draws, so no deadline passes first.
pub const late_head_ms_min: u64 = 500;
pub const late_head_ms_max: u64 = 2_000;

/// A long body's server keeps decision 110's default limits, and caps a body at a span a plan
/// draws from `long_body_cap_ms_min` to `long_body_cap_ms_max`. The peer sends a piece every gap,
/// at `long_body_rate_factor` times the minimum body rate, so every window holds its quota, and
/// the cap passes before the `slow_body_len` octets its request declares have arrived.
pub const long_body_cap_ms_min: u64 = 25_000;
pub const long_body_cap_ms_max: u64 = 30_000;
pub const long_body_rate_factor: u32 = 2;
pub const long_body_gap_ms_min: u64 = 250;
pub const long_body_gap_ms_max: u64 = 500;

/// How long the server's close follows its GOAWAY by at most, in milliseconds: the time the peer
/// takes to acknowledge the GOAWAY, which is the `max_ack_delay` of a peer that names none (RFC
/// 9000 §18.2). The drain deadline, which closes a connection whose peer acknowledges nothing, is
/// far past it.
pub const close_after_goaway_ms_max: u64 = 25;

/// A run's instants start at a base drawn below this, in milliseconds, so the server counts no
/// deadline from the instant 0.
pub const base_ms_max: u64 = 1_000_000;

/// The shortest limit a plan gives the server when it shortens decision 110's defaults, as a
/// server short of connections does, in milliseconds.
pub const short_limit_ms_min: u64 = 5_000;

/// The shortest grace period and the highest minimum rate of a body or a send a plan gives the
/// server when it makes decision 110's defaults stricter.
pub const short_rate_ms_min: u64 = 2_000;
pub const short_rate_max: u32 = 2_048;

/// The octets a window owes at its minimum rate, at least, in the limits a plan draws: past half
/// a unit of 16,384 octets, which `Deadlines.validate_units` requires, and past the credit a
/// reader's stream starts with, so a peer that gives no more falls short.
pub const window_quota_min: u64 = 9_216;

/// The instants one run visits at most, the passes one instant takes at most before nothing
/// moves, and the datagrams one side sends in one pass at most.
pub const instants_max: u32 = 65_536;
pub const passes_per_instant_max: u32 = 64;
pub const datagrams_per_pass_max: u32 = 256;

/// The events the server reports in one pass at most.
pub const events_per_pass_max: u32 = 4_096;

/// Octets of a check's trace line, and of a trace: its first line, a line for each exchange, and
/// the line of its end.
pub const line_len_max: u32 = 256;
pub const trace_len_max: u32 = line_len_max * (exchanges_max + trace_lines_besides_answers);
const trace_lines_besides_answers: u32 = 2;

comptime {
    assert(read_gap_ms_min <= read_gap_ms_max and read_rate_factor_min <= read_rate_factor_max);
    assert(upload_gap_ms_min <= upload_gap_ms_max and upload_rate_factor_min <= upload_rate_factor_max);
    assert(slow_read_rate_min <= slow_read_rate_max and slow_body_rate_min <= slow_body_rate_max);
    assert(hostile_gap_ms_min <= hostile_gap_ms_max and exchanges_max > 0 and content_len_max > 0);
    assert(read_content_len_min <= read_content_len_max and reader_stream_window < window_quota_min);
    assert(short_rate_ms_min <= short_limit_ms_min and quic_idle_timeout_ms > horizon_ms);
    assert(requests_max >= exchanges_max and flood_batch_len_max > 0 and flood_gap_ms > 0);
    assert(late_head_ms_min <= late_head_ms_max and late_head_ms_max * 2 <= short_limit_ms_min);
    assert(long_body_cap_ms_min <= long_body_cap_ms_max and long_body_gap_ms_min <= long_body_gap_ms_max);
    assert(long_body_rate_factor > 1);
    assert(second_head_after_ms_min + second_head_before_idle_ms <= short_limit_ms_min);
    assert(link_rate_factor_min <= link_rate_factor_max and link_queue_len > 0);
    assert(answer_gap_ms_max > 0 and answer_delay_ms_max > 0);
}
