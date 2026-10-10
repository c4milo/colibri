//! The limits of the endpoint check (design §8 step 21b.5, decision 119), split off `constants.zig`
//! because a hand-written source file stays at or under 500 lines (CLAUDE.md). `constants.zig`
//! exports them as `endpoint`.
const std = @import("std");
const assert = std.debug.assert;
const deadline = @import("constants_deadline.zig");
const h3_deadline = @import("constants_h3_deadline.zig");

/// Nanoseconds in a millisecond, the unit a run's instants are counted in.
pub const ns_per_ms: u64 = 1_000_000;

/// The seeds `run_check` covers when its caller names none, and which the census test pins.
pub const check_seeds_default: u64 = 128;

/// The simulated time one run lasts at most, in milliseconds: well past every deadline decision
/// 110 names, so each connection the endpoint serves ends before it.
pub const horizon_ms: u64 = 600_000;

/// A run's instants start at a base drawn below this, in milliseconds, so the endpoint counts no
/// deadline from the instant 0.
pub const base_ms_max: u64 = 1_000_000;

/// The slots of each kind the run's endpoint holds, and the peers of each kind a seed draws: more
/// peers than slots, so a slot is freed and taken again.
pub const tcp_slots: usize = 2;
pub const quic_slots: usize = 2;
pub const tcp_peers: usize = 3;
pub const quic_peers: usize = 3;

/// The octets each QUIC connection holds unread, as the test-only UDP server sizes it. The
/// connection's credit follows it.
pub const receive_pool_len: usize = 65_536;

/// QUIC's own idle timeout, in milliseconds: past the horizon, so decision 110's deadlines end a
/// connection, and not RFC 9000 §10.1's silence.
pub const quic_idle_timeout_ms: u64 = 1_200_000;

/// The instant a peer arrives at, from the start of the run, in milliseconds at most.
pub const arrive_ms_max: u64 = 20_000;

/// One seed in this many shuts the endpoint down, at an instant in `[shutdown_ms_min,
/// shutdown_ms_max]`.
pub const shutdown_one_in: u64 = 4;
pub const shutdown_ms_min: u64 = 30_000;
pub const shutdown_ms_max: u64 = 120_000;

/// One honest or silent TCP peer in this many runs TLS.
pub const tls_one_in: u64 = 2;

/// One honest peer in this many cancels one of its requests, and one peer in this many closes its
/// connection early: a TCP peer only when it is honest, a QUIC peer whatever it does.
pub const resetting_one_in: u64 = 4;
pub const early_closing_one_in: u64 = 6;

/// How long after its request a resetting peer cancels it, and how long after its start an
/// early-closing peer closes, in milliseconds.
pub const reset_after_ms_max: u64 = 2_000;
pub const close_after_ms_max: u64 = 5_000;

/// The ports peers send from, the first and one more for each peer after it.
pub const port_first: u16 = 50_000;

/// What the program answers a request with: content of one of three tiers, drawn out of
/// `answer_tiers`. Draws below `answer_small_below` are small, one equal to `answer_medium_draw`
/// medium, and the rest long. A long answer passes h2's first window of 65,535 octets and h3's
/// credit, so the response waits for room.
pub const answer_tiers: u64 = 4;
pub const answer_small_below: u64 = 2;
pub const answer_medium_draw: u64 = 2;
pub const answer_small_len_max: u32 = 2_048;
pub const answer_medium_len_min: u32 = 2_049;
pub const answer_medium_len_max: u32 = 16_384;
pub const answer_long_len_min: u32 = 65_537;
pub const answer_long_len_max: u32 = 98_304;

/// The pieces the program writes an answer's content in: the answer's longest piece is drawn in
/// `[piece_len_min, piece_len_max]`, and each piece from that over `piece_len_divisor` to it.
pub const piece_len_min: u32 = 512;
pub const piece_len_max: u32 = 16_384;
pub const piece_len_divisor: u32 = 4;

/// The pieces of the longest answer at the shortest piece, at most: what one answer's writes are
/// bounded by.
pub const pieces_max: u32 = answer_long_len_max / (piece_len_min / piece_len_divisor) + 1;

/// One answer over h2 or h3 in this many ends with a trailer section, and one in this many is
/// cancelled by the program after `[0, cancel_after_pieces_max]` pieces, 0 meaning before its head.
pub const trailers_one_in: u64 = 8;
pub const cancel_one_in: u64 = 8;
pub const cancel_after_pieces_max: u64 = 3;

/// One answer in this many starts up to `answer_delay_ms_max` after its request's head, so a peer
/// that cancels its request can do so while it is open.
pub const answer_delay_one_in: u64 = 2;
pub const answer_delay_ms_max: u64 = 3_000;

/// One request in this many keeps the word 0, and one body event in this many sets a new word.
pub const word_zero_one_in: u64 = 8;
pub const reword_one_in: u64 = 16;

/// One pass in this many makes a call by an id or a handle that names nothing any more.
pub const stale_call_one_in: u64 = 8;

/// The octets a stale call passes as a socket's read.
pub const stale_octets_len: usize = 8;

/// The octets each direction of a TCP peer's socket holds over the run: what a peer writes, at
/// most its script or its requests with their uploads, and what the endpoint writes, at most the
/// longest answer to each exchange with its framing.
pub const to_server_len: u32 = 262_144;
pub const to_client_len: u32 = 524_288;

/// Octets of framing an answer carries at most beside its content: h2's frame headers and TLS's
/// record overhead, each at most this much per 512 octets, and its head.
pub const answer_slack_len: u32 = 16_384;

/// Octets the endpoint writes to a TCP peer beside its answers: the TLS handshake, h2's SETTINGS,
/// PING replies, resets and GOAWAY, at most.
pub const server_output_slack_len: u32 = 65_536;

/// Octets a peer writes beside its script or its requests' content: request heads, frame
/// headers, records and acknowledgments, at most.
pub const peer_output_slack_len: u32 = 65_536;

/// The requests, the connections and the instants one run holds or visits at most, and the
/// passes one instant takes at most before nothing moves.
pub const requests_max: u32 = 1_024;
pub const handles_max: u32 = 16;
pub const instants_max: u32 = 131_072;
pub const passes_per_instant_max: u32 = 64;

/// The events, the datagrams and the `receive` calls with one socket's octets one pass makes at
/// most.
pub const events_per_pass_max: u32 = 4_096;
pub const datagrams_per_pass_max: u32 = 256;
pub const receives_per_stream_max: u32 = to_server_len + events_per_pass_max;

/// The `send_stream` calls one `send` event takes at most: each fills a buffer the size of the
/// endpoint's output, of which the peer's socket holds this many.
pub const sends_per_event_max: u32 = 64;

/// The salts each stream of draws is seeded with beside the seed: the endpoint's, each peer's
/// and the program's, so no two streams draw the same values.
pub const server_salt: u64 = 0x5e5e_5e5e_5e5e_5e5e;
pub const peer_salt: u64 = 0x9e9e_9e9e_9e9e_9e9e;
pub const program_salt: u64 = 0x7a7a_7a7a_7a7a_7a7a;

/// Octets of a check's trace line, and of a trace: its first line, a line for each peer, the
/// line of its totals and a violation line.
pub const line_len_max: u32 = 512;
pub const trace_lines_max: u32 = 12;
pub const trace_len_max: u32 = line_len_max * trace_lines_max;

comptime {
    // Design §8 step 21b.5: more peers than slots, so each kind of slot is taken again by a later
    // peer.
    assert(tcp_peers > tcp_slots and quic_peers > quic_slots);
    assert(quic_idle_timeout_ms > horizon_ms and shutdown_ms_min <= shutdown_ms_max);
    assert(answer_small_below < answer_tiers and answer_medium_draw < answer_tiers);
    assert(answer_small_len_max < answer_medium_len_min and answer_medium_len_max < answer_long_len_min);
    assert(answer_long_len_min <= answer_long_len_max and piece_len_min <= piece_len_max);
    assert(piece_len_min / piece_len_divisor > 0);
    // A hostile peer's script, or an honest peer's requests and their content, fit the socket
    // toward the endpoint.
    assert(to_server_len >= @max(deadline.script_len_max, deadline.exchanges_max * deadline.upload_len_max) + peer_output_slack_len);
    assert(to_server_len >= h3_deadline.slow_body_len);
    // Every answer to every exchange of a peer fits the socket toward it.
    assert(to_client_len >= deadline.exchanges_max * (answer_long_len_max + answer_slack_len) + server_output_slack_len);
    // Every request the peers can open: each TCP peer's flood of streams, and each QUIC peer's.
    assert(requests_max >= tcp_peers * deadline.many_streams_len + quic_peers * h3_deadline.requests_max);
    // A connection for each peer of each kind, and more.
    assert(handles_max >= tcp_peers + quic_peers);
    assert(trace_lines_max >= tcp_peers + quic_peers + 4);
}
