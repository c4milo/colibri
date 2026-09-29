//! The limits of the client trace run (decision 105, design §8 step 17d), split off
//! `constants.zig` because a hand-written source file stays at or under 500 lines (CLAUDE.md).
//! `constants.zig` exports them as `client_trace`.
const std = @import("std");
const assert = std.debug.assert;

/// Exchanges a seed's caller makes at most: the model's `N`.
pub const exchanges_max: u32 = 3;

/// The window the caller makes its exchanges in, and the most a cancel comes after its exchange.
pub const make_window_ns: u64 = 400_000_000;
pub const cancel_after_max_ns: u64 = 300_000_000;
/// One exchange in this many is cancelled.
pub const cancel_one_in: u64 = 5;
/// The most the caller waits after its last exchange before it shuts the origin down.
pub const shutdown_after_max_ns: u64 = 1_500_000_000;

/// Octets of a POST's content at most, past the servers' stream windows for some draws, so a
/// stream can still send content after its response ended. One exchange in `post_one_in` is a
/// POST.
pub const content_len_max: u32 = 393_216;
pub const post_one_in: u64 = 3;

/// The fallback delay the origin is configured with: short, so a slow QUIC loses to TCP within a
/// few round trips.
pub const fallback_delay_ns: u64 = 100_000_000;
/// The one-way delay of the TCP link, and of the network for a QUIC that works.
pub const tcp_delay_ns: u64 = 10_000_000;
/// The delays of a slow QUIC: past the fallback delay each way.
pub const slow_delay_min_ns: u64 = 120_000_000;
pub const slow_delay_max_ns: u64 = 200_000_000;
/// Datagrams a lossy network drops, out of `schedule_denominator`, and the most it drops in a
/// row toward one endpoint.
pub const lossy_drop: u32 = 100;
pub const lossy_drop_run_max: u32 = 3;

/// The most a server waits before it answers or resets a request.
pub const answer_delay_max_ns: u64 = 60_000_000;

/// Design §8 step 17g: one seed in `late_one_in` makes its last exchange this long after the
/// others, around the 30 s idle timeout both QUIC endpoints advertise. Before the client's idle
/// margin the exchange takes the connection that stands; after it, the connection has retired and
/// the exchange opens another (RFC 9114 §5.1).
pub const late_one_in: u64 = 2;
pub const late_gap_min_ns: u64 = 25_000_000_000;
pub const late_gap_max_ns: u64 = 40_000_000_000;
/// One seed in `slow_answer_one_in` has its servers answer this late, past the 30 s idle timeout,
/// so a QUIC connection outlives the wait only with the client's PING (RFC 9000 §10.1.2).
pub const slow_answer_one_in: u64 = 3;
pub const slow_answer_min_ns: u64 = 30_000_000_000;
pub const slow_answer_max_ns: u64 = 45_000_000_000;
/// The window a server's GOAWAY is drawn in, and one seed in this many draws one.
pub const goaway_window_ns: u64 = 600_000_000;
pub const goaway_one_in: u64 = 4;
/// One seed in this many is rough: its servers may refuse and reset requests, and a connection
/// breaks, so no exchange must end in a response.
pub const rough_one_in: u64 = 2;
/// The window after the first exchange is made that a rough seed's connection breaks in, while
/// that exchange is likely in flight.
pub const break_window_ns: u64 = 300_000_000;

/// The longest an origin takes to close once its caller shut it down and its last exchange ended:
/// past a closing period of three Probe Timeouts after their backoffs (RFC 9000 §10.2), and a third
/// of the 30 s idle timeout that ends a connection that never closes.
pub const closing_max_ns: u64 = 10_000_000_000;

/// Instants one run moves through at most. A run ends once the origin reports `closed`: a
/// blocked QUIC's handshake runs until the origin abandons it, and its closing period after.
pub const instants_max: u32 = 20_000;
/// Rounds of receives and sends one instant runs until nothing moves, at most.
pub const settle_rounds_max: u32 = 64;
/// Datagrams one side sends in one round at most.
pub const datagrams_per_round_max: u32 = 64;
/// Octets each direction of the TCP link holds in flight at most.
pub const tcp_queue_len_max: u32 = 1_048_576;
/// Chunks each direction of the TCP link holds in flight at most.
pub const tcp_chunks_max: u32 = 4096;

/// The model's states one run keeps, each differing from the one before.
pub const states_max: u32 = 2048;
/// Octets of the TLA+ module one seed's trace is written as: 2 MiB.
pub const module_len_max: u32 = 2_097_152;
/// The seeds `sim --client-trace-write` writes for TLC, and the model's steps TLC may take
/// between two logged states: an instant can end each exchange, report it, move it and assign
/// it again, and open, close or drain each transport.
pub const written_seeds: u64 = 64;
/// Seeds past those that `sim --client-trace-write` also writes, each one whose run retired a
/// QUIC connection or kept one alive (design §8 step 17g), so TLC checks both idle rules: a QUIC
/// connection carries exchanges in few seeds, since TCP often wins the race.
pub const idle_seeds_written_max: u64 = 16;
pub const steps_between_max: u64 = steps_per_exchange * exchanges_max + steps_per_instant;
const steps_per_exchange: u64 = 6;
const steps_per_instant: u64 = 12;

comptime {
    assert(exchanges_max > 0 and cancel_one_in > 0 and post_one_in > 0);
    // A slow QUIC loses the race to TCP: its first round trip is past the fallback delay.
    assert(slow_delay_min_ns > fallback_delay_ns);
    assert(tcp_delay_ns < fallback_delay_ns);
    assert(late_one_in > 0 and late_gap_min_ns < late_gap_max_ns);
    assert(slow_answer_one_in > 0 and slow_answer_min_ns < slow_answer_max_ns);
}
