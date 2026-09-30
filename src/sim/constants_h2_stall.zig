//! The limits of the h2 stall check (https://github.com/c4milo/colibri/issues/85), split off
//! `constants.zig` because a hand-written source file stays at or under 500 lines (CLAUDE.md).
//! `constants.zig` exports them as `h2_stall`. The `sim` module imports no protocol module, so the
//! check asserts where these meet h2's own limits (`h2_stall_plan.zig`).
const std = @import("std");
const assert = std.debug.assert;

/// The octets one direction of the transport holds, one of which each seed draws: what the
/// writer's output buffer, both socket buffers and the reader's input buffer hold together. The
/// smallest holds each endpoint's preface and a request, each of the rest is `capacity_factor`
/// times the one before, and the largest holds more than flow control lets a sender have in flight
/// in DATA frames of a few octets.
pub const capacity_min: u32 = 1024;
pub const capacity_factor: u32 = 4;
pub const capacity_count: usize = 5;
pub const capacities: [capacity_count]u32 = values: {
    var values: [capacity_count]u32 = undefined;
    var value: u32 = capacity_min;
    for (&values) |*entry| {
        entry.* = value;
        value *= capacity_factor;
    }
    break :values values;
};
pub const capacity_max: u32 = capacities[capacity_count - 1];

/// Streams a seed's client opens at most. An aligned seed opens at least `aligned_streams_min`,
/// more than h2's reply queue holds, so the WINDOW_UPDATE frames one octet more on each stream owes
/// fill it.
pub const streams_max: u32 = 48;
pub const aligned_streams_min: u32 = 40;

/// Octets of a random seed's request or response body at most.
pub const body_len_max: u32 = 131072;

/// Octets one write call puts in a DATA frame at most, drawn per seed from `[1, chunk_len_max]`. An
/// aligned seed sends its bodies' second parts in chunks of at most `aligned_chunk_len_max`, so its
/// first chunks reach many streams while the queues are small.
pub const chunk_len_max: u32 = 16384;
pub const aligned_chunk_len_max: u32 = 64;

/// Write calls and frames read one endpoint's turn makes at most, each drawn per seed.
pub const writes_per_turn_max: u32 = 64;
pub const frames_per_turn_max: u32 = 64;

/// Rounds one run takes at most, each one turn of each endpoint's reading and writing. A seed that
/// needs more is a violation, `RunTooLong`: a run either finishes or stops moving well before it.
pub const rounds_max: u64 = 1_000_000;

/// The seeds the check's test runs, and the count `sim --h2-stall-check` runs when given none.
/// Few, because an aligned seed moves megabytes: a search for stalls runs thousands in ReleaseSafe.
pub const check_seeds_default: u64 = 16;

/// A seed whose endpoints stop each other, found by such a search: aligned, 46 streams, a 4096-octet
/// transport, and both endpoints writing their own frames before what their connections owe.
pub const stalled_seed: u64 = 0x12c;

/// One seed in this many is aligned; the rest are random.
pub const aligned_one_in: u64 = 2;

/// One endpoint in this many writes what its connection owes before its own frames, as
/// `client.Connection` does; the rest write their own frames first, as `server.Connection` does.
pub const owed_first_one_in: u64 = 2;

comptime {
    assert(capacities.len > 0 and capacity_max >= capacities[0]);
    for (capacities[1..], 0..) |capacity, index| assert(capacity > capacities[index]);
    assert(aligned_streams_min <= streams_max);
    assert(chunk_len_max > 0 and aligned_chunk_len_max > 0 and aligned_chunk_len_max <= chunk_len_max);
    assert(writes_per_turn_max > 0 and frames_per_turn_max > 0 and rounds_max > 0);
    assert(check_seeds_default > 0 and aligned_one_in > 0 and owed_first_one_in > 0);
}
