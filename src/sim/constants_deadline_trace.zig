//! The limits of the deadline trace run (https://github.com/c4milo/colibri/issues/86), split off
//! `constants.zig` because a hand-written source file stays at or under 500 lines (CLAUDE.md).
//! `constants.zig` exports them as `deadline_trace`.
const std = @import("std");
const assert = std.debug.assert;

/// Streams a seed's client opens at most: the model's `StreamCount`.
pub const streams_max: u32 = 3;
/// The octets of DATA a request carries, and a response, at most: past two windows of 65,535, so
/// WINDOW_UPDATE frames go both ways and a window can hold a stream. A request may carry none.
pub const body_len_max: u32 = 150_000;
/// The octets the application offers write_body at once, at least and at most: the model's
/// `ProduceStep`.
pub const produce_step_min: u32 = 1;
pub const produce_step_max: u32 = 40_000;
/// The octets in flight toward one endpoint at once, at least and at most: the model's
/// `ChannelLen`. The least holds one DATA frame of the largest size with its header.
pub const channel_len_min: u32 = 16_393;
pub const channel_len_max: u32 = 70_000;
/// Actions one run draws, at least and at most, before the drain.
pub const actions_min: u32 = 32;
pub const actions_max: u32 = 160;
/// Rounds of the drain after the last action: each round lets every side act once, and a round
/// that changes nothing ends it.
pub const drain_rounds_max: u32 = 200;
/// Actions one round of the drain takes at most: for every stream an upload, a reply and content,
/// and then the client's settling and reading, colibri's reading and its hand-out.
const actions_per_stream: u32 = 3;
const actions_per_round_besides_streams: u32 = 4;
pub const actions_per_round_max: u32 = actions_per_stream * streams_max + actions_per_round_besides_streams;
/// Frames one direction, or colibri's output, holds at once at most. The run fails a seed that
/// holds more: a frame is 9 octets at least, but an honest exchange never piles up that many.
pub const frames_max: u32 = 48;
/// WINDOW_UPDATE frames about streams one endpoint owes at once at most.
pub const stream_owed_max: u32 = 8;
/// Calls to `receive` that one frame's arrival takes at most, and to `write_body` one retry takes.
pub const receives_per_frame_max: u32 = 8;
/// Calls to `write_body` one offer of a response's content makes at most. Each call writes one DATA
/// frame, of one octet and its header at least, into colibri's output of `output_len` octets, which
/// `deadline_trace_world.zig` asserts this covers.
pub const writes_per_offer_max: u32 = 4_917;
/// The model's states one run keeps, each differing from the one before: the first, one after
/// each action and one after each action of the drain.
pub const states_max: u32 = 1 + actions_max + drain_rounds_max * actions_per_round_max;
/// The instant the run starts at, and the time each action takes, in nanoseconds: a run takes a
/// few seconds at most, so no deadline passes.
pub const start_ns: u64 = 1_000_000;
pub const action_ns: u64 = 1_000_000;
/// Octets of the TLA+ module one seed's trace is written as: 8 MiB.
pub const module_len_max: u32 = 8_388_608;
/// The seeds `sim --deadline-trace-write` writes for TLC, and the model's steps TLC may take
/// between two logged states: an arrival reads one frame, a hand-out takes one, and the replies
/// colibri writes and the content it takes in the same call add a few more.
pub const written_seeds: u64 = 32;
pub const steps_between_max: u64 = 24;

/// The time the longest run takes, which `deadline_trace_check.zig` holds under decision 110's
/// shortest default limit.
pub const run_ns_max: u64 = start_ns + (actions_max + drain_rounds_max * actions_per_round_max) * action_ns;

comptime {
    assert(streams_max > 0 and actions_min <= actions_max);
    assert(produce_step_min > 0 and produce_step_min <= produce_step_max);
    assert(channel_len_min <= channel_len_max);
}
