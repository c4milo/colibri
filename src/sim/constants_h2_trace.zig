//! The limits of the h2 trace run (https://github.com/c4milo/colibri/issues/75, decision 104),
//! split off `constants.zig` because a hand-written source file stays at or under 500 lines
//! (CLAUDE.md). `constants.zig` exports them as `h2_trace`.
const std = @import("std");
const assert = std.debug.assert;

/// Streams a seed's client opens at most: the model's `N`.
pub const streams_max: u32 = 3;
/// DATA frames a message carries at most: the model's `Content`.
pub const content_max: u32 = 2;
/// Interim heads a response carries at most: the model's `Interims`.
pub const interims_max: u32 = 1;
/// GOAWAY frames the server sends at most: the model's `MaxGoaways`.
pub const goaways_max: u32 = 2;
/// One seed in this many lets neither endpoint reset a stream: the model's `Resets` is FALSE.
pub const no_resets_one_in: u64 = 4;

/// Actions one run draws, at least and at most.
pub const actions_min: u32 = 16;
pub const actions_max: u32 = 96;

/// Octets one direction holds in flight: every frame of every stream, with the preface, SETTINGS
/// and the replies, far below this.
pub const queue_len_max: u32 = 16384;

/// Frames of the model's kinds one direction holds in flight at most. In each direction a stream
/// carries at most its interim heads, one head, its DATA, one trailers section and one RST_STREAM,
/// GOAWAY frames add theirs, and the writer's preface is one more (RFC 9113 §3.4).
pub const frames_per_stream_max: u32 = interims_max + 1 + content_max + 1 + 1;
pub const preface_frames: u32 = 1;
pub const frames_max: u32 = streams_max * frames_per_stream_max + goaways_max + preface_frames;

/// HEADERS frames one direction carries over a run at most: every stream's head, its interim heads
/// and its trailers.
pub const headers_max: u32 = streams_max * (1 + interims_max + 1);

/// Receive calls one delivery makes for each frame of the model's kinds at most. Each such frame
/// takes one call to read it, and a direction holds at most as many frames the model leaves out
/// (SETTINGS, its acknowledgment). Before each read, one more call can find replies owed.
pub const receives_per_frame_max: u32 = 4;

/// Rounds of delivery after the last action, each one way and then the other. A round that moves
/// no octet ends the drain, and a frame answers at most one frame the other way.
pub const drain_rounds_max: u32 = frames_max + 1;
/// Deliveries one round of the drain makes: one to the server, then one to the client.
pub const deliveries_per_round: u32 = 2;

/// The model's states one run keeps, each differing from the one before: the first, at most one
/// after each action, and at most one after each delivery of the drain.
pub const states_max: u32 = 1 + actions_max + deliveries_per_round * drain_rounds_max;

/// Octets of the TLA+ module one seed's trace is written as: 1 MiB.
pub const module_len_max: u32 = 1_048_576;

/// The seeds `sim --h2-trace-write` writes for TLC, and the model's steps TLC may take between two
/// logged states: a delivery reads every frame in flight, each one of the model's steps, and
/// answers each with at most one frame.
pub const written_seeds: u64 = 64;
pub const steps_between_max: u64 = frames_max + frames_max;

comptime {
    assert(streams_max > 0 and actions_min <= actions_max);
    // A stream identifier fits the model's index, and a queue holds every frame of a run.
    assert(frames_max < queue_len_max);
}
