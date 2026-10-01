//! The limits of the TCP trace run (https://github.com/c4milo/colibri/issues/79): a
//! `client.Connection` and a `server.Connection` over h2, logged in `spec/tla/h2_connection`'s
//! terms. Split off `constants.zig` because a hand-written source file stays at or under 500 lines
//! (CLAUDE.md). `constants.zig` exports them as `tcp_trace`.
const std = @import("std");
const assert = std.debug.assert;
const h2_trace = @import("constants_h2_trace.zig");

/// Streams a seed's client opens at most: the model's `N`.
pub const streams_max: u32 = 3;
/// DATA frames a message carries at most: the model's `Content`. A request's content goes out
/// whole, as one frame of `request_content_len` octets when its plan gives it any, and each piece
/// of a response's content the server's caller writes is one frame of up to `piece_len` octets.
pub const content_max: u32 = 2;
pub const request_content_len: u32 = 8;
pub const piece_len: u32 = 4;
/// Interim heads a response carries at most: the model's `Interims`.
pub const interims_max: u32 = 1;
/// GOAWAY frames the server sends at most: its caller shuts it down once, the model's
/// `MaxGoaways`.
pub const goaways_max: u32 = 1;
/// One seed in this many lets neither endpoint reset a stream: the model's `Resets` is FALSE.
pub const no_resets_one_in: u64 = 4;
/// One seed in this many runs over TLS, where the client's first flight goes out with its Finished.
pub const tls_one_in: u64 = 2;

/// Actions one run draws after the client's first flight, at least and at most.
pub const actions_min: u32 = 16;
pub const actions_max: u32 = 96;

/// Octets one direction carries over a run at most: the preface, SETTINGS and their
/// acknowledgments, the WINDOW_UPDATE frames and every message's frames, and over TLS the
/// handshake's flights and each record's header and tag, far below this.
pub const stream_len_max: u32 = 16384;

/// HEADERS frames the server writes over a run at most: each response's interim heads, its final
/// head and its trailers.
pub const headers_max: u32 = streams_max * (interims_max + 1 + 1);

/// Calls to `receive` one delivery makes at most. Each takes a frame or more, or reports an event,
/// and a direction holds fewer frames than this.
pub const receives_per_delivery_max: u32 = 256;

/// Rounds of the drain after the last action, each a send and a delivery one way and then the
/// other. A round that changes nothing ends it.
pub const drain_rounds_max: u32 = h2_trace.frames_max + 1;
/// The actions that move one direction's octets: a send and a delivery.
pub const actions_per_direction: u32 = 2;
pub const actions_per_round: u32 = actions_per_direction + actions_per_direction;
/// The actions of a TLS handshake before the client's first flight: the ClientHello's send and
/// delivery, then the server's flight's.
pub const handshake_actions: u32 = actions_per_round;

/// Actions one run takes at most: the first flight's requests, the handshake's actions, the first
/// flight's send and delivery, the actions drawn, and the drain's.
pub const run_actions_max: u32 = streams_max + handshake_actions + actions_per_direction + actions_max + actions_per_round * drain_rounds_max;
/// The model's states one run keeps, each differing from the one before: the first, and at most
/// one after each action.
pub const states_max: u32 = 1 + run_actions_max;
/// Sends one side makes over a run: one action each at most.
pub const sends_max: u32 = run_actions_max;

/// Octets of the TLA+ module one seed's trace is written as: 1 MiB.
pub const module_len_max: u32 = 1_048_576;

/// The seeds `sim --tcp-trace-write` writes for TLC, and the model's steps TLC may take between two
/// logged states. A delivery reads every frame in flight, each one of the model's steps, and the
/// reader answers each with at most one frame, as in the h2 trace. A delivery to the server also
/// writes the server's preface and the final head of each request its caller answers at once.
pub const written_seeds: u64 = 64;
pub const steps_between_max: u64 = h2_trace.steps_between_max + h2_trace.preface_frames + streams_max;

comptime {
    // The run logs its states in the h2 trace's `State`, whose arrays the h2 trace's limits size.
    assert(streams_max <= h2_trace.streams_max and content_max <= h2_trace.content_max);
    assert(interims_max <= h2_trace.interims_max and goaways_max <= h2_trace.goaways_max);
    assert(actions_min <= actions_max and piece_len > 0 and request_content_len > 0);
}
