//! What one seed of the h2 stall check (https://github.com/c4milo/colibri/issues/85) runs: the
//! octets each direction of the transport holds, the streams the client opens, each message's body,
//! and how much one endpoint's turn reads and writes.
//!
//! A seed is random or aligned:
//!   - random: bodies of any length up to `body_len_max`, sent in chunks of any size;
//!   - aligned: every body goes in two parts. The first part is one octet short of the credit a
//!     receiver gathers before it owes a WINDOW_UPDATE on a stream (`window.Receiver`), and neither
//!     endpoint sends a second part before it has sent every first part. The first octets of the
//!     second parts then owe the receiver one WINDOW_UPDATE on each stream, and there are more
//!     streams than h2's reply queue holds. The second parts go in chunks of a few octets, so they
//!     reach many streams while the transport is still filling.
const std = @import("std");
const assert = std.debug.assert;
const h2 = @import("h2");
const sim = @import("sim");

const Random = sim.Random;
const limits = sim.constants.h2_stall;

/// Which of the two kinds of seed the file header describes.
pub const Shape = enum { random, aligned };

/// Which endpoints write what their connection owes before their own frames: both, one, or neither.
pub const Order = enum { owed_first, mixed, frames_first };

/// Octets of an aligned body's first part: one short of h2's WINDOW_UPDATE threshold.
pub const aligned_first_len: u32 = h2.constants.window_update_threshold - 1;

pub const Plan = struct {
    shape: Shape,
    /// Octets each direction of the transport holds: one of `limits.capacities`.
    capacity: u32,
    /// Streams the client opens: identifiers 1, 3, 5 and on (RFC 9113 §5.1.1).
    streams: u32,
    /// Each stream's request and response body, in octets. Index 0 is stream 1, and the entries
    /// past `streams` are 0.
    request_len: [limits.streams_max]u32,
    response_len: [limits.streams_max]u32,
    /// Octets of each body's first part: `aligned_first_len` in an aligned seed, and 0 in a random
    /// one, whose bodies go in one part.
    first_len: u32,
    /// Octets a write call puts in a DATA frame at most, in a random seed's bodies and an aligned
    /// seed's second parts. An aligned seed's first parts go in frames as large as the room allows.
    chunk_len: u32,
    /// Write calls, and frames read, one endpoint's turn makes at most.
    writes_per_turn: u32,
    frames_per_turn: u32,
    /// Whether each endpoint's writing turn writes what its connection owes before its own frames,
    /// as `client.Connection` does, or after them, as `server.Connection`'s `respond` and
    /// `write_body` leave it to `send`.
    client_owed_first: bool,
    server_owed_first: bool,

    /// Draws a seed's plan.
    pub fn draw(plan: *Plan, random: *Random) void {
        plan.shape = if (random.below(limits.aligned_one_in) == 0) .aligned else .random;
        plan.capacity = limits.capacities[@intCast(random.below(limits.capacities.len))];
        plan.writes_per_turn = @intCast(random.between(1, limits.writes_per_turn_max));
        plan.frames_per_turn = @intCast(random.between(1, limits.frames_per_turn_max));
        plan.client_owed_first = random.below(limits.owed_first_one_in) == 0;
        plan.server_owed_first = random.below(limits.owed_first_one_in) == 0;
        plan.request_len = @splat(0);
        plan.response_len = @splat(0);
        switch (plan.shape) {
            .random => plan.draw_random(random),
            .aligned => plan.draw_aligned(random),
        }
        assert(plan.streams > 0 and plan.streams <= limits.streams_max);
        assert(plan.chunk_len > 0 and plan.chunk_len <= limits.chunk_len_max);
    }

    /// Which endpoints write what they owe first.
    pub fn order(plan: *const Plan) Order {
        if (plan.client_owed_first and plan.server_owed_first) return .owed_first;
        if (!plan.client_owed_first and !plan.server_owed_first) return .frames_first;
        return .mixed;
    }

    /// The octets of a body of `body_len` octets that its sender sends before any second part: the
    /// first part in an aligned seed, and the whole body in a random one.
    pub fn first_part_len(plan: *const Plan, body_len: u32) u32 {
        return if (plan.shape == .aligned) @min(plan.first_len, body_len) else body_len;
    }

    fn draw_random(plan: *Plan, random: *Random) void {
        plan.streams = @intCast(random.between(1, limits.streams_max));
        plan.first_len = 0;
        plan.chunk_len = @intCast(random.between(1, limits.chunk_len_max));
        for (0..plan.streams) |index| {
            plan.request_len[index] = @intCast(random.between(0, limits.body_len_max));
            plan.response_len[index] = @intCast(random.between(0, limits.body_len_max));
        }
    }

    fn draw_aligned(plan: *Plan, random: *Random) void {
        plan.streams = @intCast(random.between(limits.aligned_streams_min, limits.streams_max));
        plan.first_len = aligned_first_len;
        plan.chunk_len = @intCast(random.between(1, limits.aligned_chunk_len_max));
        // Each second part is at least one octet, which owes the receiver its WINDOW_UPDATE.
        for (0..plan.streams) |index| {
            plan.request_len[index] = aligned_first_len + @as(u32, @intCast(random.between(1, h2.constants.window_update_threshold)));
            plan.response_len[index] = aligned_first_len + @as(u32, @intCast(random.between(1, h2.constants.window_update_threshold)));
        }
    }
};

comptime {
    // An aligned seed opens more streams than the reply queue holds, and every seed's streams fit
    // what a colibri server advertises as SETTINGS_MAX_CONCURRENT_STREAMS (RFC 9113 §5.1.2).
    assert(limits.aligned_streams_min > h2.constants.stream_replies_max);
    assert(limits.streams_max <= h2.constants.concurrent_streams_max);
    // A chunk fits one frame colibri sends (RFC 9113 §4.2).
    assert(limits.chunk_len_max <= h2.constants.frame_size_max);
}

const testing = std.testing;

/// The seeds the plan's test draws. Test-only.
const test_seeds: u64 = 64;

test "an aligned plan opens more streams than the reply queue holds, each body one octet past a first part" {
    var plan: Plan = undefined;
    var aligned_seen = false;
    var random_seen = false;
    for (0..test_seeds) |seed| {
        var random = Random.init(seed);
        plan.draw(&random);
        switch (plan.shape) {
            .aligned => {
                aligned_seen = true;
                try testing.expect(plan.streams > h2.constants.stream_replies_max);
                for (0..plan.streams) |index| try testing.expect(plan.request_len[index] > aligned_first_len);
            },
            .random => random_seen = true,
        }
        for (plan.streams..limits.streams_max) |index| try testing.expectEqual(0, plan.response_len[index]);
    }
    try testing.expect(aligned_seen and random_seen);
}
