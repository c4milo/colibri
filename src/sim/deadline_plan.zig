//! One seed's plan for the deadline check (design §8 step 20b, decision 110): the protocol, how the
//! peer behaves, the server's limits, and when the application answers each request it reads.
//!
//! The peers are decision 110's slow and hostile ones, with honest ones beside them that no
//! deadline may end: a peer that makes its exchanges at once, one whose octets arrive in small
//! pieces over a few seconds, and one that uploads content at twice decision 110's minimum body
//! rate or more.
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");
const server = @import("server");

const Random = sim.Random;
const limits = sim.constants.deadline;

pub const Protocol = enum { h11, h2 };

/// How the peer behaves.
pub const Peer = enum {
    /// colibri's client: makes its exchanges at once, reads every response, then sends nothing.
    honest,
    /// colibri's client, its octets delivered in small pieces a short gap apart, so its requests
    /// take seconds to arrive and none takes half the head deadline.
    slow_honest,
    /// colibri's client, making its exchanges one at a time with content in each request, its
    /// octets delivered at two to four times decision 110's minimum body rate. A client that
    /// uploads on several h2 streams at once shares its link between them, so each stream here
    /// has the whole link.
    upload,
    /// Opens the connection and sends nothing.
    silent,
    /// Sends its first request head in pieces too slow for any deadline: an h11 head a few octets
    /// at a time, or an h2 field block in CONTINUATION frames.
    slow_head,
    /// Makes one exchange, then sends its next request head as `slow_head` does.
    slow_second_head,
    /// h2 alone: sends its preface and SETTINGS, then PINGs and nothing else.
    pinger,
    /// Makes one exchange, then PINGs and nothing else. h11 has no PING, so in h11 it makes its
    /// exchange and sends nothing more.
    idle_pinger,
    /// Sends a whole request head, then its body at under decision 110's minimum rate.
    slow_body,
    /// Sends a whole request head, then its body at twice the plan's minimum rate for longer than
    /// the plan's cap on a body, which it shortens so the cap passes first.
    long_body,
};

pub const Plan = struct {
    protocol: Protocol,
    peer: Peer,
    /// The instant the run starts at, in milliseconds.
    base_ms: u64,
    /// The server's limits: decision 110's defaults, or shorter ones.
    deadlines: server.Deadlines,
    /// The exchanges the peer makes whole: every one of an honest peer's, and the first one of a
    /// peer that ends slow.
    exchanges_len: u8,
    /// The gap between two pieces, or two PINGs, in milliseconds.
    gap_ms: u64,
    /// The octets in one piece.
    piece_len: u32,
    /// The content each request of an uploading peer carries.
    upload_len: [limits.exchanges_max]u32,
    /// The rate a slow body arrives at, in octets a second.
    body_rate: u32,
    /// How long the application takes to answer each request, from the instant its body ended.
    answer_delay_ms: [limits.exchanges_max]u64,
    /// The content of each response.
    content_len: [limits.exchanges_max]u32,

    /// Whether colibri's client plays the peer.
    pub fn honest(plan: *const Plan) bool {
        return plan.peer == .honest or plan.peer == .slow_honest or plan.peer == .upload;
    }

    /// Whether the peer's octets arrive a piece at a time.
    pub fn paced(plan: *const Plan) bool {
        return plan.peer == .slow_honest or plan.peer == .upload;
    }
};

/// The protocols and the peers in the order `draw` picks from.
const protocols = std.enums.values(Protocol);
const peers = std.enums.values(Peer);

/// One plan in this many shortens the server's limits.
const short_limits_one_in: u64 = 4;

pub fn draw(random: *Random) Plan {
    const protocol = protocols[random.below(protocols.len)];
    var peer = peers[random.below(peers.len)];
    // A PING is an h2 frame, so an h11 pinger is a silent peer.
    if (peer == .pinger and protocol == .h11) peer = .silent;
    var plan: Plan = .{
        .protocol = protocol,
        .peer = peer,
        .base_ms = random.below(limits.base_ms_max),
        .deadlines = if (peer == .long_body) long_body_deadlines(random) else draw_deadlines(random),
        .exchanges_len = exchanges_of(peer, random),
        .gap_ms = 0,
        .piece_len = 0,
        .upload_len = @splat(0),
        .body_rate = 0,
        .answer_delay_ms = @splat(0),
        .content_len = @splat(0),
    };
    draw_pace(&plan, random);
    for (0..limits.exchanges_max) |index| {
        plan.answer_delay_ms[index] = random.below(limits.answer_delay_ms_max + 1);
        plan.content_len[index] = @intCast(random.below(limits.content_len_max + 1));
        if (peer == .upload) plan.upload_len[index] = @intCast(random.between(1, limits.upload_len_max));
    }
    assert(plan.exchanges_len <= limits.exchanges_max);
    return plan;
}

/// Decision 110's defaults, or in one plan of `short_limits_one_in` shorter ones, as a server
/// short of connections sets.
fn draw_deadlines(random: *Random) server.Deadlines {
    if (random.below(short_limits_one_in) != 0) return .{};
    return draw_short_deadlines(random);
}

fn draw_short_deadlines(random: *Random) server.Deadlines {
    const defaults = server.constants;
    return .{
        .first_request_ns = shorter_ns(random, limits.short_limit_ms_min, defaults.first_request_timeout_ns),
        .idle_ns = shorter_ns(random, limits.short_limit_ms_min, defaults.idle_timeout_ns),
        .head_ns = shorter_ns(random, limits.short_limit_ms_min, defaults.head_timeout_ns),
        .body_rate_min = @intCast(random.between(limits.short_body_rate_min, defaults.body_rate_min)),
        .rate_grace_ns = shorter_ns(random, limits.short_rate_ms_min, defaults.rate_grace_ns),
        .rate_window_ns = shorter_ns(random, limits.short_rate_ms_min, defaults.rate_window_ns),
        .body_ns = shorter_ns(random, limits.short_body_ms_min, defaults.body_timeout_ns),
    };
}

/// The shortened limits a long body runs under: the lowest minimum rate a plan draws, and a cap
/// its body outlasts.
fn long_body_deadlines(random: *Random) server.Deadlines {
    var deadlines = draw_short_deadlines(random);
    deadlines.body_rate_min = limits.short_body_rate_min;
    deadlines.body_ns = random.between(limits.long_body_cap_ms_min, limits.long_body_cap_ms_max) * limits.ns_per_ms;
    return deadlines;
}

/// A limit of whole milliseconds, from `min_ms` to the default.
fn shorter_ns(random: *Random, min_ms: u64, default_ns: u64) u64 {
    const limit_ms = random.between(min_ms, default_ns / limits.ns_per_ms);
    return limit_ms * limits.ns_per_ms;
}

fn exchanges_of(peer: Peer, random: *Random) u8 {
    return switch (peer) {
        .honest, .slow_honest, .upload => @intCast(random.between(1, limits.exchanges_max)),
        .slow_second_head, .idle_pinger => 1,
        .silent, .slow_head, .pinger, .slow_body, .long_body => 0,
    };
}

/// The gap and the piece length: a slow honest peer's are small, an upload's carry at least twice
/// the minimum body rate, and a hostile one's are large, or carry a body under that rate.
fn draw_pace(plan: *Plan, random: *Random) void {
    switch (plan.peer) {
        .honest, .silent => {},
        .slow_honest => {
            plan.gap_ms = random.between(limits.honest_gap_ms_min, limits.honest_gap_ms_max);
            plan.piece_len = @intCast(random.between(limits.honest_piece_len_min, limits.honest_piece_len_max));
        },
        .upload => {
            plan.gap_ms = random.between(limits.upload_gap_ms_min, limits.upload_gap_ms_max);
            const rate = random.between(limits.upload_rate_min, limits.upload_rate_max);
            // Rounded up, so the pace is the rate or more.
            plan.piece_len = @intCast((rate * plan.gap_ms + limits.ms_per_s - 1) / limits.ms_per_s);
        },
        .slow_head, .slow_second_head, .pinger, .idle_pinger => {
            plan.gap_ms = random.between(limits.hostile_gap_ms_min, limits.hostile_gap_ms_max);
            plan.piece_len = @intCast(random.between(1, limits.hostile_piece_len_max));
        },
        .slow_body => {
            plan.gap_ms = random.between(limits.hostile_gap_ms_min, limits.hostile_gap_ms_max);
            plan.body_rate = @intCast(random.between(limits.slow_body_rate_min, limits.slow_body_rate_max));
            // Rounded down, so the pace is the rate or less.
            plan.piece_len = @intCast(@max(1, plan.body_rate * plan.gap_ms / limits.ms_per_s));
        },
        .long_body => {
            plan.gap_ms = random.between(limits.long_body_gap_ms_min, limits.long_body_gap_ms_max);
            plan.body_rate = limits.long_body_rate;
            plan.piece_len = @intCast(plan.body_rate * plan.gap_ms / limits.ms_per_s);
        },
    }
}

/// The instant a hostile peer's body stops, in milliseconds.
pub fn body_end_ms(plan: *const Plan) u64 {
    return if (plan.peer == .long_body) limits.long_body_ms else limits.slow_body_ms;
}

const testing = std.testing;

test "a plan's pace fits its peer, and an h11 peer never pings" {
    for (0..512) |seed| {
        var random = Random.init(seed);
        const plan = draw(&random);
        if (plan.protocol == .h11) try testing.expect(plan.peer != .pinger);
        if (plan.peer == .slow_honest) try testing.expect(plan.gap_ms <= limits.honest_gap_ms_max);
        if (plan.peer == .slow_head) try testing.expect(plan.gap_ms >= limits.hostile_gap_ms_min);
        const hostile_exchange = plan.peer == .slow_second_head or plan.peer == .idle_pinger;
        try testing.expectEqual(plan.honest(), plan.exchanges_len > 0 and !hostile_exchange);
        // An upload arrives at twice the minimum body rate or more, and a slow body under it.
        if (plan.peer == .upload) try testing.expect(plan.piece_len * limits.ms_per_s >= limits.upload_rate_min * plan.gap_ms);
        if (plan.peer == .slow_body) try testing.expect(plan.piece_len * limits.ms_per_s <= limits.slow_body_rate_max * plan.gap_ms);
    }
}
