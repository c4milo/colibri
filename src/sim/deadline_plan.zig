//! One seed's plan for the deadline check (design §8 step 20b, decision 110): the protocol, how the
//! peer behaves, and when the application answers each request it reads.
//!
//! The peers are decision 110's slow and hostile ones, with honest ones beside them that no
//! deadline may end: a peer that makes its exchanges at once, and one whose octets arrive in small
//! pieces over a few seconds.
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");

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
};

pub const Plan = struct {
    protocol: Protocol,
    peer: Peer,
    /// The exchanges the peer makes whole: every one of an honest peer's, and the first one of a
    /// peer that ends slow.
    exchanges_len: u8,
    /// The gap between two pieces, or two PINGs, in milliseconds.
    gap_ms: u64,
    /// The octets in one piece.
    piece_len: u32,
    /// How long the application takes to answer each request, from the instant it read it.
    answer_delay_ms: [limits.exchanges_max]u64,
    /// The content of each response.
    content_len: [limits.exchanges_max]u32,

    /// Whether colibri's client plays the peer.
    pub fn honest(plan: *const Plan) bool {
        return plan.peer == .honest or plan.peer == .slow_honest;
    }
};

/// The protocols and the peers in the order `draw` picks from.
const protocols = std.enums.values(Protocol);
const peers = std.enums.values(Peer);

pub fn draw(random: *Random) Plan {
    const protocol = protocols[random.below(protocols.len)];
    var peer = peers[random.below(peers.len)];
    // A PING is an h2 frame, so an h11 pinger is a silent peer.
    if (peer == .pinger and protocol == .h11) peer = .silent;
    var plan: Plan = .{
        .protocol = protocol,
        .peer = peer,
        .exchanges_len = exchanges_of(peer, random),
        .gap_ms = 0,
        .piece_len = 0,
        .answer_delay_ms = @splat(0),
        .content_len = @splat(0),
    };
    draw_pace(&plan, random);
    for (0..limits.exchanges_max) |index| {
        plan.answer_delay_ms[index] = random.below(limits.answer_delay_ms_max + 1);
        plan.content_len[index] = @intCast(random.below(limits.content_len_max + 1));
    }
    assert(plan.exchanges_len <= limits.exchanges_max);
    return plan;
}

fn exchanges_of(peer: Peer, random: *Random) u8 {
    return switch (peer) {
        .honest, .slow_honest => @intCast(random.between(1, limits.exchanges_max)),
        .slow_second_head, .idle_pinger => 1,
        .silent, .slow_head, .pinger => 0,
    };
}

/// The gap and the piece length: a slow honest peer's are small, and a hostile one's are large.
fn draw_pace(plan: *Plan, random: *Random) void {
    switch (plan.peer) {
        .honest, .silent => {},
        .slow_honest => {
            plan.gap_ms = random.between(limits.honest_gap_ms_min, limits.honest_gap_ms_max);
            plan.piece_len = @intCast(random.between(limits.honest_piece_len_min, limits.honest_piece_len_max));
        },
        .slow_head, .slow_second_head, .pinger, .idle_pinger => {
            plan.gap_ms = random.between(limits.hostile_gap_ms_min, limits.hostile_gap_ms_max);
            plan.piece_len = @intCast(random.between(1, limits.hostile_piece_len_max));
        },
    }
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
    }
}
