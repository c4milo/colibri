//! One seed's plan for the deadline check (design §8 step 20b, decision 110): the protocol, how the
//! peer behaves, the server's limits, and when the application answers each request it reads.
//!
//! The peers are decision 110's slow and hostile ones, with honest ones beside them that no
//! deadline may end: a peer that makes its exchanges at once, one whose octets arrive in small
//! pieces over a few seconds, one that uploads content at twice decision 110's minimum body rate
//! or more, and one that reads long responses at twice its minimum send rate or more.
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
    /// colibri's client, reading long responses at two to four times decision 110's minimum send
    /// rate.
    slow_reader,
    /// Makes a request whose long answer it never reads.
    reads_nothing,
    /// Makes a request and reads its long answer at a small fraction of the minimum send rate.
    reads_slowly,
    /// h2 alone: makes a request with a stream window of 0, which it opens an octet each gap. In
    /// h11 it reads nothing.
    opens_window_slowly,
    /// h2 alone: makes a request with the largest stream window, and never opens the connection's
    /// window, which the long answer uses up. In h11 it reads nothing.
    opens_no_connection_window,
    /// h2 alone: opens `many_streams_len` streams at once, each a request whose body never comes.
    /// In h11, which has no streams, it sends a slow body.
    many_streams,
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
    /// How a peer that reads slowly reads: a piece of `read_len` octets every `read_gap_ms`.
    read_gap_ms: u64,
    read_len: u32,
    /// The rate a slow body arrives at, in octets a second.
    body_rate: u32,
    /// How long the application takes to answer each request, from the instant its body ended.
    answer_delay_ms: [limits.exchanges_max]u64,
    /// The content of each response.
    content_len: [limits.exchanges_max]u32,

    /// Whether colibri's client plays the peer.
    pub fn honest(plan: *const Plan) bool {
        return switch (plan.peer) {
            .honest, .slow_honest, .upload, .slow_reader => true,
            else => false,
        };
    }

    /// Whether the peer reads what the server sends a piece at a time, and whether it reads
    /// nothing.
    pub fn reads_paced(plan: *const Plan) bool {
        return plan.peer == .slow_reader or plan.peer == .reads_slowly;
    }

    pub fn reads_none(plan: *const Plan) bool {
        return plan.peer == .reads_nothing;
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
    // A PING is an h2 frame, so an h11 pinger is a silent peer, and h11 has no window, so an h11
    // peer that would open one slowly reads nothing.
    if (peer == .pinger and protocol == .h11) peer = .silent;
    if (protocol == .h11 and (peer == .opens_window_slowly or peer == .opens_no_connection_window)) peer = .reads_nothing;
    if (protocol == .h11 and peer == .many_streams) peer = .slow_body;
    var plan: Plan = .{
        .protocol = protocol,
        .peer = peer,
        .base_ms = random.below(limits.base_ms_max),
        .deadlines = if (peer == .long_body) long_body_deadlines(random) else draw_deadlines(random),
        .exchanges_len = exchanges_of(peer, random),
        .gap_ms = 0,
        .piece_len = 0,
        .upload_len = @splat(0),
        .read_gap_ms = 0,
        .read_len = 0,
        .body_rate = 0,
        .answer_delay_ms = @splat(0),
        .content_len = @splat(0),
    };
    draw_pace(&plan, random);
    draw_read_pace(&plan, random);
    for (0..limits.exchanges_max) |index| {
        plan.answer_delay_ms[index] = random.below(limits.answer_delay_ms_max + 1);
        plan.content_len[index] = @intCast(random.below(limits.content_len_max + 1));
        if (peer == .upload) plan.upload_len[index] = @intCast(random.between(1, limits.upload_len_max));
        if (reads_long(peer)) plan.content_len[index] = @intCast(random.between(limits.read_content_len_min, limits.read_content_len_max));
    }
    assert(plan.exchanges_len <= limits.exchanges_max);
    return plan;
}

/// Decision 110's defaults, or in one plan of `short_limits_one_in` stricter ones, as a server
/// short of connections sets.
fn draw_deadlines(random: *Random) server.Deadlines {
    if (random.below(short_limits_one_in) != 0) return .{};
    return draw_short_deadlines(random);
}

fn draw_short_deadlines(random: *Random) server.Deadlines {
    const defaults = server.constants;
    const body_rate: u32 = @intCast(random.between(defaults.body_rate_min, limits.short_rate_max));
    return .{
        .first_request_ns = shorter_ns(random, limits.short_limit_ms_min, defaults.first_request_timeout_ns),
        .idle_ns = shorter_ns(random, limits.short_limit_ms_min, defaults.idle_timeout_ns),
        .head_ns = shorter_ns(random, limits.short_limit_ms_min, defaults.head_timeout_ns),
        .body_rate_min = body_rate,
        .rate_grace_ns = shorter_ns(random, limits.short_rate_ms_min, defaults.rate_grace_ns),
        .rate_window_ns = shorter_ns(random, window_ms_min(body_rate), defaults.rate_window_ns),
        .body_ns = shorter_ns(random, limits.short_body_ms_min, defaults.body_timeout_ns),
        .send_rate_min = @intCast(random.between(defaults.send_rate_min, limits.short_rate_max)),
        .linger_ns = shorter_ns(random, limits.short_linger_ms_min, defaults.close_linger_ns),
    };
}

/// The limits a long body runs under: a server that allows slow bodies and caps them, with a cap
/// its body outlasts.
fn long_body_deadlines(random: *Random) server.Deadlines {
    var deadlines = draw_short_deadlines(random);
    deadlines.body_rate_min = limits.long_body_rate_min;
    deadlines.body_ns = random.between(limits.long_body_cap_ms_min, limits.long_body_cap_ms_max) * limits.ns_per_ms;
    return deadlines;
}

/// The shortest window a plan draws for a minimum rate: one whose quota is `window_quota_min`.
fn window_ms_min(rate: u32) u64 {
    const quota_ms = (limits.window_quota_min * limits.ms_per_s + rate - 1) / rate;
    return @max(limits.short_rate_ms_min, quota_ms);
}

/// A limit of whole milliseconds, from `min_ms` to the default.
fn shorter_ns(random: *Random, min_ms: u64, default_ns: u64) u64 {
    const limit_ms = random.between(min_ms, default_ns / limits.ns_per_ms);
    return limit_ms * limits.ns_per_ms;
}

fn exchanges_of(peer: Peer, random: *Random) u8 {
    return switch (peer) {
        .honest, .slow_honest, .upload, .slow_reader => @intCast(random.between(1, limits.exchanges_max)),
        .slow_second_head, .idle_pinger, .reads_nothing, .reads_slowly, .opens_window_slowly, .opens_no_connection_window => 1,
        .silent, .slow_head, .pinger, .slow_body, .long_body, .many_streams => 0,
    };
}

/// The gap and the piece length: a slow honest peer's are small, an upload's carry at least twice
/// the minimum body rate, and a hostile one's are large, or carry a body under that rate.
fn draw_pace(plan: *Plan, random: *Random) void {
    switch (plan.peer) {
        .honest, .silent, .slow_reader, .reads_nothing, .reads_slowly, .opens_no_connection_window, .many_streams => {},
        .slow_honest => {
            plan.gap_ms = random.between(limits.honest_gap_ms_min, limits.honest_gap_ms_max);
            plan.piece_len = @intCast(random.between(limits.honest_piece_len_min, limits.honest_piece_len_max));
        },
        .upload => {
            plan.gap_ms = random.between(limits.upload_gap_ms_min, limits.upload_gap_ms_max);
            const rate_min = plan.deadlines.body_rate_min.?;
            const rate = random.between(limits.upload_rate_factor_min * rate_min, limits.upload_rate_factor_max * rate_min);
            // Rounded up, so the pace is the rate or more.
            plan.piece_len = @intCast((rate * plan.gap_ms + limits.ms_per_s - 1) / limits.ms_per_s);
        },
        .slow_head, .slow_second_head, .pinger, .idle_pinger, .opens_window_slowly => {
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

/// Whether the peer's answers are long, so its reading decides how fast the server sends.
fn reads_long(peer: Peer) bool {
    return switch (peer) {
        .slow_reader, .reads_nothing, .reads_slowly, .opens_window_slowly, .opens_no_connection_window => true,
        else => false,
    };
}

/// The pace a slow reader reads at: an honest one at two to four times the minimum send rate, a
/// hostile one at a small fraction of it.
fn draw_read_pace(plan: *Plan, random: *Random) void {
    switch (plan.peer) {
        .slow_reader => {
            plan.read_gap_ms = random.between(limits.read_gap_ms_min, limits.read_gap_ms_max);
            const rate_min = plan.deadlines.send_rate_min.?;
            const rate = random.between(limits.read_rate_factor_min * rate_min, limits.read_rate_factor_max * rate_min);
            // Rounded up, so the pace is the rate or more.
            plan.read_len = @intCast((rate * plan.read_gap_ms + limits.ms_per_s - 1) / limits.ms_per_s);
        },
        .reads_slowly => {
            plan.read_gap_ms = random.between(limits.hostile_gap_ms_min, limits.hostile_gap_ms_max);
            const rate = random.between(limits.slow_read_rate_min, limits.slow_read_rate_max);
            // Rounded down, so the pace is the rate or less.
            plan.read_len = @intCast(@max(1, rate * plan.read_gap_ms / limits.ms_per_s));
        },
        else => {},
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
        const hostile_exchange = switch (plan.peer) {
            .slow_second_head, .idle_pinger, .reads_nothing, .reads_slowly, .opens_window_slowly, .opens_no_connection_window => true,
            else => false,
        };
        try testing.expectEqual(plan.honest(), plan.exchanges_len > 0 and !hostile_exchange);
        try testing.expect(plan.deadlines.body_quota().? >= limits.window_quota_min or plan.peer == .long_body);
        try expect_write_pace(&plan);
        try expect_read_pace(&plan);
    }
}

/// An upload arrives at twice the minimum body rate or more, and a slow body under it.
fn expect_write_pace(plan: *const Plan) !void {
    if (plan.peer == .slow_honest) try testing.expect(plan.gap_ms <= limits.honest_gap_ms_max);
    if (plan.peer == .slow_head) try testing.expect(plan.gap_ms >= limits.hostile_gap_ms_min);
    const upload_rate_min = limits.upload_rate_factor_min * plan.deadlines.body_rate_min.?;
    if (plan.peer == .upload) try testing.expect(plan.piece_len * limits.ms_per_s >= upload_rate_min * plan.gap_ms);
    if (plan.peer == .slow_body) try testing.expect(plan.piece_len * limits.ms_per_s <= limits.slow_body_rate_max * plan.gap_ms);
}

/// An honest slow reader reads at twice the minimum send rate or more, a hostile one at a small
/// fraction of it, and each reads a long answer.
fn expect_read_pace(plan: *const Plan) !void {
    const read_rate_min = limits.read_rate_factor_min * plan.deadlines.send_rate_min.?;
    if (plan.peer == .slow_reader) try testing.expect(plan.read_len * limits.ms_per_s >= read_rate_min * plan.read_gap_ms);
    if (plan.peer == .reads_slowly) try testing.expect(plan.read_len * limits.ms_per_s <= limits.slow_read_rate_max * plan.read_gap_ms);
    if (reads_long(plan.peer)) try testing.expect(plan.content_len[0] >= limits.read_content_len_min);
}

comptime {
    // A slow hostile reader's first window falls short under any limits a plan draws: over the
    // longest grace period and a piece more, it reads less than the quota the lowest minimum send
    // rate, the default, leaves over the shortest window once its own reading within it counts.
    const grace_ms_max = server.constants.rate_grace_ns / limits.ns_per_ms;
    const read_ms = grace_ms_max + limits.hostile_gap_ms_max;
    const left = (server.constants.send_rate_min - limits.slow_read_rate_max) * window_ms_min(limits.short_rate_max);
    assert(limits.slow_read_rate_max * read_ms < left);
    // A body's cap stays past the longest honest upload, at twice the lowest minimum rate.
    const upload_ms_max = limits.upload_len_max * limits.ms_per_s / (limits.upload_rate_factor_min * server.constants.body_rate_min);
    assert(limits.short_body_ms_min > upload_ms_max);
}
