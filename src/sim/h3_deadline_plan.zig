//! One seed's plan for the h3 deadline check (design §8 step 20c, decision 110 as amended): how
//! the peer behaves, the server's limits, and when the application answers each request it reads.
//!
//! The peers are decision 110's slow and flooding ones over QUIC, with honest ones beside them
//! that no deadline may end: a peer that makes its exchanges at once, one whose request heads
//! arrive late, one that uploads content at twice the minimum body rate or more, one that reads
//! long responses at twice the minimum send rate or more, and one behind a link that carries four
//! times the minimum send rate or more.
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");
const server = @import("server");

const Random = sim.Random;
const limits = sim.constants.h3_deadline;

/// How the peer behaves.
pub const Peer = enum {
    /// Makes its exchanges at once, reads every response, then sends nothing.
    honest,
    /// Makes its exchanges one at a time, and sends the last octet of each request's head a gap
    /// after the rest, well inside every deadline.
    slow_honest,
    /// Makes its exchanges one at a time with content in each request, which it sends at two to
    /// four times the plan's minimum body rate.
    upload,
    /// Reads long responses at two to four times the plan's minimum send rate, from streams whose
    /// credit grows as it reads.
    slow_reader,
    /// Makes its exchanges at once and reads long responses at once, behind a link that carries
    /// four to eight times the plan's minimum send rate and drops what its short queue cannot hold.
    slow_link,
    /// Completes the handshake and sends nothing more.
    silent,
    /// Completes the handshake, then sends a PING every gap and no request.
    pinger,
    /// Makes one exchange, then sends a PING every gap and no request.
    idle_pinger,
    /// Sends all of its first request's head but the last octet.
    slow_head,
    /// Makes one exchange, then a gap after its response ended sends its next request's head as
    /// `slow_head` does.
    slow_second_head,
    /// Sends a whole request head, then its content under the minimum body rate.
    slow_body,
    /// Sends a whole request head, then its content at twice the minimum body rate for longer than
    /// the plan's cap on a body, which the plan shortens so the cap passes first.
    long_body,
    /// Makes a request and acknowledges nothing of its long answer.
    deaf,
    /// Makes a request and reads none of its long answer, so its stream's credit never grows.
    holds_credit,
    /// Makes a request on a stream with ample credit and reads none of its long answer, which
    /// uses up the small credit the peer gives its connection (RFC 9000 §4.1).
    holds_connection_credit,
    /// Makes a request and reads its long answer at a small fraction of the minimum send rate.
    reads_slowly,
    /// Opens requests and cancels them, past the server's limit in one period.
    flooder,
    /// Opens two requests a while apart, and sends the content of neither.
    many_bodies,
};

pub const Plan = struct {
    peer: Peer,
    /// The instant the run starts at, in milliseconds.
    base_ms: u64,
    /// The server's limits: decision 110's defaults, or shorter ones.
    deadlines: server.Deadlines,
    /// The exchanges the peer makes whole: every one of an honest peer's, and the first one of a
    /// peer that ends slow.
    exchanges_len: u8,
    /// The gap between two pieces of content, or two PINGs, or a head and its last octet, or a
    /// response's end and a slow second head, in milliseconds, and the octets in one piece.
    gap_ms: u64,
    piece_len: u32,
    /// The requests a peer that floods opens and cancels in one batch.
    flood_batch_len: u32,
    /// The content each request of an uploading peer carries.
    upload_len: [limits.exchanges_max]u32,
    /// How a peer that reads slowly reads: `read_len` octets every `read_gap_ms`.
    read_gap_ms: u64,
    read_len: u32,
    /// Octets a second the link from the server to the peer carries, or 0 for a link with no rate.
    link_rate: u32,
    /// How long the application takes to answer each request, from the instant its content ended.
    answer_delay_ms: [limits.exchanges_max]u64,
    /// How long after the first half of an answer's content the application writes the rest and
    /// ends the response, or 0 for an answer it writes whole.
    answer_gap_ms: [limits.exchanges_max]u64,
    /// The content of each response.
    content_len: [limits.exchanges_max]u32,

    /// Whether no deadline may end the peer's requests.
    pub fn honest(plan: *const Plan) bool {
        return switch (plan.peer) {
            .honest, .slow_honest, .upload, .slow_reader, .slow_link => true,
            else => false,
        };
    }

    /// Whether the peer reads what arrives a piece at a time, and whether it reads none of it.
    pub fn reads_paced(plan: *const Plan) bool {
        return plan.peer == .slow_reader or plan.peer == .reads_slowly;
    }

    pub fn reads_none(plan: *const Plan) bool {
        return plan.peer == .holds_credit or plan.peer == .holds_connection_credit;
    }

    /// Whether the peer's streams start with the small credit of a slow reader, and whether its
    /// connection does.
    pub fn small_window(plan: *const Plan) bool {
        return plan.reads_paced() or plan.peer == .holds_credit;
    }

    pub fn small_connection_window(plan: *const Plan) bool {
        return plan.peer == .holds_connection_credit;
    }

    /// Whether the application leaves its answer open, as a stream of events does. The octets it
    /// wrote then wait on the connection's credit alone, with no end of the response behind them.
    pub fn answer_stays_open(plan: *const Plan) bool {
        return plan.peer == .holds_connection_credit;
    }

    /// Whether the request the peer makes gets a long answer.
    pub fn reads_long(plan: *const Plan) bool {
        return switch (plan.peer) {
            .slow_reader, .slow_link, .deaf, .holds_credit, .holds_connection_credit, .reads_slowly => true,
            else => false,
        };
    }
};

const peers = std.enums.values(Peer);

/// One plan in this many shortens the server's limits, and one answer in this many to an honest
/// peer is written in two halves.
const short_limits_one_in: u64 = 4;
const answers_in_two_one_in: u64 = 2;

pub fn draw(random: *Random) Plan {
    const peer = peers[random.below(peers.len)];
    var plan: Plan = .{
        .peer = peer,
        .base_ms = random.below(limits.base_ms_max),
        .deadlines = if (peer == .long_body) long_body_deadlines(random) else draw_deadlines(random),
        .exchanges_len = exchanges_of(peer, random),
        .gap_ms = 0,
        .piece_len = 0,
        .flood_batch_len = 0,
        .upload_len = @splat(0),
        .read_gap_ms = 0,
        .read_len = 0,
        .link_rate = 0,
        .answer_delay_ms = @splat(0),
        .answer_gap_ms = @splat(0),
        .content_len = @splat(0),
    };
    draw_pace(&plan, random);
    draw_read_pace(&plan, random);
    if (peer == .slow_link) {
        const factor: u32 = @intCast(random.between(limits.link_rate_factor_min, limits.link_rate_factor_max));
        plan.link_rate = factor * plan.deadlines.send_rate_min.?;
    }
    for (0..limits.exchanges_max) |index| {
        plan.answer_delay_ms[index] = random.below(limits.answer_delay_ms_max + 1);
        plan.content_len[index] = @intCast(random.below(limits.content_len_max + 1));
        if (peer == .upload) plan.upload_len[index] = @intCast(random.between(1, limits.upload_len_max));
        if (plan.reads_long()) plan.content_len[index] = @intCast(random.between(limits.read_content_len_min, limits.read_content_len_max));
        // One answer in two to an honest peer is written in two halves, a gap apart.
        if (plan.honest() and random.below(answers_in_two_one_in) == 0) plan.answer_gap_ms[index] = random.between(1, limits.answer_gap_ms_max);
    }
    assert(plan.exchanges_len <= limits.exchanges_max);
    return plan;
}

/// The exchanges `peer` makes whole.
fn exchanges_of(peer: Peer, random: *Random) u8 {
    return switch (peer) {
        .honest, .slow_honest, .upload, .slow_reader, .slow_link => @intCast(random.between(1, limits.exchanges_max)),
        .idle_pinger, .slow_second_head => 1,
        // Each of these makes one request, which a deadline ends.
        .slow_body, .long_body, .deaf, .holds_credit, .holds_connection_credit, .reads_slowly => 1,
        .silent, .pinger, .slow_head, .flooder, .many_bodies => 0,
    };
}

/// Decision 110's defaults, or in one plan of `short_limits_one_in` stricter ones, as a server
/// short of connections sets.
fn draw_deadlines(random: *Random) server.Deadlines {
    if (random.below(short_limits_one_in) != 0) return .{};
    const defaults = server.constants;
    const body_rate: u32 = @intCast(random.between(defaults.body_rate_min, limits.short_rate_max));
    const send_rate: u32 = @intCast(random.between(defaults.send_rate_min, limits.short_rate_max));
    return .{
        .first_request_ns = shorter_ns(random, limits.short_limit_ms_min, defaults.first_request_timeout_ns),
        .idle_ns = shorter_ns(random, limits.short_limit_ms_min, defaults.idle_timeout_ns),
        .head_ns = shorter_ns(random, limits.short_limit_ms_min, defaults.head_timeout_ns),
        .body_rate_min = body_rate,
        .rate_grace_ns = shorter_ns(random, limits.short_rate_ms_min, defaults.rate_grace_ns),
        .rate_window_ns = shorter_ns(random, window_ms_min(@min(body_rate, send_rate)), defaults.rate_window_ns),
        .send_rate_min = send_rate,
    };
}

/// Decision 110's defaults, with a cap on a body that a long body outlasts.
fn long_body_deadlines(random: *Random) server.Deadlines {
    const cap_ms = random.between(limits.long_body_cap_ms_min, limits.long_body_cap_ms_max);
    return .{ .body_ns = cap_ms * limits.ns_per_ms };
}

/// A limit between `min_ms` and decision 110's default, in nanoseconds.
fn shorter_ns(random: *Random, min_ms: u64, default_ns: u64) u64 {
    const default_ms = default_ns / limits.ns_per_ms;
    assert(min_ms <= default_ms);
    return random.between(min_ms, default_ms) * limits.ns_per_ms;
}

/// The shortest window a plan draws for a minimum rate: one whose quota is `window_quota_min`.
fn window_ms_min(rate: u32) u64 {
    return (limits.window_quota_min * limits.ms_per_s + rate - 1) / rate;
}

/// The pace of what the peer sends: an upload's pieces at two to four times the minimum body
/// rate, a long body's at twice it, a slow body's under it, the gap between a pinger's PINGs,
/// before a late head's last octet or before a slow second head, or the requests in a flooder's
/// batch.
fn draw_pace(plan: *Plan, random: *Random) void {
    switch (plan.peer) {
        .long_body => {
            plan.gap_ms = random.between(limits.long_body_gap_ms_min, limits.long_body_gap_ms_max);
            plan.piece_len = piece_of(limits.long_body_rate_factor * plan.deadlines.body_rate_min.?, plan.gap_ms);
        },
        .slow_honest => plan.gap_ms = random.between(limits.late_head_ms_min, limits.late_head_ms_max),
        .slow_second_head => {
            const idle_ms = plan.deadlines.idle_ns.? / limits.ns_per_ms;
            plan.gap_ms = random.between(limits.second_head_after_ms_min, idle_ms - limits.second_head_before_idle_ms);
        },
        .flooder => plan.flood_batch_len = @intCast(random.between(1, limits.flood_batch_len_max)),
        .upload => {
            const factor = random.between(limits.upload_rate_factor_min, limits.upload_rate_factor_max);
            plan.gap_ms = random.between(limits.upload_gap_ms_min, limits.upload_gap_ms_max);
            plan.piece_len = piece_of(factor * plan.deadlines.body_rate_min.?, plan.gap_ms);
        },
        .slow_body => {
            plan.gap_ms = random.between(limits.hostile_gap_ms_min, limits.hostile_gap_ms_max);
            plan.piece_len = piece_of(random.between(limits.slow_body_rate_min, limits.slow_body_rate_max), plan.gap_ms);
        },
        .pinger, .idle_pinger => plan.gap_ms = random.between(limits.hostile_gap_ms_min, limits.hostile_gap_ms_max),
        else => {},
    }
}

/// The pace a peer reads at: an honest slow reader's at two to four times the minimum send rate,
/// or a hostile one's at a small fraction of it.
fn draw_read_pace(plan: *Plan, random: *Random) void {
    switch (plan.peer) {
        .slow_reader => {
            const factor = random.between(limits.read_rate_factor_min, limits.read_rate_factor_max);
            plan.read_gap_ms = random.between(limits.read_gap_ms_min, limits.read_gap_ms_max);
            plan.read_len = piece_of(factor * plan.deadlines.send_rate_min.?, plan.read_gap_ms);
        },
        .reads_slowly => {
            plan.read_gap_ms = random.between(limits.hostile_gap_ms_min, limits.hostile_gap_ms_max);
            plan.read_len = piece_of(random.between(limits.slow_read_rate_min, limits.slow_read_rate_max), plan.read_gap_ms);
        },
        else => {},
    }
}

/// The octets `rate` octets a second bring in `gap_ms`, rounded up, and one at least.
fn piece_of(rate: u64, gap_ms: u64) u32 {
    return @intCast(@max(1, (rate * gap_ms + limits.ms_per_s - 1) / limits.ms_per_s));
}

const testing = std.testing;

/// Seeds the test draws plans from.
const plan_seeds: u64 = 4_096;

test "every plan's limits are ones the server takes, and every pace keeps its side of the minimum rate" {
    var seen: [peers.len]bool = @splat(false);
    for (0..plan_seeds) |seed| {
        var random = Random.init(seed);
        const plan = draw(&random);
        seen[@intFromEnum(plan.peer)] = true;
        try plan.deadlines.validate();
        try plan.deadlines.validate_units();
        const first_window_ms = (plan.deadlines.rate_grace_ns + plan.deadlines.rate_window_ns) / limits.ns_per_ms;
        try testing.expect(plan.deadlines.body_quota().? >= limits.window_quota_min);
        try testing.expect(plan.deadlines.send_quota().? >= limits.window_quota_min);
        try expect_pace(&plan, first_window_ms);
    }
    for (seen) |drawn| try testing.expect(drawn);
}

/// A late head takes one part in this of the shortest deadline at most, and a stream's credit
/// grows once one part in this of its window is read (RFC 9000 §4.1).
const late_head_margin: u64 = 2;
const credit_grows_at: u64 = 2;

/// What the plan's pace must keep, so that the peer ends as the check expects.
fn expect_pace(plan: *const Plan, first_window_ms: u64) !void {
    const deadlines = &plan.deadlines;
    switch (plan.peer) {
        // The last octet of a head arrives in under half of each deadline it could pass.
        .slow_honest => {
            const shortest_ns = @min(deadlines.first_request_ns.?, deadlines.idle_ns.?, deadlines.head_ns.?);
            try testing.expect(plan.gap_ms * limits.ns_per_ms * late_head_margin <= shortest_ns);
        },
        // Twice the minimum rate or more, a piece every gap.
        .upload => try testing.expect(plan.piece_len * limits.ms_per_s >= limits.upload_rate_factor_min * deadlines.body_rate_min.? * plan.gap_ms),
        .slow_reader => try testing.expect(plan.read_len * limits.ms_per_s >= limits.read_rate_factor_min * deadlines.send_rate_min.? * plan.read_gap_ms),
        .slow_link => try testing.expect(plan.link_rate >= limits.link_rate_factor_min * deadlines.send_rate_min.?),
        // Under the quota in its first window, the grace period included.
        .slow_body => try testing.expect((first_window_ms / plan.gap_ms + 1) * plan.piece_len < deadlines.body_quota().?),
        .long_body => try expect_long_body(plan, first_window_ms),
        // RFC 9000 §4.1: its stream's credit grows once half the window is read, which the
        // first window never sees.
        .reads_slowly => try testing.expect((first_window_ms / plan.read_gap_ms + 1) * plan.read_len < limits.reader_stream_window / credit_grows_at),
        // The credit of its connection is under the quota of a window.
        .holds_connection_credit => try testing.expect(limits.reader_stream_window < deadlines.send_quota().?),
        .flooder => try testing.expect(plan.flood_batch_len > 0 and plan.flood_batch_len <= limits.flood_batch_len_max),
        else => {},
    }
}

/// A window is judged before the cap, every window holds its quota, and the content the request
/// declares outlasts the cap.
fn expect_long_body(plan: *const Plan, first_window_ms: u64) !void {
    const deadlines = &plan.deadlines;
    const cap_ms = deadlines.body_ns.? / limits.ns_per_ms;
    const window_ms = deadlines.rate_window_ns / limits.ns_per_ms;
    try testing.expect(first_window_ms <= cap_ms);
    try testing.expect((window_ms / plan.gap_ms) * plan.piece_len >= deadlines.body_quota().?);
    try testing.expect((cap_ms / plan.gap_ms + 1) * plan.piece_len < limits.slow_body_len);
}
