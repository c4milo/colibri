//! One seed's plan for the client trace run (decision 105, design §8 step 17d): the exchanges the
//! caller makes and cancels, how the channel chooses QUIC, what happens to QUIC on the network and
//! at its server, how each server answers, and when the caller shuts the channel down. The plan is
//! drawn from the seed alone before the run, so a seed replays (invariant 5).
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");

const Random = sim.Random;
const limits = sim.constants.client_trace;

/// A draw that comes out one way half the time.
const one_in_two: u64 = 2;

/// How the channel chooses QUIC, as spec/tla/client_exchanges's `QuicPolicy` names it.
pub const Policy = enum {
    /// QUIC first: the configuration says to try it, or an HTTPS record names h3.
    first,
    /// TCP first, and QUIC once a TCP response's Alt-Svc named h3 (RFC 7838 §3).
    learn,
    /// No QUIC configured.
    never,
};

/// What happens to QUIC.
pub const Quic = enum {
    /// The network carries it with TCP's delay.
    works,
    /// The network drops every datagram the client sends, as a network that blocks UDP does.
    blocked,
    /// The server's ALPN names no h3, so the handshake selects none (RFC 9114 §3.1).
    refused,
    /// The network delays each datagram past the fallback delay.
    slow,
    /// The network drops some datagrams each way.
    lossy,
};

/// How a connection breaks.
pub const Break = enum {
    /// The QUIC server closes the connection with an error (RFC 9000 §10.2).
    quic_close,
    /// The caller's UDP flow fails.
    quic_flow,
    /// The caller's TCP connection fails.
    tcp_flow,
};

/// How a server answers a request it read.
pub const Answer = enum {
    /// It processes the request and sends the response.
    respond,
    /// It refuses the request unprocessed (RFC 9113 §8.7, RFC 9114 §4.1.1).
    reject,
    /// It processes the request, then resets its stream.
    reset,
};

pub const Plan = struct {
    /// Exchanges the caller makes: the model's `N`.
    exchanges: u32,
    /// The instant each is made, and the instant it is cancelled, if it is.
    make_at_ns: [limits.exchanges_max]u64,
    cancel_at_ns: [limits.exchanges_max]?u64,
    /// Octets of each request's content: none for a GET, some for a POST.
    content_len: [limits.exchanges_max]u32,
    /// Whether the caller cancels a POST once its connection ended it and before the channel
    /// reported it, while its stream may still send the content (RFC 9000 §3.1).
    cancel_on_end: [limits.exchanges_max]bool,
    policy: Policy,
    /// Whether the values carry an HTTPS record: one naming h3 under `first`, and one naming no h3
    /// under `learn`.
    https: bool,
    quic: Quic,
    /// How each server answers each exchange, and how long it takes to.
    quic_answers: [limits.exchanges_max]Answer,
    tcp_answers: [limits.exchanges_max]Answer,
    answer_delay_ns: u64,
    /// Whether a server answers a request as soon as its head arrives, before its content has.
    answer_early: bool,
    /// The instant a server sends the seed's one GOAWAY, and which transport's server does.
    goaway_at_ns: ?u64,
    goaway_transport: Transport,
    /// The instant a connection breaks, and how, in a rough seed that draws one.
    break_at_ns: ?u64,
    break_kind: Break,
    /// The instant the caller shuts the channel down, after its last exchange is made.
    shutdown_at_ns: u64,
    /// Whether every exchange that is not cancelled must end in a response: the servers only
    /// respond, and at most one GOAWAY refuses an exchange (design §8 step 17d's check).
    clean: bool,

    pub const Transport = enum { quic, tcp };

    pub fn draw(plan: *Plan, random: *Random) void {
        plan.exchanges = 1 + @as(u32, @intCast(random.below(limits.exchanges_max)));
        plan.clean = random.below(limits.rough_one_in) != 0;
        var last_make_ns: u64 = 0;
        for (0..limits.exchanges_max) |index| {
            plan.make_at_ns[index] = random.below(limits.make_window_ns);
            last_make_ns = @max(last_make_ns, plan.make_at_ns[index]);
            plan.cancel_at_ns[index] = null;
            if (random.below(limits.cancel_one_in) == 0) {
                plan.cancel_at_ns[index] = plan.make_at_ns[index] + random.below(limits.cancel_after_max_ns);
            }
            plan.content_len[index] = 0;
            if (random.below(limits.post_one_in) == 0) plan.content_len[index] = 1 + @as(u32, @intCast(random.below(limits.content_len_max)));
            plan.cancel_on_end[index] = plan.content_len[index] > 0 and random.below(one_in_two) == 0;
            plan.quic_answers[index] = plan.draw_answer(random);
            plan.tcp_answers[index] = plan.draw_answer(random);
        }
        plan.draw_transports(random);
        plan.answer_delay_ns = random.below(limits.answer_delay_max_ns);
        // Design §8 step 17g: a QUIC connection idle near its timeout, and one waiting past it.
        if (random.below(limits.late_one_in) == 0) {
            const late = plan.exchanges - 1;
            const late_ns = limits.late_gap_min_ns + random.below(limits.late_gap_max_ns - limits.late_gap_min_ns);
            const moved_ns = limits.make_window_ns + late_ns - plan.make_at_ns[late];
            plan.make_at_ns[late] += moved_ns;
            if (plan.cancel_at_ns[late]) |cancel_at_ns| plan.cancel_at_ns[late] = cancel_at_ns + moved_ns;
            last_make_ns = @max(last_make_ns, plan.make_at_ns[late]);
        }
        if (random.below(limits.slow_answer_one_in) == 0) {
            plan.answer_delay_ns = limits.slow_answer_min_ns + random.below(limits.slow_answer_max_ns - limits.slow_answer_min_ns);
        }
        plan.answer_early = random.below(one_in_two) == 0;
        plan.draw_goaway(random);
        plan.break_kind = @enumFromInt(random.below(std.meta.fields(Break).len));
        plan.break_at_ns = if (plan.clean) null else plan.first_make_ns() + random.below(limits.break_window_ns);
        plan.shutdown_at_ns = last_make_ns + 1 + random.below(limits.shutdown_after_max_ns);
        assert(plan.exchanges >= 1 and plan.exchanges <= limits.exchanges_max);
    }

    fn draw_answer(plan: *const Plan, random: *Random) Answer {
        if (plan.clean) return .respond;
        return @enumFromInt(random.below(std.meta.fields(Answer).len));
    }

    fn draw_transports(plan: *Plan, random: *Random) void {
        plan.policy = @enumFromInt(random.below(std.meta.fields(Policy).len));
        plan.https = random.below(one_in_two) == 0 and plan.policy != .never;
        plan.quic = @enumFromInt(random.below(std.meta.fields(Quic).len));
        if (plan.policy == .never) plan.quic = .works;
    }

    /// A seed's one GOAWAY, if it draws one. A learning channel's TCP server sends it, so a later
    /// connection goes over the h3 it learned.
    fn draw_goaway(plan: *Plan, random: *Random) void {
        plan.goaway_at_ns = null;
        plan.goaway_transport = .quic;
        if (plan.policy == .learn) plan.goaway_transport = .tcp;
        if (plan.policy == .never) plan.goaway_transport = .tcp;
        const draws = plan.policy == .learn or random.below(limits.goaway_one_in) == 0;
        if (draws) plan.goaway_at_ns = random.below(limits.goaway_window_ns);
    }

    /// The instant the first exchange is made.
    fn first_make_ns(plan: *const Plan) u64 {
        var first: u64 = std.math.maxInt(u64);
        for (plan.make_at_ns[0..plan.exchanges]) |make_at_ns| first = @min(first, make_at_ns);
        return first;
    }

    /// Whether exchange `index` is made in this seed.
    pub fn made(plan: *const Plan, index: usize) bool {
        return index < plan.exchanges;
    }
};

const testing = std.testing;

test "a plan is drawn from its seed alone, and its caller shuts the channel down after its last exchange" {
    var first: Plan = undefined;
    var second: Plan = undefined;
    for (0..sim.constants.check_seeds_default) |seed| {
        var random = Random.init(seed);
        first.draw(&random);
        random = Random.init(seed);
        second.draw(&random);
        try testing.expect(std.meta.eql(first, second));
        for (first.make_at_ns[0..first.exchanges]) |make_at_ns| try testing.expect(make_at_ns < first.shutdown_at_ns);
        if (first.clean) for (first.quic_answers, first.tcp_answers) |quic, tcp| {
            try testing.expect(quic == .respond and tcp == .respond);
        };
        // A clean seed breaks no connection, so each of its exchanges can complete.
        if (first.clean) try testing.expectEqual(null, first.break_at_ns);
    }
}
