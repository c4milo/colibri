//! What one seed of the h3 trace run does (https://github.com/c4milo/colibri/issues/58): a plan
//! inside the scope of `spec/tla/h3_connection`, whose states the run logs for TLC to check.
//!
//! The model's client opens request streams in order, each a HEADERS frame and `content` DATA
//! frames, writes at most one insert with each, and may cancel any of them. Its server answers
//! each request once it has read all of it, and sends up to `h3_trace_goaways_max` GOAWAY frames.
//! QPACK runs from the client to the server alone: the client's decoder allows no dynamic table,
//! so no response inserts. The plan draws the steps at which each of those happens, and the
//! server decoder's settings.
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");
const h3 = @import("h3");

const Random = sim.Random;
const constants = sim.constants;

/// What a request's one regular line does to the client's dynamic table (RFC 9204 §3.2).
pub const Line = enum {
    /// The request carries no regular line.
    none,
    /// A line no earlier request carried, which the encoder may insert.
    new,
    /// The line of the last earlier request whose line was new, which the encoder may reference.
    repeat,
};

/// One seed in this many gives the server's decoder no dynamic table.
const capacity_one_in: u64 = 2;
/// How many spans of `h3_trace_act_steps` the first request's step is drawn from.
const first_open_spans: u64 = 2;

pub const Plan = struct {
    /// Request streams the client opens at most: the model's `N`.
    requests: u32,
    /// DATA frames each request carries after its HEADERS frame: the model's `Content`.
    content: u32,
    /// Each request's regular line.
    lines: [constants.h3_trace_requests_max]Line,
    /// The step from which the client opens request r. The steps rise with r, because the model's
    /// client opens its streams in order.
    open_at: [constants.h3_trace_requests_max]u64,
    /// The step from which the client cancels request r if it has not ended, or null.
    cancel_at: [constants.h3_trace_requests_max]?u64,
    /// The steps from which the server sends each GOAWAY, in order.
    goaway_at: [constants.h3_trace_goaways_max]u64,
    goaways: u32,
    /// The server decoder's settings (RFC 9204 §5): the model's `BlockedStreams`, and a capacity
    /// of 0 or `h3_trace_capacity`.
    server_decoder: h3.qpack.decoder.Settings,
    client_grease: u64,
    server_grease: u64,

    pub fn draw(plan: *Plan, random: *Random) void {
        plan.requests = @intCast(random.between(1, constants.h3_trace_requests_max));
        plan.content = @intCast(random.below(constants.h3_trace_content_max + 1));
        plan.server_decoder = .{
            .max_table_capacity = if (random.below(capacity_one_in) == 0) 0 else constants.h3_trace_capacity,
            .blocked_streams = random.below(constants.h3_trace_blocked_max + 1),
        };
        plan.client_grease = random.next();
        plan.server_grease = random.next();
        // The first request may open before the server's SETTINGS arrive, when no insert is
        // possible, or well after, when one is (RFC 9204 §3.2.3).
        var at: u64 = random.below(constants.h3_trace_act_steps * first_open_spans);
        for (0..plan.requests) |r| {
            at += random.below(constants.h3_trace_act_steps);
            plan.open_at[r] = at;
            plan.lines[r] = plan.draw_line(random, r);
            const cancels = random.below(constants.h3_trace_cancel_one_in) == 0;
            plan.cancel_at[r] = if (cancels) at + random.below(constants.h3_trace_act_steps) else null;
        }
        plan.goaways = @intCast(random.below(constants.h3_trace_goaways_max + 1));
        // A GOAWAY comes no sooner than the first request could, so most requests are answered.
        var goaway_at: u64 = constants.h3_trace_act_steps;
        for (plan.goaway_at[0..plan.goaways]) |*held| {
            goaway_at += random.below(constants.h3_trace_act_steps);
            held.* = goaway_at;
        }
        assert(plan.requests > 0 and plan.requests <= constants.h3_trace_requests_max);
    }

    /// A line may repeat only one an earlier request made new.
    fn draw_line(plan: *const Plan, random: *Random, r: usize) Line {
        const drawn: Line = @enumFromInt(random.below(@typeInfo(Line).@"enum".fields.len));
        if (drawn != .repeat) return drawn;
        return if (plan.last_new(r) == null) .new else .repeat;
    }

    /// The last request before `r` whose line was new, or null.
    pub fn last_new(plan: *const Plan, r: usize) ?usize {
        var found: ?usize = null;
        for (plan.lines[0..r], 0..) |line, earlier| {
            if (line == .new) found = earlier;
        }
        return found;
    }

    /// The inserts the client's encoder may make at most: the model's `MaxInserts`.
    pub fn inserts_max(plan: *const Plan) u32 {
        var count: u32 = 0;
        for (plan.lines[0..plan.requests]) |line| {
            if (line == .new) count += 1;
        }
        return count;
    }
};

const testing = std.testing;

/// The plan the tests draw, outside any stack frame. Test-only.
var test_plan: Plan = undefined;

test "a seed draws the same plan every time, and a line repeats only one made new" {
    for (0..constants.check_seeds_default) |seed| {
        var first = Random.init(seed);
        test_plan.draw(&first);
        const requests = test_plan.requests;
        const opens = test_plan.open_at;
        var again = Random.init(seed);
        test_plan.draw(&again);
        try testing.expectEqual(requests, test_plan.requests);
        try testing.expectEqualSlices(u64, opens[0..requests], test_plan.open_at[0..requests]);
        for (test_plan.lines[0..test_plan.requests], 0..) |line, r| {
            if (line == .repeat) try testing.expect(test_plan.last_new(r) != null);
            if (r > 0) try testing.expect(test_plan.open_at[r] >= test_plan.open_at[r - 1]);
        }
        try testing.expect(test_plan.inserts_max() <= test_plan.requests);
    }
}
