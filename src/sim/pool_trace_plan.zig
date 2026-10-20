//! One seed's plan for the pool trace run (decision 105, design §8 step 22): the TCP slots the
//! pool holds, the exchanges the caller makes and cancels, how the server answers each request,
//! which slot's first connect fails, and when the caller shuts the pool down. The plan is drawn
//! from the seed alone before the run, so a seed replays (invariant 5).
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");

const Random = sim.Random;
const limits = sim.constants.pool_trace;

/// How the server answers a request it read.
pub const Answer = enum {
    /// It processes the request and sends the response.
    respond,
    /// It processes the request and answers with `Connection: close`, after which the connection
    /// takes no new request (RFC 9112 §9.6).
    close,
    /// It processes the request, then closes the connection before any of the response.
    @"break",
};

pub const Plan = struct {
    /// TCP slots the pool holds, and requests the caller makes: the model's `TcpSlots` and `N`.
    slots: u32,
    requests: u32,
    /// The instant each exchange is made, and the instant it is cancelled, if it is.
    make_at: [limits.requests_max]u32,
    cancel_at: [limits.requests_max]?u32,
    /// Whether each request is a POST, which RFC 9110 §9.2.2 does not let the pool send again.
    post: [limits.requests_max]bool,
    /// How the server answers each exchange's request, each time it reads it.
    answers: [limits.requests_max]Answer,
    /// Whether each slot's first connect fails.
    connect_fails: [limits.slots_max]bool,
    /// The instant the caller shuts the pool down.
    shutdown_at: u32,

    pub fn draw(plan: *Plan, random: *Random) void {
        plan.slots = limits.slots_min + @as(u32, @intCast(random.below(limits.slots_max - limits.slots_min + 1)));
        plan.requests = limits.requests_min + @as(u32, @intCast(random.below(limits.requests_max - limits.requests_min + 1)));
        var last_make: u32 = 0;
        for (0..limits.requests_max) |index| {
            plan.make_at[index] = @intCast(random.below(limits.make_window));
            plan.cancel_at[index] = null;
            if (random.below(limits.cancel_one_in) == 0) {
                plan.cancel_at[index] = plan.make_at[index] + @as(u32, @intCast(random.below(limits.cancel_after_max)));
            }
            plan.post[index] = random.below(limits.post_one_in) == 0;
            plan.answers[index] = draw_answer(random);
            if (index < plan.requests) last_make = @max(last_make, plan.make_at[index]);
        }
        for (&plan.connect_fails) |*fails| fails.* = random.below(limits.connect_fail_one_in) == 0;
        plan.shutdown_at = last_make + 1 + @as(u32, @intCast(random.below(limits.shutdown_after_max)));
    }

    fn draw_answer(random: *Random) Answer {
        if (random.below(limits.break_one_in) == 0) return .@"break";
        if (random.below(limits.close_one_in) == 0) return .close;
        return .respond;
    }

    /// Whether exchange `index`'s method is idempotent (RFC 9110 §9.2.2).
    pub fn idempotent(plan: *const Plan, index: usize) bool {
        assert(index < plan.requests);
        return !plan.post[index];
    }

    /// The answers that end a connection with `Connection: close`, which the model counts as
    /// GOAWAY frames.
    pub fn closes(plan: *const Plan) u32 {
        var counted: u32 = 0;
        for (plan.answers[0..plan.requests]) |answer| counted += @intFromBool(answer == .close);
        return counted;
    }
};
