//! What one seed of the h3 deadline trace run does (design §8 step 20d): the constants of
//! `spec/tla/h3_deadlines` the seed runs under, and the actions it draws.
//!
//! A seed draws the request streams the client opens, the units of each request's head and
//! content, the units of each response, how many of each the client sends and the application
//! writes, and the order the drain takes the client's units, the application's writes and time
//! in. The run then draws each action from those the world allows at that moment, so a seed's
//! actions depend on what colibri did, and replay with it. A client that stops short, or a drain
//! that moves time before the client acts, is one whose head and body deadlines pass; an
//! application that stops short is one whose connection drains at the shutdown.
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");

const Random = sim.Random;
const limits = sim.constants.h3_deadline_trace;

/// One action the run takes. `request` is the model's index, 0 to the plan's `requests` less 1.
pub const Action = union(enum) {
    /// The client opens its next request stream and sends the first unit of its head.
    open,
    /// The client sends the next unit of `request`.
    unit: u32,
    /// The oldest datagram toward the server arrives, and colibri reads it and writes what it owes.
    to_server,
    /// The oldest datagram toward the client arrives, and the client reads it and acknowledges.
    to_client,
    /// The application writes the next unit of its answer to `request`.
    write: u32,
    /// The program shuts the connection down.
    shutdown,
    /// Time moves on to the next instant either side is due at, with no datagram in flight.
    wait,
};

/// Each kind of action: `Action`'s tag.
pub const Kind = std.meta.Tag(Action);

/// The kinds the drain orders after its deliveries.
const drain_kinds = [_]Kind{ .unit, .write, .wait };

/// One plan in this many may move time before its client opens a request, and one request in
/// this many stops short of what it would send or write.
const idle_start_one_in: u64 = 8;
const stops_one_in: u64 = 3;

/// `all`, or in one draw in `stops_one_in` fewer: a client that stops inside a head or a body, or
/// an application that stops inside an answer, or before it.
fn short_of(random: *Random, all: u32) u32 {
    if (random.below(stops_one_in) != 0) return all;
    return @intCast(random.below(all));
}

/// How often each kind of action is drawn, against the others. Deliveries weigh most, so datagrams
/// do not pile up, and the program's shutdown least, so most runs reach their deadlines first.
const weights: std.EnumArray(Kind, u64) = .init(.{
    .open = weight_common,
    .unit = weight_common,
    .to_server = weight_delivery,
    .to_client = weight_delivery,
    .write = weight_common,
    .shutdown = weight_rare,
    .wait = weight_time,
});
const weight_rare: u64 = 1;
const weight_time: u64 = 2;
const weight_common: u64 = 4;
const weight_delivery: u64 = 8;

pub const Plan = struct {
    requests: u32,
    head_units: u32,
    content_units: u32,
    response_units: u32,
    /// Actions drawn before the drain.
    actions: u32,
    /// The order the drain takes the client's units, the application's writes and time in, after
    /// it delivered what is in flight.
    drain_order: [drain_kinds.len]Kind,
    /// Whether the run may move time, or shut down, before the client opens its first request,
    /// which reaches the first-request deadline. Other runs draw neither until then.
    idle_start: bool,
    /// The units of each request the client sends, and of each answer the application writes:
    /// all of them, or in one request in `stops_one_in` fewer.
    client_units: [limits.requests_max]u32,
    answer_units: [limits.requests_max]u32,

    pub fn draw(plan: *Plan, random: *Random) void {
        plan.* = .{
            .requests = @intCast(random.between(1, limits.requests_max)),
            .head_units = @intCast(random.between(1, limits.head_units_max)),
            .content_units = @intCast(random.below(limits.content_units_max + 1)),
            .response_units = @intCast(random.between(1, limits.response_units_max)),
            .actions = @intCast(random.between(limits.actions_min, limits.actions_max)),
            .drain_order = drain_kinds,
            .idle_start = random.below(idle_start_one_in) == 0,
            .client_units = undefined,
            .answer_units = undefined,
        };
        for (&plan.client_units, &plan.answer_units) |*sent, *written| {
            // Opening a request stream sends its first unit, so the client sends one at least.
            sent.* = @max(1, short_of(random, plan.units()));
            written.* = short_of(random, plan.response_units);
        }
        // A Fisher-Yates shuffle of the three.
        var left: usize = drain_kinds.len;
        while (left > 1) : (left -= 1) {
            const chosen = random.below(left);
            std.mem.swap(Kind, &plan.drain_order[left - 1], &plan.drain_order[chosen]);
        }
    }

    /// The units of one request: its head, then its content.
    pub fn units(plan: *const Plan) u32 {
        return plan.head_units + plan.content_units;
    }
};

/// Draws one of `allowed`, each kind weighed by `weights`, or null when none is allowed. Before the
/// client opened a request, a plan without `idle_start` draws neither time nor the shutdown.
pub fn pick(random: *Random, plan: *const Plan, opened: bool, allowed: []const Action) ?Action {
    var total: u64 = 0;
    for (allowed) |action| total += weight_of(plan, opened, action);
    if (total == 0) return null;
    var point = random.below(total);
    for (allowed) |action| {
        const weight = weight_of(plan, opened, action);
        if (point < weight) return action;
        point -= weight;
    }
    unreachable;
}

fn weight_of(plan: *const Plan, opened: bool, action: Action) u64 {
    const waits = action == .wait or action == .shutdown;
    if (waits and !opened and !plan.idle_start) return 0;
    return weights.get(action);
}

const testing = std.testing;

test "h3 deadline trace plan: a seed draws a scope within the limits, and a pick is one allowed" {
    var random = Random.init(0);
    var plan: Plan = undefined;
    plan.draw(&random);
    try testing.expect(plan.requests >= 1 and plan.requests <= limits.requests_max);
    try testing.expect(plan.units() >= 1 and plan.units() <= limits.head_units_max + limits.content_units_max);
    const allowed = [_]Action{ .to_server, .{ .write = 1 } };
    const picked = pick(&random, &plan, true, &allowed).?;
    try testing.expect(picked == .to_server or picked == .write);
    try testing.expectEqual(null, pick(&random, &plan, true, &.{}));
    plan.idle_start = false;
    try testing.expectEqual(null, pick(&random, &plan, false, &.{.wait}));
    try testing.expectEqual(Action.wait, pick(&random, &plan, true, &.{.wait}).?);
}
