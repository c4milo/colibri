//! What one seed of the deadline trace run does (https://github.com/c4milo/colibri/issues/86): the
//! constants of `spec/tla/server_deadlines` the seed runs under, and the actions it draws.
//!
//! A seed draws the streams the client opens, the DATA each request and each response carries, the
//! octets the application offers write_body at once, the octets in flight each way, and whether
//! the client opens a stream before it has read the last response. The model's other constants
//! are colibri's own: its windows and thresholds, the floor, the frame size and its output.
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");

const Random = sim.Random;
const limits = sim.constants.deadline_trace;

/// One action the run draws. `stream` is the model's index, 1 to the plan's `streams`.
pub const Action = union(enum) {
    /// The client writes what it owes, then opens its next stream.
    open,
    /// The client writes what it owes, then sends a DATA frame on `stream`.
    upload: u32,
    /// The client writes what it owes.
    settle,
    /// The client reads the oldest frame toward it.
    read,
    /// The oldest frame toward colibri arrives, and colibri reads it.
    arrive,
    /// colibri's caller hands the socket the oldest frame colibri's output holds.
    hand_out,
    /// The application answers `stream`'s request with its head.
    respond: u32,
    /// The application offers write_body the next `produce_step` octets of `stream`'s response.
    produce: u32,
};

/// Each kind of action: `Action`'s tag.
pub const Kind = std.meta.Tag(Action);

/// How often each kind of action is drawn, against the others. Deliveries weigh most, so frames do
/// not pile up, and the client opens and colibri answers least, once a stream.
const weights: std.EnumArray(Kind, u64) = .init(.{
    .open = weight_rare,
    .upload = weight_common,
    .settle = weight_common,
    .read = weight_delivery,
    .arrive = weight_delivery,
    .hand_out = weight_delivery,
    .respond = weight_rare,
    .produce = weight_common,
});
const weight_rare: u64 = 1;
const weight_common: u64 = 3;
const weight_delivery: u64 = 5;
const weights_total: u64 = total: {
    var sum: u64 = 0;
    for (weights.values) |weight| sum += weight;
    break :total sum;
};

/// One plan in this many carries short bodies, which the windows never hold.
const short_bodies_one_in: u64 = 4;
/// The longest short body.
const short_body_len_max: u32 = 2_000;
/// One plan in this many has the client open a stream before it has read the last response.
const pipelining_one_in: u64 = 2;

pub const Plan = struct {
    /// The model's `StreamCount`, `RequestBody`, `ResponseBody`, `ProduceStep`, `ChannelLen` and
    /// `Pipelining`.
    streams: u32,
    request_body: u32,
    response_body: u32,
    produce_step: u32,
    channel_len: u32,
    pipelining: bool,
    /// Actions the run draws before it drains.
    actions: u32,

    pub fn draw(plan: *Plan, random: *Random) void {
        plan.streams = @intCast(random.between(1, limits.streams_max));
        const body_len_max = if (random.below(short_bodies_one_in) == 0) short_body_len_max else limits.body_len_max;
        plan.request_body = @intCast(random.below(body_len_max + 1));
        plan.response_body = @intCast(random.between(1, body_len_max));
        plan.produce_step = @intCast(random.between(limits.produce_step_min, limits.produce_step_max));
        plan.channel_len = @intCast(random.between(limits.channel_len_min, limits.channel_len_max));
        plan.pipelining = random.below(pipelining_one_in) == 0;
        plan.actions = @intCast(random.between(limits.actions_min, limits.actions_max));
        assert(plan.streams >= 1 and plan.streams <= limits.streams_max);
        assert(plan.response_body >= 1);
    }

    /// The next action, drawn from `random`.
    pub fn next_action(plan: *const Plan, random: *Random) Action {
        const stream: u32 = @intCast(random.between(1, plan.streams));
        var drawn = random.below(weights_total);
        for (std.enums.values(Kind)) |kind| {
            const weight = weights.get(kind);
            if (drawn < weight) return action_of(kind, stream);
            drawn -= weight;
        }
        unreachable;
    }
};

fn action_of(kind: Kind, stream: u32) Action {
    return switch (kind) {
        .open => .open,
        .upload => .{ .upload = stream },
        .settle => .settle,
        .read => .read,
        .arrive => .arrive,
        .hand_out => .hand_out,
        .respond => .{ .respond = stream },
        .produce => .{ .produce = stream },
    };
}

comptime {
    // Every kind of action can be drawn.
    for (weights.values) |weight| assert(weight > 0);
    assert(short_body_len_max < limits.body_len_max);
}

const testing = std.testing;

test "a plan stays inside the model's constants, and every kind of action is drawn" {
    var random = Random.init(1);
    var drawn: std.EnumArray(Kind, bool) = .initFill(false);
    for (0..limits.actions_max) |seed| {
        random = Random.init(seed);
        var plan: Plan = undefined;
        plan.draw(&random);
        try testing.expect(plan.request_body <= limits.body_len_max and plan.response_body <= limits.body_len_max);
        try testing.expect(plan.channel_len >= limits.channel_len_min and plan.channel_len <= limits.channel_len_max);
        drawn.set(std.meta.activeTag(plan.next_action(&random)), true);
    }
    for (drawn.values) |seen| try testing.expect(seen);
}
