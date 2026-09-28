//! What one seed of the h2 trace run does (https://github.com/c4milo/colibri/issues/75): the scope
//! of `spec/tla/h2_connection` the seed stays in, and the actions it draws inside that scope.
//!
//! The scope is the model's constants: the streams the client opens, the DATA frames a message
//! carries, the interim heads a response carries, the GOAWAY frames the server sends, and whether
//! either endpoint resets streams. The run never asks for more than those bounds allow, because
//! the model has no transition past them, but it asks for every order the rules forbid: DATA
//! before a response's head, a head after the final one, a frame after END_STREAM or a reset, and
//! a stream after a GOAWAY. colibri must refuse each of those, and a call it takes shows as a state
//! the model cannot reach.
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");

const Random = sim.Random;
const limits = sim.constants.h2_trace;

/// One action the run draws: a write call at either endpoint, or a delivery of every frame one
/// direction holds. `stream` is the model's index, 1 to the plan's `streams`.
pub const Action = union(enum) {
    open: bool,
    client_data: Target,
    client_trailers: u32,
    client_reset: u32,
    server_interim: Target,
    server_final: Target,
    server_data: Target,
    server_trailers: u32,
    server_reset: u32,
    server_goaway,
    deliver_to_server,
    deliver_to_client,
};

/// A stream, and whether the frame the call writes carries END_STREAM.
pub const Target = struct {
    stream: u32,
    end: bool,
};

/// Each kind of action: `Action`'s tag.
pub const Kind = std.meta.Tag(Action);

/// How often each kind of action is drawn, against the others. Deliveries weigh most, so frames do
/// not pile up, and the client opens often enough for streams to overlap. The writes that end or
/// break a message's order weigh least.
const weights: std.EnumArray(Kind, u64) = .init(.{
    .open = weight_message,
    .client_data = weight_message,
    .client_trailers = weight_rare,
    .client_reset = weight_rare,
    .server_interim = weight_rare,
    .server_final = weight_message,
    .server_data = weight_message,
    .server_trailers = weight_rare,
    .server_reset = weight_rare,
    .server_goaway = weight_rare,
    .deliver_to_server = weight_delivery,
    .deliver_to_client = weight_delivery,
});
const weight_rare: u64 = 1;
const weight_message: u64 = 3;
const weight_delivery: u64 = 5;
const weights_total: u64 = total: {
    var sum: u64 = 0;
    for (weights.values) |weight| sum += weight;
    break :total sum;
};

/// One write call in this many carries END_STREAM.
const end_stream_one_in: u64 = 2;

pub const Plan = struct {
    /// The model's `N`, `Content`, `Interims`, `MaxGoaways` and `Resets`.
    streams: u32,
    content: u32,
    interims: u32,
    goaways: u32,
    resets: bool,
    /// Actions the run draws before it delivers what is left.
    actions: u32,

    pub fn draw(plan: *Plan, random: *Random) void {
        plan.streams = @intCast(random.between(1, limits.streams_max));
        plan.content = @intCast(random.below(limits.content_max + 1));
        plan.interims = @intCast(random.below(limits.interims_max + 1));
        plan.goaways = @intCast(random.below(limits.goaways_max + 1));
        plan.resets = random.below(limits.no_resets_one_in) != 0;
        plan.actions = @intCast(random.between(limits.actions_min, limits.actions_max));
        assert(plan.streams >= 1 and plan.streams <= limits.streams_max);
    }

    /// The next action, drawn from `random`.
    pub fn next_action(plan: *const Plan, random: *Random) Action {
        const stream: u32 = @intCast(random.between(1, plan.streams));
        const end = random.below(end_stream_one_in) == 0;
        const target: Target = .{ .stream = stream, .end = end };
        var drawn = random.below(weights_total);
        for (std.enums.values(Kind)) |kind| {
            const weight = weights.get(kind);
            if (drawn < weight) return action_of(kind, target);
            drawn -= weight;
        }
        unreachable;
    }
};

fn action_of(kind: Kind, target: Target) Action {
    return switch (kind) {
        .open => .{ .open = target.end },
        .client_data => .{ .client_data = target },
        .client_trailers => .{ .client_trailers = target.stream },
        .client_reset => .{ .client_reset = target.stream },
        .server_interim => .{ .server_interim = target },
        .server_final => .{ .server_final = target },
        .server_data => .{ .server_data = target },
        .server_trailers => .{ .server_trailers = target.stream },
        .server_reset => .{ .server_reset = target.stream },
        .server_goaway => .server_goaway,
        .deliver_to_server => .deliver_to_server,
        .deliver_to_client => .deliver_to_client,
    };
}

comptime {
    // Every kind of action can be drawn.
    for (weights.values) |weight| assert(weight > 0);
}

const testing = std.testing;

/// The plan the tests draw, outside any stack frame. Test-only.
var test_plan: Plan align(@alignOf(Plan)) = undefined;

test "a seed draws the same plan and actions every time, inside the model's scope" {
    for (0..sim.constants.check_seeds_default) |seed| {
        var first = Random.init(seed);
        test_plan.draw(&first);
        const drawn = test_plan;
        const action = test_plan.next_action(&first);
        var again = Random.init(seed);
        test_plan.draw(&again);
        try testing.expectEqual(drawn, test_plan);
        try testing.expectEqual(action, test_plan.next_action(&again));
        try testing.expect(test_plan.streams <= limits.streams_max and test_plan.goaways <= limits.goaways_max);
    }
}
