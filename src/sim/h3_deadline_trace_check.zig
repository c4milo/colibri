//! The h3 deadline trace run (design §8 step 20d): an honest client and a colibri server
//! connection act out a seed's `h3_deadline_trace_plan.zig` over a queue of datagrams each way,
//! and an application answers each request a unit at a time. After the plan's actions the run
//! drains: it delivers what is in flight, sends what the client has left, writes what the
//! application has left, and moves time on, until the client reads the server's close.
//!
//! After each action the run computes the logged state of `spec/tla/h3_deadlines`'s model
//! (`h3_deadline_trace_state.zig`) and keeps it when it differs from the last one kept. That trace
//! is what `h3_deadline_trace_tla.zig` writes for TLC, which checks that the model goes through
//! the same states and that each of colibri's clocks runs exactly when the model's rule says. An
//! honest exchange never fails the connection or has an answer refused, so either is a violation
//! here too, found without TLC, and so is a run whose client never reads the close.
//!
//! Each seed runs twice and must go through the same states, which is invariant 5.
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");
const plan_module = @import("h3_deadline_trace_plan.zig");
const world_module = @import("h3_deadline_trace_world.zig");
const state_module = @import("h3_deadline_trace_state.zig");

const Random = sim.Random;
const limits = sim.constants.h3_deadline_trace;
const Plan = plan_module.Plan;
const Action = plan_module.Action;
const State = state_module.State;

pub const Violation = world_module.Error || state_module.Error || error{
    /// The connection failed, an answer was refused, or a request could not open: none happens
    /// between an honest client and colibri.
    Broken,
    /// The run went through more of the model's states than `states_max`.
    TraceFull,
    /// The drain ended before the client read the server's close.
    Unfinished,
    /// The seed's second run went through different states from its first (invariant 5).
    ReplayDiverged,
};

/// The storage one seed runs in, outside any stack frame (decision 35).
pub const Storage = struct {
    plan: Plan,
    world: world_module.World,
    /// The model's states the last run went through, each one differing from the one before, and
    /// the first run's, which the second must repeat.
    states: [limits.states_max]State,
    states_len: usize,
    first: [limits.states_max]State,

    /// The last run's trace.
    pub fn trace(storage: *const Storage) []const State {
        return storage.states[0..storage.states_len];
    }
};

/// One seed's counts: the states it went through, the requests the client opened, what it learned
/// of them, and how colibri closed.
pub const Result = struct {
    states: u64 = 0,
    opened: u64 = 0,
    responses: u64 = 0,
    timeouts: u64 = 0,
    rejected: u64 = 0,
    cancelled: u64 = 0,
    drained: u64 = 0,
    drain_passed: u64 = 0,
};

pub const Census = struct {
    seeds: u64 = 0,
    total: Result = .{},

    fn count(census: *Census, result: Result) void {
        census.seeds += 1;
        inline for (std.meta.fields(Result)) |field| {
            @field(census.total, field.name) += @field(result, field.name);
        }
    }
};

/// Runs one seed twice and returns the first run's counts.
pub fn run_seed(storage: *Storage, seed: u64) Violation!Result {
    const first = try run_once(storage, seed);
    const first_len = storage.states_len;
    @memcpy(storage.first[0..first_len], storage.states[0..first_len]);
    _ = try run_once(storage, seed);
    if (storage.states_len != first_len) return error.ReplayDiverged;
    for (storage.first[0..first_len], storage.states[0..first_len]) |*before, *again| {
        if (!std.meta.eql(before.*, again.*)) return error.ReplayDiverged;
    }
    return first;
}

fn run_once(storage: *Storage, seed: u64) Violation!Result {
    var random = Random.init(seed);
    storage.plan.draw(&random);
    try storage.world.init(seed);
    storage.states_len = 0;
    try record(storage);
    var listed: [world_module.allowed_max]Action = undefined;
    for (0..storage.plan.actions) |_| {
        const allowed = storage.world.allowed(&storage.plan, &listed);
        const opened = storage.world.peer.fetches_len > 0;
        const action = plan_module.pick(&random, &storage.plan, opened, allowed) orelse break;
        try act(storage, action);
    }
    for (0..limits.drain_actions_max) |_| {
        const allowed = storage.world.allowed(&storage.plan, &listed);
        try act(storage, drain_action(&storage.plan, allowed) orelse break);
    }
    if (storage.world.peer.close == null) return error.Unfinished;
    return result_of(storage);
}

/// The drain's next action: a delivery toward the client, then one toward the server, then the
/// first the plan's drain order allows, and last the shutdown, which a connection whose
/// application stopped short of an answer needs to end.
fn drain_action(plan: *const Plan, allowed: []const Action) ?Action {
    const deliveries = [_]plan_module.Kind{ .to_client, .to_server };
    for (deliveries ++ plan.drain_order ++ [_]plan_module.Kind{.shutdown}) |kind| {
        for (allowed) |action| {
            if (action == kind) return action;
        }
    }
    return null;
}

fn act(storage: *Storage, action: Action) Violation!void {
    try storage.world.act(&storage.plan, action);
    try record(storage);
}

/// Keeps the model's state after an action when it differs from the last one kept, and fails the
/// run on what an honest exchange never does.
fn record(storage: *Storage) Violation!void {
    if (storage.world.broken) return error.Broken;
    const state = try state_module.compute(&storage.world, &storage.plan);
    if (storage.states_len > 0) {
        if (std.meta.eql(storage.states[storage.states_len - 1], state)) return;
    }
    if (storage.states_len == storage.states.len) return error.TraceFull;
    storage.states[storage.states_len] = state;
    storage.states_len += 1;
}

fn result_of(storage: *const Storage) Result {
    const last = &storage.states[storage.states_len - 1];
    var result: Result = .{ .states = storage.states_len, .opened = last.opened };
    for (last.outcome[0..storage.plan.requests]) |outcome| {
        switch (outcome) {
            .none => {},
            .response => result.responses += 1,
            .timeout => result.timeouts += 1,
            .rejected => result.rejected += 1,
            .cancelled => result.cancelled += 1,
        }
    }
    switch (last.closed) {
        .open => {},
        .drained => result.drained += 1,
        .drain => result.drain_passed += 1,
    }
    return result;
}

/// Runs seeds `[0, seeds)` in order. On a violation, `failed_seed` names the seed.
pub fn run_check(storage: *Storage, seeds: u64, census: *Census, failed_seed: *?u64) Violation!void {
    for (0..seeds) |seed| {
        failed_seed.* = seed;
        census.count(try run_seed(storage, seed));
    }
    failed_seed.* = null;
    assert(census.seeds == seeds);
}

const testing = std.testing;

/// The storage the check test runs in, outside any stack frame.
var test_storage: Storage align(@alignOf(Storage)) = undefined;

test "h3 deadline trace run: an honest client's runs end in the server's close, and replay" {
    var census: Census = .{};
    var failed_seed: ?u64 = null;
    run_check(&test_storage, limits.written_seeds, &census, &failed_seed) catch |failure| {
        std.debug.print("h3-deadline-trace: seed 0x{x} failed: {t}\n", .{ failed_seed.?, failure });
        return failure;
    };
    // The runs reach whole responses, the deadlines' 408s and rejections, and both closes.
    const total = census.total;
    try testing.expect(total.responses > 0 and total.timeouts > 0 and total.rejected > 0);
    try testing.expect(total.drained > 0);
}
