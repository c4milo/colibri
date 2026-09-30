//! The deadline trace run (https://github.com/c4milo/colibri/issues/86): a colibri h2 client and a
//! colibri server connection act out a seed's `deadline_trace_plan.zig`, one queue of octets each
//! way, and an application answers each request. After the plan's actions the run drains: each
//! side acts in turn until a round changes nothing.
//!
//! After each action the run computes the state of `spec/tla/server_deadlines`'s model, colibri's
//! clocks included (`deadline_trace_state.zig`), and keeps it when it differs from the last one
//! kept. That trace is what `deadline_trace_tla.zig` writes for TLC, which checks that the model
//! goes through the same states and that each of colibri's clocks runs exactly when the model's
//! rule for it says. Two honest endpoints never cancel a request or fail the connection, so either
//! is a violation here too, found without TLC. A log that stops early is still a behavior of the
//! model, so the run also requires the drain to end with every exchange finished at both
//! endpoints, no frame in flight or in colibri's output, and no reply owed.
//!
//! Each seed runs twice and must go through the same states, which is invariant 5.
const std = @import("std");
const assert = std.debug.assert;
const server = @import("server");
const sim = @import("sim");
const plan_module = @import("deadline_trace_plan.zig");
const world_module = @import("deadline_trace_world.zig");
const state_module = @import("deadline_trace_state.zig");

const Random = sim.Random;
const limits = sim.constants.deadline_trace;
const Plan = plan_module.Plan;
const Action = plan_module.Action;
const State = state_module.State;

pub const Violation = state_module.Error || error{
    /// The server connection refused to start.
    StartRefused,
    /// A request was cancelled, the connection failed, or a HEADERS frame changed length: none
    /// happens between two honest colibri endpoints.
    Broken,
    /// The run went through more of the model's states than `states_max`.
    TraceFull,
    /// The drain ended with an exchange unfinished, a frame in flight or in colibri's output, or a
    /// reply owed.
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

/// One seed's counts: the states it went through, the requests the client sent whole and the
/// responses it read whole, and the states in which a body's rate or a stream's send ran.
pub const Result = struct {
    states: u64 = 0,
    requests: u64 = 0,
    responses: u64 = 0,
    bodies_timed: u64 = 0,
    sends_timed: u64 = 0,
};

pub const Census = struct {
    seeds: u64 = 0,
    states: u64 = 0,
    requests: u64 = 0,
    responses: u64 = 0,
    bodies_timed: u64 = 0,
    sends_timed: u64 = 0,

    fn count(census: *Census, result: Result) void {
        census.seeds += 1;
        census.states += result.states;
        census.requests += result.requests;
        census.responses += result.responses;
        census.bodies_timed += result.bodies_timed;
        census.sends_timed += result.sends_timed;
    }
};

comptime {
    // No deadline passes during a run: the longest takes less than decision 110's shortest
    // default limit, so every clock the trace logs is one that runs, not one that fired.
    assert(limits.run_ns_max < server.constants.first_request_timeout_ns);
    assert(limits.run_ns_max < server.constants.head_timeout_ns);
    assert(limits.run_ns_max < server.constants.rate_grace_ns);
}

/// Runs one seed twice and returns the first run's counts.
pub fn run_seed(storage: *Storage, seed: u64) Violation!Result {
    const first = try run_once(storage, seed);
    const first_len = storage.states_len;
    @memcpy(storage.first[0..first_len], storage.states[0..first_len]);
    const second = try run_once(storage, seed);
    if (second.states != first.states) return error.ReplayDiverged;
    for (storage.first[0..first_len], storage.states[0..first_len]) |*before, *again| {
        if (!std.meta.eql(before.*, again.*)) return error.ReplayDiverged;
    }
    return first;
}

fn run_once(storage: *Storage, seed: u64) Violation!Result {
    var random = Random.init(seed);
    storage.plan.draw(&random);
    storage.world.init(seed) catch return error.StartRefused;
    storage.states_len = 0;
    try record(storage);
    for (0..storage.plan.actions) |_| {
        storage.world.act(storage.plan.next_action(&random), &storage.plan);
        try record(storage);
    }
    for (0..limits.drain_rounds_max) |_| {
        const before = storage.states_len;
        try drain_round(storage);
        if (storage.states_len == before) break;
    }
    if (!finished(&storage.states[storage.states_len - 1], storage.plan.streams)) return error.Unfinished;
    return result_of(storage);
}

/// Whether `last` has every exchange finished at both endpoints, nothing in flight or in colibri's
/// output, nothing owed on either side, and colibri's SETTINGS acknowledged.
fn finished(last: *const State, streams: u32) bool {
    for (0..streams) |index| {
        if (last.req_read[index] != .ended or last.resp[index] != .ended) return false;
        if (last.cli_req[index] != .ended or last.cli_resp[index] != .ended) return false;
    }
    if (last.out.len > 0 or last.to_client.len > 0 or last.to_server.len > 0) return false;
    return last.settings_acked and owes_nothing(&last.colibri) and owes_nothing(&last.client);
}

fn owes_nothing(side: *const state_module.Side) bool {
    return side.acks_owed == 0 and side.connection_owed == 0 and side.stream_owed.len == 0;
}

/// One round of the drain: the client settles, opens and uploads, colibri reads and hands out,
/// the client reads, and the application answers and offers content, each at most once.
fn drain_round(storage: *Storage) Violation!void {
    const streams = storage.plan.streams;
    try act(storage, .settle);
    try act(storage, .open);
    for (1..streams + 1) |stream| try act(storage, .{ .upload = @intCast(stream) });
    try act(storage, .arrive);
    try act(storage, .hand_out);
    try act(storage, .read);
    for (1..streams + 1) |stream| {
        try act(storage, .{ .respond = @intCast(stream) });
        try act(storage, .{ .produce = @intCast(stream) });
    }
}

fn act(storage: *Storage, action: Action) Violation!void {
    storage.world.act(action, &storage.plan);
    try record(storage);
}

/// Keeps the model's state after an action when it differs from the last one kept, and fails the
/// run on what two honest endpoints never do.
fn record(storage: *Storage) Violation!void {
    if (storage.world.broken) return error.Broken;
    const previous: ?*const State = if (storage.states_len > 0) &storage.states[storage.states_len - 1] else null;
    const state = try state_module.compute(&storage.world, storage.plan.streams, previous);
    if (previous) |last| {
        if (std.meta.eql(last.*, state)) return;
    }
    if (storage.states_len == storage.states.len) return error.TraceFull;
    storage.states[storage.states_len] = state;
    storage.states_len += 1;
}

fn result_of(storage: *const Storage) Result {
    var result: Result = .{ .states = storage.states_len };
    const last = &storage.states[storage.states_len - 1];
    for (0..storage.plan.streams) |index| {
        if (last.cli_req[index] == .ended) result.requests += 1;
        if (last.cli_resp[index] == .ended) result.responses += 1;
    }
    for (storage.trace()) |*state| {
        for (state.body_runs[0..storage.plan.streams]) |runs| result.bodies_timed += @intFromBool(runs);
        for (state.send_runs[0..storage.plan.streams]) |runs| result.sends_timed += @intFromBool(runs);
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

test "deadline trace run: honest endpoints finish their exchanges, replay, and time bodies and sends" {
    var census: Census = .{};
    var failed_seed: ?u64 = null;
    run_check(&test_storage, limits.written_seeds, &census, &failed_seed) catch |failure| {
        std.debug.print("deadline-trace: seed 0x{x} failed: {t}\n", .{ failed_seed.?, failure });
        return failure;
    };
    // Every seed finished each exchange, so each stream counts one request and one response.
    try testing.expect(census.responses > 0 and census.requests == census.responses);
    // The runs reach the states the clocks' rules are about.
    try testing.expect(census.bodies_timed > 0 and census.sends_timed > 0);
}
