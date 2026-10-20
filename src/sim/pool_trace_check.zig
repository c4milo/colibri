//! The pool trace run (decision 105 as decision 125 extends it, design §8 step 22): a
//! `client.PoolOf(.{ .quic = false })` of two or three TCP slots carries a seed's exchanges in h11,
//! one at a time on each connection, while the server answers, closes after an answer or before
//! one, and a slot's first connect may fail (`pool_trace_world.zig`). After each act and each event
//! the run computes spec/tla/client_exchanges's state (`pool_trace_state.zig`) and keeps it when it
//! differs from the last one kept, which is the trace `pool_trace_tla.zig` writes for TLC.
//!
//! The model's safety property is checked here too, without TLC, and every seed must end with
//! the pool closed and each exchange reported once or cancelled. Each seed runs twice and must go
//! through the same states (invariant 5).
const std = @import("std");
const assert = std.debug.assert;
const client = @import("client");
const sim = @import("sim");
const world_module = @import("pool_trace_world.zig");
const state_module = @import("pool_trace_state.zig");
const plan_module = @import("pool_trace_plan.zig");

const limits = sim.constants.pool_trace;
const World = world_module.World;
const Plan = plan_module.Plan;
const State = state_module.State;
const Tracker = state_module.Tracker;

pub const Violation = world_module.Error || error{
    /// The world refused to start.
    Stuck,
    /// The caller heard `refused` for an exchange a server processed, two servers processed a
    /// request that is not idempotent, or an exchange moved more than `moves_max` times
    /// (decision 124).
    RefusedProcessed,
    ProcessedTwice,
    MovedTooOften,
    /// A connection closed while it held an exchange, or held more than one at once (decision
    /// 125).
    ClosedHolding,
    HeldTwo,
    /// The run moved through more instants than `instants_max`, or kept more states than
    /// `states_max`.
    Unfinished,
    TraceFull,
    /// The run ended with the pool open, or an exchange neither reported nor cancelled.
    NotClosed,
    NotReported,
    /// The seed's second run went through different states from its first (invariant 5).
    ReplayDiverged,
};

/// The storage one seed runs in, outside any stack frame (decision 35).
pub const Storage = struct {
    world: World,
    tracker: Tracker,
    states: [limits.states_max]State,
    states_len: usize,
    first: [limits.states_max]State,

    pub fn trace(storage: *const Storage) []const State {
        return storage.states[0..storage.states_len];
    }
};

/// One seed's counts.
pub const Result = struct {
    states: u64 = 0,
    requests: u64 = 0,
    responses: u64 = 0,
    refused: u64 = 0,
    closed: u64 = 0,
    cancelled: u64 = 0,
    moved: u64 = 0,
    /// TCP connections the pool opened, and seeds whose pool opened a connection in more than one
    /// slot.
    connections: u64 = 0,
    grown: u64 = 0,
};

pub const Census = struct {
    seeds: u64 = 0,
    result: Result = .{},

    fn count(census: *Census, result: Result) void {
        census.seeds += 1;
        inline for (std.meta.fields(Result)) |field| {
            @field(census.result, field.name) += @field(result, field.name);
        }
    }
};

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
    const world = &storage.world;
    world.init(seed) catch return error.Stuck;
    storage.tracker.init();
    storage.states_len = 0;
    try record(storage);
    const observer: Observer = .{ .storage = storage };
    for (0..limits.instants_max) |_| {
        if (world.closed) break;
        try world.step(observer);
    } else return error.Unfinished;
    try check_end(world);
    return result_of(storage);
}

/// What the world calls after each act and each event.
const Observer = struct {
    storage: *Storage,

    pub fn observe(observer: Observer) Violation!void {
        try record(observer.storage);
    }
};

/// Keeps the model's state now when it differs from the last one kept, and fails the run on what
/// the model's safety property forbids.
fn record(storage: *Storage) Violation!void {
    storage.tracker.update(&storage.world);
    const state = state_module.compute(&storage.world, &storage.tracker);
    try check_safe(&state, &storage.world.plan);
    if (storage.states_len > 0 and std.meta.eql(storage.states[storage.states_len - 1], state)) return;
    if (storage.states_len == storage.states.len) return error.TraceFull;
    storage.states[storage.states_len] = state;
    storage.states_len += 1;
}

/// spec/tla/client_exchanges's Safe, over this state: no closed connection holds an exchange or
/// drops a response, and none holds more than one at once.
fn check_safe(state: *const State, plan: *const Plan) Violation!void {
    var held: [limits.slots_max]u32 = @splat(0);
    for (0..plan.requests) |index| {
        try check_processed(state, index, plan.idempotent(index));
        const carrier = state.carrier[index] orelse continue;
        // The model's Held(t) and Dropping(t): an h11 connection keeps a cancelled exchange's room
        // until it drops the response.
        const carried = state.stage[index] == .queued or state.stage[index] == .sent or state.stage[index] == .ended;
        if (!carried and !state.drops[index]) continue;
        if (state.phase[carrier] == .closed) return error.ClosedHolding;
        held[carrier] += 1;
    }
    // Decision 125: an h11 connection in a pool of several slots holds one exchange at a time.
    for (held[0..plan.slots]) |count| {
        if (count > 1) return error.HeldTwo;
    }
}

/// Safe's rules of what a server processed and how often an exchange moved. The caller hears
/// `refused` only for an exchange no server processed. Decision 124: the pool sends an idempotent
/// request again once, so two servers may process it, and no other request is processed twice.
fn check_processed(state: *const State, index: usize, idempotent: bool) Violation!void {
    const refused = state.outcome[index] == .refused;
    if (refused and state.seen[index]) return error.RefusedProcessed;
    if (refused and state.stage[index] == .reported and state.processed[index] > 0) return error.RefusedProcessed;
    if (state.processed[index] > 1 and !idempotent) return error.ProcessedTwice;
    if (state.moved[index] > client.constants.moves_max) return error.MovedTooOften;
}

fn check_end(world: *const World) Violation!void {
    if (!world.closed) return error.NotClosed;
    for (0..world.plan.requests) |index| {
        if (!world.reported[index] and !world.cancelled[index]) return error.NotReported;
    }
}

fn result_of(storage: *const Storage) Result {
    const world = &storage.world;
    var result: Result = .{ .states = storage.states_len, .requests = world.plan.requests };
    var slots_used: u32 = 0;
    for (world.pool.tcp_links[0..world.plan.slots]) |link| {
        result.connections += link.opens;
        slots_used += @intFromBool(link.opens > 0);
    }
    result.grown = @intFromBool(slots_used > 1);
    const last = &storage.states[storage.states_len - 1];
    for (0..world.plan.requests) |index| {
        result.cancelled += @intFromBool(world.cancelled[index]);
        result.moved += last.moved[index];
        if (!world.reported[index]) continue;
        switch (world.responses[index].outcome) {
            .response => result.responses += 1,
            .refused => result.refused += 1,
            else => result.closed += 1,
        }
    }
    return result;
}

/// Runs seeds `[0, seeds)` in order. On a violation, `failed_seed` names the seed.
pub fn run_check(storage: *Storage, seeds: u64, census: *Census, failed_seed: *?u64) Violation!void {
    for (0..seeds) |seed| {
        failed_seed.* = seed;
        const result = try run_seed(storage, seed);
        census.count(result);
    }
    failed_seed.* = null;
    assert(census.seeds == seeds);
}

const testing = std.testing;

/// The storage the check test runs in, outside any stack frame.
var test_storage: Storage align(@alignOf(Storage)) = undefined;

test "pool trace run: every seed closes the pool with each exchange reported once or cancelled" {
    var census: Census = .{};
    var failed_seed: ?u64 = null;
    run_check(&test_storage, sim.constants.check_seeds_default, &census, &failed_seed) catch |failure| {
        std.debug.print("pool trace run: seed 0x{x} failed: {t}\n", .{ failed_seed.?, failure });
        return failure;
    };
    // The seeds reached the paths the model checks: a second slot opened, exchanges moved and
    // ended refused or closed, and some were cancelled. A seed replays in every build mode
    // (invariant 5), so the census is pinned, as Debug and `-Drelease` both give it.
    try testing.expectEqual(Result{
        .states = 5828,
        .requests = 784,
        .responses = 512,
        .refused = 29,
        .closed = 118,
        .cancelled = 125,
        .moved = 78,
        .connections = 831,
        .grown = 229,
    }, census.result);
}
