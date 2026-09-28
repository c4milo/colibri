//! The h2 trace run (https://github.com/c4milo/colibri/issues/75, decision 104): a colibri client
//! and a colibri server act out a seed's `h2_trace_plan.zig`, one queue of octets in each
//! direction, which TCP would deliver in order (RFC 9113 §2). The plan draws write calls the
//! connections must refuse as well as ones they take, and after its last action the run delivers
//! what is left in both directions.
//!
//! After each action the run computes the state of `spec/tla/h2_connection`'s model from both
//! endpoints (`h2_trace_state.zig`) and keeps it when it differs from the last one kept, which is
//! the trace `h2_trace_tla.zig` writes for TLC. Two colibri endpoints never provoke a connection
//! error or a stream error, and a client opens no stream after a GOAWAY, so each is a violation
//! here too, found without TLC.
//!
//! Each seed runs twice and must go through the same states, which is invariant 5.
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");
const h2_trace_plan = @import("h2_trace_plan.zig");
const h2_trace_pair = @import("h2_trace_pair.zig");
const h2_trace_state = @import("h2_trace_state.zig");

const Random = sim.Random;
const limits = sim.constants.h2_trace;
const State = h2_trace_state.State;

pub const Violation = h2_trace_state.Error || error{
    /// A connection failed: one colibri endpoint found a connection error in what the other sent.
    ConnectionFailed,
    /// A receiver reset a stream for a stream error, or read a message out of RFC 9113 §8.1's
    /// order.
    Malformed,
    /// The client opened a stream after it read a GOAWAY (RFC 9113 §6.8).
    OpenedAfterGoaway,
    /// The run went through more of the model's states than `states_max`.
    TraceFull,
    /// The seed's second run went through different states from its first (invariant 5).
    ReplayDiverged,
};

/// The storage one seed runs in, outside any stack frame (decision 35).
pub const Storage = struct {
    plan: h2_trace_plan.Plan,
    pair: h2_trace_pair.Pair,
    /// The model's states the last run went through, each one differing from the one before,
    /// and the first run's, which the second must repeat.
    states: [limits.states_max]State,
    states_len: usize,
    first: [limits.states_max]State,

    /// The last run's trace.
    pub fn trace(storage: *const Storage) []const State {
        return storage.states[0..storage.states_len];
    }
};

/// One seed's counts.
pub const Result = struct {
    states: u64 = 0,
    opened: u64 = 0,
    responses: u64 = 0,
    resets: u64 = 0,
    goaways: u64 = 0,
    refused: u64 = 0,
};

pub const Census = struct {
    seeds: u64 = 0,
    opened: u64 = 0,
    responses: u64 = 0,
    resets: u64 = 0,
    goaways: u64 = 0,
    refused: u64 = 0,

    fn count(census: *Census, result: Result) void {
        census.seeds += 1;
        census.opened += result.opened;
        census.responses += result.responses;
        census.resets += result.resets;
        census.goaways += result.goaways;
        census.refused += result.refused;
    }
};

/// The instant each connection is given. The run moves no clock: nothing it does waits on one.
const now_ns: u64 = 1_000_000;

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
    storage.pair.init(now_ns);
    storage.states_len = 0;
    try record(storage);
    for (0..storage.plan.actions) |_| {
        storage.pair.act(storage.plan.next_action(&random), &storage.plan);
        try record(storage);
    }
    for (0..limits.drain_rounds_max) |_| {
        const before = storage.pair.to_server.len + storage.pair.to_client.len;
        storage.pair.act(.deliver_to_server, &storage.plan);
        try record(storage);
        storage.pair.act(.deliver_to_client, &storage.plan);
        try record(storage);
        if (storage.pair.to_server.len + storage.pair.to_client.len == before) break;
    }
    return result_of(storage);
}

/// Keeps the model's state after an action when it differs from the last one kept, and fails the
/// run on what two colibri endpoints never do.
fn record(storage: *Storage) Violation!void {
    const state = try h2_trace_state.compute(&storage.pair, &storage.plan);
    if (storage.states_len > 0 and std.meta.eql(storage.states[storage.states_len - 1], state)) return;
    if (storage.states_len == storage.states.len) return error.TraceFull;
    storage.states[storage.states_len] = state;
    storage.states_len += 1;
    if (state.broken) return error.ConnectionFailed;
    if (state.malformed) return error.Malformed;
    if (state.late_open) return error.OpenedAfterGoaway;
}

fn result_of(storage: *const Storage) Result {
    const seen = &storage.pair.seen;
    var result: Result = .{
        .states = storage.states_len,
        .opened = seen.opened,
        .goaways = seen.goaways_sent,
        .refused = seen.refused,
    };
    const last = &storage.states[storage.states_len - 1];
    for (0..storage.plan.streams) |index| {
        if (last.response_read[index] == .ended) result.responses += 1;
        if (last.client_closed[index] == .rst_sent or last.server_closed[index] == .rst_sent) result.resets += 1;
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

test "h2 trace run: no seed provokes a connection or stream error, and every rule is drawn" {
    var census: Census = .{};
    var failed_seed: ?u64 = null;
    run_check(&test_storage, sim.constants.check_seeds_default, &census, &failed_seed) catch |failure| {
        std.debug.print("h2 trace run: seed 0x{x} failed: {t}\n", .{ failed_seed.?, failure });
        return failure;
    };
    // The seeds reached the paths the model checks, and drew calls colibri refused.
    try testing.expect(census.opened > 0 and census.responses > 0 and census.resets > 0);
    try testing.expect(census.goaways > 0 and census.refused > 0);
}
