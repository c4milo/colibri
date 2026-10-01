//! The TCP trace run (https://github.com/c4milo/colibri/issues/79): a `client.Connection` and a
//! `server.Connection` act out a seed's `tcp_trace_plan.zig` over h2, in cleartext or over TLS, and
//! after each action the run computes `spec/tla/h2_connection`'s state from both
//! (`tcp_trace_state.zig`). It keeps each state that differs from the last one kept, which
//! `h2_trace_tla.zig` writes for TLC.
//!
//! The run starts with the client's first flight: the requests the plan makes, one send that hands
//! out the client's preface, its SETTINGS and those requests at once, and one delivery that gives
//! the server all of them. Over TLS the handshake runs first, the ClientHello one way and the
//! server's flight the other, so the first flight goes out with the client's Finished. Then the run
//! draws the plan's actions, and drains: each side sends and the other reads, until a round changes
//! nothing. A connection error, a stream error, or a stream opened after a GOAWAY fails the run
//! without TLC, since two colibri endpoints cause none.
//!
//! Each seed runs twice and must go through the same states, which is invariant 5.
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");
const plan_module = @import("tcp_trace_plan.zig");
const world_module = @import("tcp_trace_world.zig");
const state_module = @import("tcp_trace_state.zig");

const Random = sim.Random;
const limits = sim.constants.tcp_trace;
const Plan = plan_module.Plan;
const Action = plan_module.Action;
const State = state_module.State;

pub const Violation = state_module.Error || error{
    /// A connection refused to start.
    StartRefused,
    /// A connection failed, which no honest peer causes.
    ConnectionFailed,
    /// A receiver read a message out of RFC 9113 §8.1's order, or refused a request as malformed.
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
    plan: Plan,
    world: world_module.World,
    /// The model's states the last run went through, each differing from the one before, and the
    /// first run's, which the second must repeat.
    states: [limits.states_max]State,
    states_len: usize,
    first: [limits.states_max]State,

    /// The last run's trace.
    pub fn trace(storage: *const Storage) []const State {
        return storage.states[0..storage.states_len];
    }
};

/// One seed's counts: the states it went through, the requests the client made, the responses it
/// read whole, the calls a connection refused, whether the server's caller shut it down, and
/// whether it ran over TLS.
pub const Result = struct {
    states: u64 = 0,
    requests: u64 = 0,
    responses: u64 = 0,
    refused: u64 = 0,
    shut_down: u64 = 0,
    tls: u64 = 0,
};

pub const Census = struct {
    seeds: u64 = 0,
    states: u64 = 0,
    requests: u64 = 0,
    responses: u64 = 0,
    refused: u64 = 0,
    shut_down: u64 = 0,
    tls: u64 = 0,

    fn count(census: *Census, result: Result) void {
        census.seeds += 1;
        census.states += result.states;
        census.requests += result.requests;
        census.responses += result.responses;
        census.refused += result.refused;
        census.shut_down += result.shut_down;
        census.tls += result.tls;
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
    var random = Random.init(seed);
    storage.plan.draw(&random);
    storage.world.init(seed, storage.plan.tls) catch return error.StartRefused;
    storage.states_len = 0;
    try record(storage);
    // The client's first flight: its preface, its SETTINGS and the plan's first requests, which
    // the server reads in one delivery. Over TLS the client completes its handshake first, so its
    // Finished goes out with them (RFC 9846 §2).
    for (0..storage.plan.first_flight) |_| try act(storage, .request);
    if (storage.plan.tls) {
        for ([_]Action{ .client_send, .deliver_to_server, .server_send, .deliver_to_client }) |action| try act(storage, action);
    }
    try act(storage, .client_send);
    try act(storage, .deliver_to_server);
    for (0..storage.plan.actions) |_| try act(storage, storage.plan.next_action(&random));
    for (0..limits.drain_rounds_max) |_| {
        const before = storage.states_len;
        try act(storage, .client_send);
        try act(storage, .deliver_to_server);
        try act(storage, .server_send);
        try act(storage, .deliver_to_client);
        if (storage.states_len == before) break;
    }
    return result_of(storage);
}

fn act(storage: *Storage, action: Action) Violation!void {
    storage.world.act(action, &storage.plan);
    try record(storage);
}

/// Keeps the model's state after an action when it differs from the last one kept, and fails the
/// run on what two colibri endpoints never do.
fn record(storage: *Storage) Violation!void {
    const state = try state_module.compute(&storage.world, &storage.plan);
    if (storage.states_len > 0 and std.meta.eql(storage.states[storage.states_len - 1], state)) return;
    if (storage.states_len == storage.states.len) return error.TraceFull;
    storage.states[storage.states_len] = state;
    storage.states_len += 1;
    if (state.broken) return error.ConnectionFailed;
    if (state.malformed) return error.Malformed;
    if (state.late_open) return error.OpenedAfterGoaway;
}

fn result_of(storage: *const Storage) Result {
    const world = &storage.world;
    var result: Result = .{
        .states = storage.states_len,
        .requests = world.requested,
        .refused = world.refused,
        .shut_down = @intFromBool(world.shut_down),
        .tls = @intFromBool(world.tls),
    };
    for (world.exchanges[0..world.requested]) |*exchange| result.responses += @intFromBool(exchange.outcome == .response);
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

test "TCP trace run: a client's first flight and every exchange after it, with no error, and replayed" {
    var census: Census = .{};
    var failed_seed: ?u64 = null;
    run_check(&test_storage, limits.written_seeds, &census, &failed_seed) catch |failure| {
        std.debug.print("tcp-trace: seed 0x{x} failed: {t}\n", .{ failed_seed.?, failure });
        return failure;
    };
    // The runs read responses whole, some shut the server down, and some run over TLS.
    try testing.expect(census.requests > 0 and census.responses > 0 and census.shut_down > 0);
    try testing.expect(census.tls > 0 and census.tls < census.seeds);
}
