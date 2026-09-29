//! The client trace run (decision 105, design §8 step 17d): a `client.Channel` carries a seed's
//! exchanges over QUIC and TCP while the plan loses, delays or refuses QUIC, and its servers
//! answer, reject, reset and send GOAWAY (`client_trace_world.zig`). After each instant the run
//! computes spec/tla/client_exchanges's state (`client_trace_state.zig`) and keeps it when it
//! differs from the last one kept, which is the trace `client_trace_tla.zig` writes for TLC.
//!
//! The model's safety property is checked here too, without TLC, and every seed must end with
//! the channel closed, each exchange reported once or cancelled, and, in a clean seed, each one
//! that was not cancelled ended in a response: design §8 step 17d's "one completed request per
//! request made". Each seed runs twice and must go through the same states (invariant 5).
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");
const world_module = @import("client_trace_world.zig");
const state_module = @import("client_trace_state.zig");

const limits = sim.constants.client_trace;
const World = world_module.World;
const State = state_module.State;
const Tracker = state_module.Tracker;

pub const Violation = world_module.Error || error{
    /// A reported or cancelled exchange's memory is still read by a QUIC stream.
    HeldAfterReturn,
    /// A stream holds an exchange's octets on a connection that is not live.
    HeldOffLiveConnection,
    /// An exchange ended refused although a server processed it, or two servers processed it.
    RefusedProcessed,
    ProcessedTwice,
    /// A connection closed while it held an exchange.
    ClosedHolding,
    /// The run moved through more instants than `instants_max`, or through one instant more
    /// often than a step can revisit it, or kept more states than `states_max`.
    Unfinished,
    TraceFull,
    /// The run ended with the channel open or closed too late after its shutdown, an exchange
    /// neither reported nor cancelled, or, in a clean seed, an exchange that ended without a
    /// response.
    NotClosed,
    ClosedLate,
    NotReported,
    NoResponse,
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
    exchanges: u64 = 0,
    responses: u64 = 0,
    refused: u64 = 0,
    failed: u64 = 0,
    cancelled: u64 = 0,
    moved: u64 = 0,
    quic_connections: u64 = 0,
    tcp_connections: u64 = 0,
    goaways: u64 = 0,
    learned: u64 = 0,
    /// QUIC connections that retired near their idle timeout, and the PINGs that kept one with an
    /// exchange outstanding from it (design §8 step 17g).
    retired: u64 = 0,
    keep_alives: u64 = 0,
};

pub const Census = struct {
    seeds: u64 = 0,
    result: Result = .{},
    /// The longest a seed's channel took to close once it had nothing left to carry.
    closing_max_ns: u64 = 0,

    fn count(census: *Census, result: Result, closing_ns: u64) void {
        census.seeds += 1;
        inline for (std.meta.fields(Result)) |field| {
            @field(census.result, field.name) += @field(result, field.name);
        }
        census.closing_max_ns = @max(census.closing_max_ns, closing_ns);
    }
};

/// Times one run may stay at an instant: each step there must move something on.
const repeats_max: u32 = 64;

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
    var last_at: u64 = 0;
    var repeats: u32 = 0;
    for (0..limits.instants_max) |_| {
        if (world.closed) break;
        const due = world.next_instant() orelse return error.Stuck;
        const at = @max(due, world.now_ns);
        repeats = if (at == last_at) repeats + 1 else 0;
        if (repeats > repeats_max) return error.Unfinished;
        last_at = at;
        try world.step(at);
        try record(storage);
    } else return error.Unfinished;
    try check_end(world);
    return result_of(storage);
}

/// Keeps the model's state after an instant when it differs from the last one kept, and fails
/// the run on what the model's safety property forbids.
fn record(storage: *Storage) Violation!void {
    storage.tracker.update(&storage.world);
    const state = state_module.compute(&storage.world, &storage.tracker);
    try check_safe(&state, storage.world.plan.exchanges);
    if (storage.states_len > 0 and std.meta.eql(storage.states[storage.states_len - 1], state)) return;
    if (storage.states_len == storage.states.len) return error.TraceFull;
    storage.states[storage.states_len] = state;
    storage.states_len += 1;
}

/// spec/tla/client_exchanges's Safe, over this state.
fn check_safe(state: *const State, exchanges: u32) Violation!void {
    for (0..exchanges) |index| try check_exchange(state, index);
}

fn check_exchange(state: *const State, index: usize) Violation!void {
    const returned = state.stage[index] == .reported or state.stage[index] == .cancelled;
    if (returned and state.holds[index]) return error.HeldAfterReturn;
    const quic_live = state.phase[0] == .open or state.phase[0] == .draining;
    if (state.holds[index] and !(state.carrier[index] == .quic and quic_live)) return error.HeldOffLiveConnection;
    if (state.outcome[index] == .refused and state.processed[index] > 0) return error.RefusedProcessed;
    if (state.processed[index] > 1) return error.ProcessedTwice;
    const held = state.stage[index] == .queued or state.stage[index] == .sent or state.stage[index] == .ended;
    const phase = switch (state.carrier[index]) {
        .none => return,
        .quic => state.phase[0],
        .tcp => state.phase[1],
    };
    if (held and phase == .closed) return error.ClosedHolding;
}

fn check_end(world: *const World) Violation!void {
    if (!world.closed) return error.NotClosed;
    // A connection that ends only at its idle timeout once it holds nothing was never closed.
    if (world.now_ns - closing_from_ns(world) > limits.closing_max_ns) return error.ClosedLate;
    for (0..world.plan.exchanges) |index| {
        if (!world.reported[index] and !world.cancelled[index]) return error.NotReported;
        if (!world.plan.clean or !world.reported[index]) continue;
        // Design §8 step 17d: every request made completes.
        if (world.exchanges[index].outcome != .response) return error.NoResponse;
    }
}

/// The instant the channel has nothing left to carry: its shutdown, or its last exchange's end.
fn closing_from_ns(world: *const World) u64 {
    return @max(world.plan.shutdown_at_ns, world.settled_ns);
}

fn result_of(storage: *const Storage) Result {
    const world = &storage.world;
    var result: Result = .{
        .states = storage.states_len,
        .exchanges = world.plan.exchanges,
        .quic_connections = world.channel.links.get(.quic).opens,
        .tcp_connections = world.channel.links.get(.tcp).opens,
        .goaways = world.ledger.goaways,
        .learned = @intFromBool(world.plan.policy == .learn and world.channel.alternative() != null),
        .keep_alives = world.keep_alives,
    };
    // Each logged state that finds the QUIC connection stale where the one before did not.
    for (storage.states[1..storage.states_len], storage.states[0 .. storage.states_len - 1]) |now, before| {
        result.retired += @intFromBool(now.stale and !before.stale);
    }
    const last = &storage.states[storage.states_len - 1];
    for (0..world.plan.exchanges) |index| {
        result.cancelled += @intFromBool(world.cancelled[index]);
        result.moved += last.moved[index];
        if (!world.reported[index]) continue;
        switch (world.exchanges[index].outcome) {
            .response => result.responses += 1,
            .refused => result.refused += 1,
            else => result.failed += 1,
        }
    }
    return result;
}

/// Runs seeds `[0, seeds)` in order. On a violation, `failed_seed` names the seed.
pub fn run_check(storage: *Storage, seeds: u64, census: *Census, failed_seed: *?u64) Violation!void {
    for (0..seeds) |seed| {
        failed_seed.* = seed;
        const result = try run_seed(storage, seed);
        census.count(result, storage.world.now_ns - closing_from_ns(&storage.world));
    }
    failed_seed.* = null;
    assert(census.seeds == seeds);
}

const testing = std.testing;

/// The storage the check test runs in, outside any stack frame.
var test_storage: Storage align(@alignOf(Storage)) = undefined;

test "client trace run: every seed closes the channel with each exchange reported once, and clean ones answered" {
    var census: Census = .{};
    var failed_seed: ?u64 = null;
    run_check(&test_storage, sim.constants.check_seeds_default, &census, &failed_seed) catch |failure| {
        std.debug.print("client trace run: seed 0x{x} failed: {t}\n", .{ failed_seed.?, failure });
        return failure;
    };
    // The seeds reached the paths the model checks: QUIC and TCP carried exchanges, exchanges
    // moved after a refusal, a GOAWAY went out, the channel learned h3, some were cancelled, a
    // QUIC connection retired near its idle timeout, and PINGs kept others from it. A seed replays
    // in every build mode (invariant 5), so the census is pinned, as Debug and `-Drelease` both
    // give it.
    try testing.expectEqual(Result{
        .states = 2570,
        .exchanges = 534,
        .responses = 342,
        .refused = 83,
        .failed = 61,
        .cancelled = 48,
        .moved = 3,
        .quic_connections = 120,
        .tcp_connections = 272,
        .goaways = 49,
        .learned = 60,
        .retired = 1,
        .keep_alives = 4,
    }, census.result);
}
