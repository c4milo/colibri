//! The h3 trace run (https://github.com/c4milo/colibri/issues/58): a colibri client and a colibri
//! server act out a seed's `h3_trace_plan.zig` over the datagram network of step 8, which drops,
//! duplicates and reorders by seed. The run passes when the client has ended every request it
//! could open, and the connection then settles: no request stream holds a slot, no section waits
//! on the dynamic table, and no decoder owes an instruction.
//!
//! After each step the run computes the state of `spec/tla/h3_connection`'s model from both
//! endpoints (`h3_trace_state.zig`) and keeps it when it differs from the last one kept, which is
//! the trace `h3_trace_tla.zig` writes for TLC.
//!
//! Each seed runs twice and must send the same datagrams, which is invariant 5.
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");
const quic = @import("quic");
const h3_trace_plan = @import("h3_trace_plan.zig");
const h3_trace_endpoint = @import("h3_trace_endpoint.zig");
const h3_trace_tracker = @import("h3_trace_tracker.zig");
const h3_trace_state = @import("h3_trace_state.zig");
const quic_endpoint = @import("quic_endpoint.zig");

const Random = sim.random.Random;
const Side = sim.network.Endpoint;
const constants = sim.constants;

pub const Violation = h3_trace_endpoint.Error || error{
    /// The network was asked to carry a datagram and had no slot, which is a harness defect.
    NetworkFull,
    /// An endpoint was still sending at the bound on one step's sends.
    SendsExhausted,
    /// The run hit its step bound before it settled.
    StepsExhausted,
    /// The seed's second run sent different datagrams from its first (invariant 5).
    ReplayDiverged,
    /// The run went through more of the model's states than `h3_trace_states_max`.
    TraceFull,
};

/// The storage one seed runs in, outside any stack frame (decision 35).
pub const Storage = struct {
    plan: h3_trace_plan.Plan,
    network: sim.Network,
    endpoints: [Side.count]h3_trace_endpoint.Endpoint,
    tracker: h3_trace_tracker.Tracker,
    /// The model's states the last run went through, each one differing from the one before.
    states: [constants.h3_trace_states_max]h3_trace_state.State,
    states_len: usize,

    /// The last run's trace.
    pub fn trace(storage: *const Storage) []const h3_trace_state.State {
        return storage.states[0..storage.states_len];
    }
};

/// One seed's counts.
pub const Result = struct {
    steps: u64 = 0,
    datagrams: u64 = 0,
    octets_crc32: u32 = 0,
    requests: u64 = 0,
    responses: u64 = 0,
    rejections: u64 = 0,
    cancels: u64 = 0,
    goaways: u64 = 0,
    inserts: u64 = 0,
};

pub const Census = struct {
    seeds: u64 = 0,
    requests: u64 = 0,
    responses: u64 = 0,
    rejections: u64 = 0,
    cancels: u64 = 0,
    goaways: u64 = 0,
    inserts: u64 = 0,

    fn count(census: *Census, result: Result) void {
        census.seeds += 1;
        census.requests += result.requests;
        census.responses += result.responses;
        census.rejections += result.rejections;
        census.cancels += result.cancels;
        census.goaways += result.goaways;
        census.inserts += result.inserts;
    }
};

/// The instant a run starts, and the longest step it takes when nothing is due sooner.
const start_ns: u64 = 1_000_000;
const idle_step_ns: u64 = 10_000_000;
/// The datagrams one endpoint may send in one step.
const sends_per_step_max: u32 = constants.h3_check_sends_per_step_max;

/// Runs one seed twice and returns the first run's counts.
pub fn run_seed(storage: *Storage, seed: u64) Violation!Result {
    const first = try run_once(storage, seed);
    const second = try run_once(storage, seed);
    if (first.octets_crc32 != second.octets_crc32 or first.datagrams != second.datagrams) return error.ReplayDiverged;
    return first;
}

fn run_once(storage: *Storage, seed: u64) Violation!Result {
    var random = Random.init(seed);
    storage.plan.draw(&random);
    storage.network.init(seed, .{
        .drop = @intCast(random.below(constants.h3_trace_drop_max + 1)),
        .duplicate = @intCast(random.below(constants.h3_trace_duplicate_max + 1)),
    });
    for (std.enums.values(Side)) |side| {
        const role: quic.connection.Role = if (side == .client) .client else .server;
        storage.endpoints[@intFromEnum(side)].init(role, &storage.plan, start_ns);
    }
    storage.tracker = .{};
    storage.states_len = 0;
    var run: Run = .{ .storage = storage, .now_ns = start_ns, .digest = .init() };
    try run.record();
    // Bounded by a named limit.
    for (0..constants.h3_trace_steps_max) |_| {
        try run.step();
        if (run.endpoint(.client).finished() and settled(storage)) return run.finish();
    }
    return error.StepsExhausted;
}

const Run = struct {
    storage: *Storage,
    now_ns: u64,
    digest: std.hash.Crc32,
    steps: u64 = 0,
    datagrams: u64 = 0,

    fn endpoint(run: *Run, side: Side) *h3_trace_endpoint.Endpoint {
        return &run.storage.endpoints[@intFromEnum(side)];
    }

    /// One step: deliver, fire deadlines, let each endpoint act on the plan, send, and move time
    /// on.
    fn step(run: *Run) Violation!void {
        for (std.enums.values(Side)) |side| try run.deliver(side);
        run.storage.tracker.observe_arrivals(run.endpoint(.server));
        for (std.enums.values(Side)) |side| try run.endpoint(side).transport.on_instant(run.now_ns);
        for (std.enums.values(Side)) |side| try run.endpoint(side).step(run.steps);
        for (std.enums.values(Side)) |side| try run.send_owed(side);
        run.now_ns = run.next_instant();
        run.steps += 1;
        try run.record();
    }

    /// Keeps the model's state after the step when it differs from the last one kept.
    fn record(run: *Run) Violation!void {
        const storage = run.storage;
        const client = run.endpoint(.client);
        const server = run.endpoint(.server);
        storage.tracker.observe(client, server);
        const state = h3_trace_state.compute(&storage.tracker, .of(&storage.plan), client, server);
        if (storage.states_len > 0 and std.meta.eql(storage.states[storage.states_len - 1], state)) return;
        if (storage.states_len == storage.states.len) return error.TraceFull;
        storage.states[storage.states_len] = state;
        storage.states_len += 1;
    }

    fn deliver(run: *Run, side: Side) Violation!void {
        const held = run.endpoint(side);
        // Bounded by the network's own slot count, which is a named limit.
        for (0..constants.network_in_flight_max) |_| {
            const delivery = run.storage.network.receive(run.now_ns, side) orelse return;
            try held.transport.receive(delivery.octets, delivery.ecn, delivery.from_address, run.now_ns);
        }
    }

    fn send_owed(run: *Run, side: Side) Violation!void {
        const held = run.endpoint(side);
        // Bounded by a named limit: the congestion window stops a sender long before it.
        for (0..sends_per_step_max) |_| {
            const sent = try held.transport.send(run.now_ns) orelse return;
            const octets = held.transport.output[0..sent.len];
            run.digest.update(octets);
            run.datagrams += 1;
            const to = quic_endpoint.network_address(sent.to);
            if (run.storage.network.send_to(run.now_ns, side, octets, quic_endpoint.network_ecn(sent.ecn), to) == .no_slot) return error.NetworkFull;
        }
        return error.SendsExhausted;
    }

    fn next_instant(run: *Run) u64 {
        var at_ns: u64 = run.now_ns +| idle_step_ns;
        if (run.storage.network.next_arrival_ns()) |arrival_ns| at_ns = @min(at_ns, arrival_ns);
        for (&run.storage.endpoints) |*held| {
            if (held.transport.next_deadline_ns()) |deadline_ns| at_ns = @min(at_ns, deadline_ns);
        }
        return @max(at_ns, run.now_ns +| 1);
    }

    fn finish(run: *Run) Result {
        const client = run.endpoint(.client);
        const server = run.endpoint(.server);
        var result: Result = .{
            .steps = run.steps,
            .datagrams = run.datagrams,
            .octets_crc32 = run.digest.final(),
            .requests = client.opened,
            .goaways = server.goaways_sent,
            .inserts = client.h3.encoder.table.insert_count(),
        };
        for (client.outcome[0..client.opened]) |outcome| {
            switch (outcome) {
                .none => unreachable, // `finished` held.
                .response => result.responses += 1,
                .rejected => result.rejections += 1,
                .cancelled => result.cancels += 1,
            }
        }
        return result;
    }
};

/// Whether both endpoints have settled: no request stream holds a slot, no field section waits
/// on the dynamic table, and no decoder owes an instruction.
fn settled(storage: *const Storage) bool {
    for (&storage.endpoints) |*held| {
        const connection = &held.h3;
        for (connection.requests.slots) |slot| {
            if (slot != null) return false;
        }
        if (connection.decoder.blocked_len != 0 or connection.decoder.owes()) return false;
    }
    return true;
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
var test_storage: Storage = undefined;

test "h3 trace run: every seed's requests end, cancelled, rejected or answered, and it settles" {
    var census: Census = .{};
    var failed_seed: ?u64 = null;
    run_check(&test_storage, constants.check_seeds_default, &census, &failed_seed) catch |failure| {
        std.debug.print("h3 trace run: seed 0x{x} failed: {t}\n", .{ failed_seed.?, failure });
        return failure;
    };
    // The seeds reached every way a request ends, and the paths the model checks.
    try testing.expect(census.responses > 0 and census.rejections > 0 and census.cancels > 0);
    try testing.expect(census.goaways > 0 and census.inserts > 0);
}
