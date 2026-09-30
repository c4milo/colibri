//! The h2 stall check (https://github.com/c4milo/colibri/issues/85): each seed's plan
//! (`h2_stall_plan.zig`) run between a colibri client and a colibri server over a transport that
//! holds a few octets (`h2_stall_run.zig`), twice. The two runs must do the same (invariant 5).
//!
//! It answers the issue's question: whether two colibri endpoints, each of which stops reading while
//! a reply queue is full (decision 39), can stop each other. The census counts, for each shape of
//! seed and each capacity of the transport, the runs that finished and the runs that stalled, and
//! among the stalls those in which both endpoints' reply queues were full. Its test pins the counts.
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");
const h2 = @import("h2");
const h2_stall_plan = @import("h2_stall_plan.zig");
const h2_stall_run = @import("h2_stall_run.zig");

const Random = sim.Random;
const limits = sim.constants.h2_stall;
const Plan = h2_stall_plan.Plan;
const Shape = h2_stall_plan.Shape;
const Record = h2_stall_run.Record;

pub const Violation = h2_stall_run.Error || error{
    /// Two runs of one seed did different things.
    ReplayDiverged,
    /// A run stalled although both endpoints write what their connections owe before their own
    /// frames. An endpoint fills its reply queue only by reading, which frees room in its peer's
    /// output, and that peer's next writing turn puts its owed replies there first.
    StalledOwedFirst,
};

/// The storage one seed runs in, outside any stack frame (decision 35).
pub const Storage = struct {
    plan: Plan,
    run: h2_stall_run.Storage,
};

/// One seed's plan and what its run did.
pub const Result = struct {
    plan: Plan,
    record: Record,
};

/// What the runs of one shape over one capacity did.
pub const Cell = struct {
    runs: u64 = 0,
    finished: u64 = 0,
    stalled: u64 = 0,
    /// Stalls in which both endpoints' reply queues were full.
    both_full: u64 = 0,
    /// The most replies about single streams one endpoint held at once, over every run, and the
    /// times `receive` took no frame because a reply queue was full.
    replies_most: u32 = 0,
    reads_stopped_full: u64 = 0,
};

const shape_count = std.meta.fields(Shape).len;
const Order = h2_stall_plan.Order;
const order_count = std.meta.fields(Order).len;

pub const Census = struct {
    seeds: u64 = 0,
    /// Body octets that arrived over every run, both ways.
    octets: u64 = 0,
    cells: [shape_count][limits.capacities.len]Cell = @splat(@splat(.{})),
    /// The same counts by which endpoints write what they owe first.
    orders: [order_count]Cell = @splat(.{}),

    fn count(census: *Census, result: Result) void {
        census.seeds += 1;
        census.octets += result.record.octets;
        add(census.cell(result.plan.shape, result.plan.capacity), result.record);
        add(&census.orders[@intFromEnum(result.plan.order())], result.record);
    }

    fn add(counts: *Cell, record: Record) void {
        counts.runs += 1;
        counts.replies_most = @max(counts.replies_most, @max(record.client_replies_most, record.server_replies_most));
        counts.reads_stopped_full += record.reads_stopped_full;
        switch (record.outcome) {
            .finished => counts.finished += 1,
            .stalled => {
                counts.stalled += 1;
                if (record.client_queue_full and record.server_queue_full) counts.both_full += 1;
            },
        }
    }

    /// The counts of `shape` over `capacity`, one of `limits.capacities`.
    pub fn cell(census: *Census, shape: Shape, capacity: u32) *Cell {
        const index = std.mem.indexOfScalar(u32, &limits.capacities, capacity).?;
        return &census.cells[@intFromEnum(shape)][index];
    }

    /// Runs of every shape and capacity that stalled.
    pub fn stalled(census: *const Census) u64 {
        var sum: u64 = 0;
        for (census.cells) |row| {
            for (row) |counts| sum += counts.stalled;
        }
        return sum;
    }
};

/// Runs one seed twice and returns the first run.
pub fn run_seed(storage: *Storage, seed: u64) Violation!Result {
    const first = try run_once(storage, seed);
    const second = try run_once(storage, seed);
    if (!std.meta.eql(first, second)) return error.ReplayDiverged;
    if (first.outcome == .stalled and storage.plan.order() == .owed_first) return error.StalledOwedFirst;
    return .{ .plan = storage.plan, .record = first };
}

fn run_once(storage: *Storage, seed: u64) Violation!Record {
    var random = Random.init(seed);
    storage.plan.draw(&random);
    return storage.run.run(&storage.plan, &random);
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

/// The storage the tests run in, outside any stack frame.
var test_storage: Storage align(@alignOf(Storage)) = undefined;

test "h2 stall check: the first seeds finish, each twice alike, every body whole" {
    var census: Census = .{};
    var failed_seed: ?u64 = null;
    run_check(&test_storage, limits.check_seeds_default, &census, &failed_seed) catch |failure| {
        std.debug.print("h2 stall check: seed 0x{x} failed: {t}\n", .{ failed_seed.?, failure });
        return failure;
    };
    try testing.expectEqual(0, census.stalled());
    // The seeds drew both shapes, and an aligned seed filled a reply queue and recovered.
    var aligned_runs: u64 = 0;
    var random_runs: u64 = 0;
    for (census.cells[@intFromEnum(Shape.aligned)]) |counts| aligned_runs += counts.runs;
    for (census.cells[@intFromEnum(Shape.random)]) |counts| random_runs += counts.runs;
    try testing.expect(aligned_runs > 0 and random_runs > 0);
    var stopped: u64 = 0;
    for (census.orders) |counts| stopped += counts.reads_stopped_full;
    try testing.expect(stopped > 0);
}

test "https://github.com/c4milo/colibri/issues/85: endpoints that write their own frames first stop each other" {
    const result = try run_seed(&test_storage, limits.stalled_seed);
    try testing.expectEqual(.aligned, result.plan.shape);
    try testing.expectEqual(.frames_first, result.plan.order());
    try testing.expectEqual(.stalled, result.record.outcome);
    // Decision 39: both reply queues are full, so neither endpoint reads, and neither direction has
    // room for the WINDOW_UPDATE frames that would let the other read on.
    try testing.expect(result.record.client_queue_full and result.record.server_queue_full);
    try testing.expectEqual(result.plan.capacity, result.record.to_server_len);
    try testing.expect(result.plan.capacity - result.record.to_client_len < window_update_frame_len);
}

/// Octets of one WINDOW_UPDATE frame: a header and an increment (RFC 9113 §6.9). Test-only.
const window_update_frame_len: u32 = h2.constants.frame_header_len + h2.constants.window_update_len;
