//! The deadline check (design §8 step 20b, decision 110): each seed's plan (`deadline_plan.zig`)
//! run between a server and its peer in simulated time (`deadline_run.zig`), twice. So:
//!   1. the two runs must write the same trace (invariant 5);
//!   2. an honest peer's exchanges must each end with a whole response, however long the
//!      application takes to answer.
//!
//! The census counts the runs the server closed and the runs it held open until the horizon, and
//! its test pins the CRC-32 of the traces of seeds `[0, check_seeds_default)`, in Debug and in
//! ReleaseSafe alike.
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");
const deadline_plan = @import("deadline_plan.zig");
const deadline_run = @import("deadline_run.zig");

const Random = sim.Random;
const limits = sim.constants.deadline;
const Plan = deadline_plan.Plan;
const Record = deadline_run.Record;

/// The name every deadline trace carries on its first line.
pub const check_name = "deadline";

/// The CRC-32 of the traces of seeds `[0, check_seeds_default)`, concatenated in seed order. A
/// change to the plan, to what the server does or to the trace format changes it, and is
/// committed with the new value after the check passes in both build modes.
pub const census_crc32_expected: u32 = 0x0cf3bfd3;

pub const Violation = deadline_run.Error || error{
    /// Two runs of one seed wrote different traces.
    ReplayDiverged,
    /// An honest peer's exchange ended without a whole response.
    ExchangeLost,
    /// The trace passed its buffer.
    TraceFull,
};

/// The storage one seed runs in, outside any stack frame (decision 35).
pub const Storage = struct {
    run: deadline_run.Storage,
    trace: [limits.trace_len_max]u8,
    trace_len: usize,
    first: [limits.trace_len_max]u8,
    first_len: usize,
};

pub const Result = struct {
    trace: []const u8,
    record: Record,
};

/// What `run_check` counted over its seeds.
pub const Census = struct {
    seeds: u64 = 0,
    exchanges: u64 = 0,
    closed: u64 = 0,
    held: u64 = 0,
    trace_octets: u64 = 0,
    crc32: std.hash.Crc32 = .init(),
};

/// Runs one seed twice, and returns the first run's trace.
pub fn run_seed(storage: *Storage, seed: u64) Violation!Result {
    var random = Random.init(seed);
    const plan = deadline_plan.draw(&random);
    try deadline_run.run(&storage.run, &plan, seed);
    try verify(storage, &plan, seed);
    @memcpy(storage.first[0..storage.trace_len], storage.trace[0..storage.trace_len]);
    storage.first_len = storage.trace_len;
    const record = storage.run.record;
    try deadline_run.run(&storage.run, &plan, seed);
    try verify(storage, &plan, seed);
    // Invariant 5: one seed replays byte for byte.
    if (!std.mem.eql(u8, storage.first[0..storage.first_len], storage.trace[0..storage.trace_len])) {
        return error.ReplayDiverged;
    }
    return .{ .trace = storage.first[0..storage.first_len], .record = record };
}

/// Runs seeds `[0, seeds)`, adding each to `census`, and names the seed that failed.
pub fn run_check(storage: *Storage, seeds: u64, census: *Census, failed_seed: *?u64) Violation!void {
    for (0..seeds) |seed| {
        const result = run_seed(storage, seed) catch |failure| {
            failed_seed.* = seed;
            return failure;
        };
        census.seeds += 1;
        census.exchanges += result.record.exchanges_done;
        switch (result.record.end) {
            .closed => census.closed += 1,
            .held => census.held += 1,
        }
        census.trace_octets += result.trace.len;
        census.crc32.update(result.trace);
    }
}

/// Checks the run's record against the plan, and writes the run's trace.
fn verify(storage: *Storage, plan: *const Plan, seed: u64) Violation!void {
    const record = &storage.run.record;
    storage.trace_len = 0;
    try line(storage, "{s} seed=0x{x} protocol={t} peer={t} exchanges={d} gap_ms={d} piece_len={d}\n", .{
        check_name, seed, plan.protocol, plan.peer, plan.exchanges_len, plan.gap_ms, plan.piece_len,
    });
    for (record.answers[0..record.answers_len], 0..) |answered, index| {
        try line(storage, "answer={d} read_ms={d} answered_ms={?d}\n", .{ index, answered.read_ms, answered.answered_ms });
    }
    try line(storage, "end={t} at_ms={d} exchanges_done={d} timeout_response={} goaway={?d}\n", .{
        record.end, record.end_ms, record.exchanges_done, record.saw_timeout_response, record.goaway_code,
    });
    // An honest peer's exchanges end whole, however long the application takes (decision 110).
    if (plan.honest() and record.exchanges_done != plan.exchanges_len) return error.ExchangeLost;
}

fn line(storage: *Storage, comptime format: []const u8, arguments: anytype) Violation!void {
    const written = std.fmt.bufPrint(storage.trace[storage.trace_len..], format, arguments) catch return error.TraceFull;
    storage.trace_len += written.len;
}

var check_storage: Storage align(@alignOf(Storage)) = undefined;

test "decision 110: every seed replays, honest peers finish their exchanges, and the census is pinned" {
    var census: Census = .{};
    var failed_seed: ?u64 = null;
    run_check(&check_storage, limits.check_seeds_default, &census, &failed_seed) catch |failure| {
        std.debug.print("deadline: seed 0x{x} failed: {t}\n", .{ failed_seed.?, failure });
        return failure;
    };
    try std.testing.expect(census.exchanges > 0);
    try std.testing.expectEqual(census_crc32_expected, census.crc32.final());
}
