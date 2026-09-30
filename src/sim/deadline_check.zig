//! The deadline check (design §8 step 20b, decision 110): each seed's plan (`deadline_plan.zig`)
//! run between a server and its peer in simulated time (`deadline_run.zig`), twice. So:
//!   1. the two runs must write the same trace (invariant 5);
//!   2. an honest peer's exchanges must each end with a whole response, however long the
//!      application takes to answer;
//!   3. every run must end at the deadline decision 110 names, at its instant under the plan's
//!      limits: an honest peer or an idle pinger at the idle deadline after its last response, a
//!      silent peer or a pinger at the first-request deadline, and a slow head at the
//!      first-request or the head deadline. A PING moves no deadline. The server has no deadline
//!      for a body yet, so a slow body holds it open until the horizon;
//!   4. and as decision 110 says: a head that began gets a 408 in h11 and a GOAWAY with
//!      ENHANCE_YOUR_CALM in h2, and with none begun h11 sends nothing and h2 a GOAWAY with
//!      NO_ERROR.
//!
//! The census counts the runs each deadline ended and the runs the server held open until the
//! horizon, and its test pins the CRC-32 of the traces of seeds `[0, check_seeds_default)`, in
//! Debug and in ReleaseSafe alike.
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");
const h2 = @import("h2");
const server = @import("server");
const deadline_plan = @import("deadline_plan.zig");
const deadline_run = @import("deadline_run.zig");
const deadline_peer = @import("deadline_peer.zig");

const Random = sim.Random;
const limits = sim.constants.deadline;
const Plan = deadline_plan.Plan;
const Record = deadline_run.Record;

/// The name every deadline trace carries on its first line.
pub const check_name = "deadline";

/// The CRC-32 of the traces of seeds `[0, check_seeds_default)`, concatenated in seed order. A
/// change to the plan, to what the server does or to the trace format changes it, and is
/// committed with the new value after the check passes in both build modes.
pub const census_crc32_expected: u32 = 0xe2af1a07;

pub const Violation = deadline_run.Error || error{
    /// Two runs of one seed wrote different traces.
    ReplayDiverged,
    /// An honest peer's exchange ended without a whole response.
    ExchangeLost,
    /// The run ended other than decision 110 says: at another instant, by another deadline, or with
    /// another response.
    EndedWrong,
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
    first_request: u64 = 0,
    idle: u64 = 0,
    head: u64 = 0,
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
        census.trace_octets += result.trace.len;
        census.crc32.update(result.trace);
        const timed_out = result.record.timed_out orelse {
            census.held += 1;
            continue;
        };
        switch (timed_out) {
            .first_request => census.first_request += 1,
            .idle => census.idle += 1,
            .head => census.head += 1,
        }
    }
}

/// Checks the run's record against the plan, and writes the run's trace.
fn verify(storage: *Storage, plan: *const Plan, seed: u64) Violation!void {
    const record = &storage.run.record;
    try write_trace(storage, plan, seed);
    // An honest peer's exchanges end whole, however long the application takes (decision 110).
    if (plan.honest() and record.exchanges_done != plan.exchanges_len) return error.ExchangeLost;
    const expected = expect(plan, record) orelse {
        if (record.end != .held or record.timed_out != null) return error.EndedWrong;
        return;
    };
    if (record.end != .closed or record.end_ms != expected.end_ms) return error.EndedWrong;
    if (record.timed_out != expected.deadline) return error.EndedWrong;
    if (!plan.honest() and !ended_as_expected(plan, record, expected)) return error.EndedWrong;
}

/// How decision 110 says a run ends: by which deadline, at which instant, and whether a request
/// head had begun, which decides the response.
const Expected = struct {
    deadline: server.Deadline,
    end_ms: u64,
    head: bool,
};

/// How decision 110 says the run ends under the plan's limits, or null for a run the server holds
/// open until the horizon.
fn expect(plan: *const Plan, record: *const Record) ?Expected {
    const first_request_ms = ms_of(plan.deadlines.first_request_ns.?);
    const head_ms = ms_of(plan.deadlines.head_ns.?);
    return switch (plan.peer) {
        .honest, .slow_honest, .upload, .idle_pinger => .{
            .deadline = .idle,
            .end_ms = last_answer_ms(record) + ms_of(plan.deadlines.idle_ns.?),
            .head = false,
        },
        .silent, .pinger => .{ .deadline = .first_request, .end_ms = first_request_ms, .head = false },
        .slow_head => slow_first_head(plan, first_request_ms, head_ms),
        .slow_second_head => .{
            .deadline = .head,
            .end_ms = plan.answer_delay_ms[0] + limits.second_head_after_ms + head_ms,
            .head = true,
        },
        .slow_body => null,
    };
}

/// A slow first head ends at the first-request deadline or at its own, whichever passes first. At
/// one instant the server names the first-request deadline.
fn slow_first_head(plan: *const Plan, first_request_ms: u64, head_ms: u64) Expected {
    const head_end_ms = deadline_peer.slow_head_start_ms(plan.protocol) + head_ms;
    if (first_request_ms <= head_end_ms) return .{ .deadline = .first_request, .end_ms = first_request_ms, .head = true };
    return .{ .deadline = .head, .end_ms = head_end_ms, .head = true };
}

/// What a hostile peer read at the end: a 408 in h11 when a head had begun, and a GOAWAY in h2
/// with ENHANCE_YOUR_CALM when one had and NO_ERROR when none had.
fn ended_as_expected(plan: *const Plan, record: *const Record, expected: Expected) bool {
    return switch (plan.protocol) {
        .h11 => record.saw_timeout_response == expected.head,
        .h2 => record.goaway_code == if (expected.head) h2.constants.error_enhance_your_calm else h2.constants.error_no_error,
    };
}

fn last_answer_ms(record: *const Record) u64 {
    var last: u64 = 0;
    for (record.answers[0..record.answers_len]) |answered| last = @max(last, answered.answered_ms.?);
    return last;
}

fn ms_of(ns: u64) u64 {
    return ns / limits.ns_per_ms;
}

/// The run's trace: the plan, each answer, and how the run ended.
fn write_trace(storage: *Storage, plan: *const Plan, seed: u64) Violation!void {
    const record = &storage.run.record;
    const deadlines = &plan.deadlines;
    storage.trace_len = 0;
    try line(storage, "{s} seed=0x{x} protocol={t} peer={t} base_ms={d}", .{ check_name, seed, plan.protocol, plan.peer, plan.base_ms });
    try line(storage, " limits_ms={d}/{d}/{d}", .{ ms_of(deadlines.first_request_ns.?), ms_of(deadlines.idle_ns.?), ms_of(deadlines.head_ns.?) });
    try line(storage, " exchanges={d} gap_ms={d} piece_len={d}\n", .{ plan.exchanges_len, plan.gap_ms, plan.piece_len });
    for (record.answers[0..record.answers_len], 0..) |answered, index| {
        try line(storage, "answer={d} read_ms={d} body_end_ms={?d} answered_ms={?d}\n", .{
            index, answered.read_ms, answered.body_end_ms, answered.answered_ms,
        });
    }
    try line(storage, "end={t} at_ms={d} deadline={?t} exchanges_done={d}", .{ record.end, record.end_ms, record.timed_out, record.exchanges_done });
    try line(storage, " timeout_response={} status={?d} reset={?d} goaway={?d}\n", .{
        record.saw_timeout_response, record.response_status, record.reset_code, record.goaway_code,
    });
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
