//! The h3 deadline check (design §8 step 20c, decision 110 as amended): each seed's plan
//! (`h3_deadline_plan.zig`) run between a server and its peer over QUIC in simulated time
//! (`h3_deadline_run.zig`), twice. So:
//!   1. the two runs must write the same trace (invariant 5);
//!   2. an honest peer's exchanges must each end with a whole response, however long the
//!      application takes to answer or to write the second half of an answer, though the last
//!      octet of a head comes seconds after the rest, though the peer uploads or reads at only
//!      twice the minimum rate, and though its link carries only four times the minimum send
//!      rate and drops datagrams;
//!   3. every run must end as decision 110 says, at its instant under the plan's limits:
//!      - an honest peer or an idle pinger reads a GOAWAY at the idle deadline after the server
//!        reported its last response done, and a silent peer, a pinger or a slow first head at
//!        the first-request deadline. The close follows with H3_NO_ERROR once the peer
//!        acknowledged the GOAWAY. A PING moves no deadline;
//!      - a late head gets a 408 at the head deadline. A head that is not late when the
//!        connection begins to shut down is reset with H3_REQUEST_REJECTED then;
//!      - a slow body gets a 408 at the end of its first window, and a body that keeps the rate
//!        gets one at the cap on a body. The application reads `cancelled` for each;
//!      - a response its stream's credit holds is reset with H3_REQUEST_CANCELLED at the end of
//!        its first window, and the application reads `cancelled` for it;
//!      - a peer that acknowledges nothing, one that holds a response with its connection's
//!        credit, two bodies that together bring nothing, and a peer that cancels requests past
//!        the limit each close the connection with H3_EXCESSIVE_LOAD. The flood is closed with
//!        the batch that carries the first cancelled request past the limit.
//!
//! The census counts the runs each deadline or limit ended, and its test pins the CRC-32 of the
//! traces of seeds `[0, check_seeds_default)`, in Debug and in ReleaseSafe alike.
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");
const h3 = @import("h3");
const server = @import("server");
const h3_deadline_plan = @import("h3_deadline_plan.zig");
const h3_deadline_run = @import("h3_deadline_run.zig");
const h3_deadline_link = @import("h3_deadline_link.zig");
const h3_deadline_app = @import("h3_deadline_app.zig");

const Random = sim.Random;
const limits = sim.constants.h3_deadline;
const Plan = h3_deadline_plan.Plan;
const Record = h3_deadline_run.Record;
const Answer = h3_deadline_app.Answer;

/// The name every h3 deadline trace carries on its first line.
pub const check_name = "h3-deadline";

/// The CRC-32 of the traces of seeds `[0, check_seeds_default)`, concatenated in seed order. A
/// change to the plan, to what the server does or to the trace format changes it, and is
/// committed with the new value after the check passes in both build modes.
pub const census_crc32_expected: u32 = 0xd51694dc;

/// The CRC-32 of the runs' datagram CRC-32s, in seed order. It follows what the wire carried apart
/// from what the application reads, so a change to how the server reports events keeps it, and a
/// change to what it sends does not (design §8 step 21b.3).
pub const census_wire_crc32_expected: u32 = 0x942c7916;

pub const Violation = h3_deadline_run.Error || error{
    /// Two runs of one seed wrote different traces.
    ReplayDiverged,
    /// An honest peer's exchange ended without a whole response.
    ExchangeLost,
    /// The run ended other than decision 110 says: at another instant, for another deadline, or
    /// with another response.
    EndedWrong,
    /// The trace passed its buffer.
    TraceFull,
};

/// The storage one seed runs in, outside any stack frame (decision 35).
pub const Storage = struct {
    run: h3_deadline_run.Storage,
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
    body_rate: u64 = 0,
    send_rate: u64 = 0,
    peer_resets: u64 = 0,
    /// The runs in which the server ended one request with a 408 or a reset, the connection
    /// going on.
    requests_cut: u64 = 0,
    trace_octets: u64 = 0,
    crc32: std.hash.Crc32 = .init(),
    /// The CRC-32 of each run's datagrams' CRC-32, in seed order (`h3_deadline_run.Record.wire`).
    wire_crc32: std.hash.Crc32 = .init(),
};

/// The plan of `seed`.
pub fn plan_of(seed: u64) Plan {
    var random = Random.init(seed);
    return h3_deadline_plan.draw(&random);
}

/// Runs one seed twice, and returns the first run's trace.
pub fn run_seed(storage: *Storage, seed: u64) Violation!Result {
    const plan = plan_of(seed);
    try h3_deadline_run.run(&storage.run, &plan, seed);
    try verify(storage, &plan, seed);
    @memcpy(storage.first[0..storage.trace_len], storage.trace[0..storage.trace_len]);
    storage.first_len = storage.trace_len;
    const record = storage.run.record;
    try h3_deadline_run.run(&storage.run, &plan, seed);
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
        var wire_octets: [@sizeOf(u32)]u8 = undefined;
        std.mem.writeInt(u32, &wire_octets, result.record.wire.final(), .big);
        census.wire_crc32.update(&wire_octets);
        if (cut_a_request(seed, &result.record)) census.requests_cut += 1;
        // `verify` refused a run the server held open, so each run has a reason.
        switch (result.record.close_reason.?) {
            .limit => census.peer_resets += 1,
            .deadline => |passed| switch (passed) {
                .first_request => census.first_request += 1,
                .idle => census.idle += 1,
                .body_rate => census.body_rate += 1,
                .send_rate => census.send_rate += 1,
                // `expect` names none of these as a connection's end.
                .head, .body, .settings, .drain => unreachable,
            },
        }
    }
}

/// Whether the server ended a request of the run with a 408 or a reset. A peer that floods resets
/// its own.
fn cut_a_request(seed: u64, record: *const Record) bool {
    if (plan_of(seed).peer == .flooder) return false;
    for (record.seen) |seen| {
        if (seen.status == timeout_status or seen.reset != null) return true;
    }
    return false;
}

/// How decision 110 says a connection ends.
const End = union(enum) {
    /// A GOAWAY at `at_ms` for `deadline`, then a close with H3_NO_ERROR.
    drained: struct { deadline: server.Deadline, at_ms: u64 },
    /// A close with H3_EXCESSIVE_LOAD for `reason`, at `at_ms` when the plan fixes the instant.
    overloaded: struct { reason: server.CloseReason, at_ms: ?u64 },
};

/// What the peer must see of one of its first requests, where the plan fixes it.
const Want = struct {
    /// The status of the response and its instant, or null for a request that gets none.
    status: ?u16 = null,
    status_ms: ?u64 = null,
    /// The code of the server's RESET_STREAM and its instant.
    reset: ?u64 = null,
    reset_ms: ?u64 = null,
    /// Whether the peer must see this and no more: a status that is null means no response, and
    /// a reset that is null means no reset. Otherwise the reset alone is fixed, when there is one.
    exact: bool = false,
};

/// How decision 110 says a run ends, what the peer sees of its first requests on the way, and
/// the deadline the application reads for the first request it holds.
const Expected = struct {
    end: End,
    seen: [h3_deadline_run.kept_fetches]Want = @splat(.{}),
    cancelled: ?server.Deadline = null,
    cancelled_ms: ?u64 = null,
};

/// Checks the run's record against the plan, and writes the run's trace.
fn verify(storage: *Storage, plan: *const Plan, seed: u64) Violation!void {
    const record = &storage.run.record;
    try write_trace(storage, plan, seed);
    // An honest peer's exchanges end whole, however long the application takes (decision 110).
    if (plan.honest() and record.exchanges_done != plan.exchanges_len) return error.ExchangeLost;
    const expected = expect(plan, record) orelse return error.EndedWrong;
    if (record.end != .closed or !ended_as(record, expected.end, plan)) return error.EndedWrong;
    if (!requests_as(&expected, plan, record)) return error.EndedWrong;
}

/// Whether the peer saw of its first requests what the plan fixes, and the application read the
/// deadline that ended one, at its instant.
fn requests_as(expected: *const Expected, plan: *const Plan, record: *const Record) bool {
    if (plan.peer == .flooder and !flooded_as(plan, record)) return false;
    for (expected.seen, record.seen) |want, have| {
        if (!seen_as(want, have)) return false;
    }
    const cancelled = record.app.first_cancelled();
    const cancelled_for = if (cancelled) |answered| answered.cancelled else null;
    const cancelled_ms = if (cancelled) |answered| answered.cancelled_ms else null;
    return cancelled_for == expected.cancelled and cancelled_ms == expected.cancelled_ms;
}

fn ended_as(record: *const Record, end: End, plan: *const Plan) bool {
    const close = record.close orelse return false;
    if (!close.application) return false;
    const reason = record.close_reason orelse return false;
    return switch (end) {
        .drained => |drained| drained_as(record, close, drained.at_ms, plan) and
            std.meta.eql(reason, server.CloseReason{ .deadline = drained.deadline }),
        .overloaded => |overloaded| overloaded_as(close, overloaded.at_ms) and std.meta.eql(reason, overloaded.reason),
    };
}

/// RFC 9114 §5.2: the client reads the GOAWAY first, which the server sent at the deadline's
/// instant. The close follows once the client acknowledged the GOAWAY, and §8.1: it says no
/// error. A slow link carries each of the two a while.
fn drained_as(record: *const Record, close: h3_deadline_run.Close, at_ms: u64, plan: *const Plan) bool {
    const carry_ms = h3_deadline_link.carry_ms(plan.link_rate, h3_deadline_link.datagram_len_max);
    const goaway_ms = record.goaway_ms orelse return false;
    if (goaway_ms < at_ms or goaway_ms - at_ms > carry_ms) return false;
    if (close.at_ms < goaway_ms or close.at_ms - goaway_ms > limits.close_after_goaway_ms_max + carry_ms) return false;
    return close.error_code == h3.constants.error_no_error or h3.constants.is_reserved(close.error_code);
}

/// RFC 9114 §10.5: H3_EXCESSIVE_LOAD, at `at_ms` when the plan fixes the instant.
fn overloaded_as(close: h3_deadline_run.Close, at_ms: ?u64) bool {
    if (close.error_code != h3.constants.error_excessive_load) return false;
    return at_ms == null or close.at_ms == at_ms.?;
}

fn seen_as(want: Want, have: h3_deadline_run.Seen) bool {
    const reset_as = have.reset == want.reset and have.reset_ms == want.reset_ms;
    if (!want.exact) return want.reset == null or reset_as;
    return reset_as and have.status == want.status and have.status_ms == want.status_ms;
}

/// How decision 110 says the run ends under the plan's limits, or null when the run lacks what
/// its end is counted from.
fn expect(plan: *const Plan, record: *const Record) ?Expected {
    const deadlines = &plan.deadlines;
    const first_request_ms = ms_of(deadlines.first_request_ns.?);
    const idle_ms = ms_of(deadlines.idle_ns.?);
    const first_window_ms = ms_of(deadlines.rate_grace_ns + deadlines.rate_window_ns);
    const first = if (record.app.answers_len > 0) &record.app.answers[0] else null;
    return switch (plan.peer) {
        .honest, .slow_honest, .upload, .slow_reader, .slow_link, .idle_pinger => idle_after(record.app.last_done_ms(), idle_ms),
        .silent, .pinger => drains(.first_request, first_request_ms),
        .slow_head => late_first_head(deadlines),
        .slow_second_head => late_second_head(plan, first, record.seen[0].ended_ms),
        .slow_body => body_cut(first, first_window_ms, .body_rate, idle_ms),
        .long_body => body_cut(first, ms_of(deadlines.body_ns.?), .body, idle_ms),
        .holds_credit, .reads_slowly => stream_cut(first, first_window_ms, idle_ms),
        .deaf, .holds_connection_credit => send_overload(first, first_window_ms),
        .many_bodies => bodies_overload(first, first_window_ms),
        // The server's limit on open streams decides when the flood passes the reset limit.
        .flooder => .{ .end = .{ .overloaded = .{ .reason = .{ .limit = .peer_resets }, .at_ms = null } } },
    };
}

fn drains(passed: server.Deadline, at_ms: u64) Expected {
    return .{ .end = .{ .drained = .{ .deadline = passed, .at_ms = at_ms } } };
}

/// The idle deadline, counted from `since_ms`.
fn idle_after(since_ms: ?u64, idle_ms: u64) ?Expected {
    return drains(.idle, (since_ms orelse return null) + idle_ms);
}

/// A first head that never ends: the first-request deadline ends the connection, and the head's
/// own deadline its request, when that comes no later.
fn late_first_head(deadlines: *const server.Deadlines) Expected {
    const first_request_ms = ms_of(deadlines.first_request_ns.?);
    var expected = drains(.first_request, first_request_ms);
    expected.seen[0] = late_head(ms_of(deadlines.head_ns.?), first_request_ms);
    return expected;
}

/// A second head that never ends, begun the plan's gap after the first response ended at
/// `ended_ms`: the idle deadline still runs from the instant the first request was done.
fn late_second_head(plan: *const Plan, first: ?*const Answer, ended_ms: ?u64) ?Expected {
    const done_ms = (first orelse return null).done_ms orelse return null;
    const second_ms = (ended_ms orelse return null) + plan.gap_ms;
    const shut_down_ms = done_ms + ms_of(plan.deadlines.idle_ns.?);
    var expected = drains(.idle, shut_down_ms);
    expected.seen[1] = late_head(second_ms + ms_of(plan.deadlines.head_ns.?), shut_down_ms);
    return expected;
}

/// A body whose deadline `passed` `after_ms` after the application read its request: a 408 for
/// the peer and `cancelled` for the application then, and the idle deadline from there.
fn body_cut(first: ?*const Answer, after_ms: u64, passed: server.Deadline, idle_ms: u64) ?Expected {
    const cut_ms = (first orelse return null).read_ms + after_ms;
    var expected = drains(.idle, cut_ms + idle_ms);
    expected.seen[0] = .{ .status = timeout_status, .status_ms = cut_ms, .exact = true };
    expected.cancelled = passed;
    expected.cancelled_ms = cut_ms;
    return expected;
}

/// A response its stream's credit held for the first window after the application answered: a
/// reset for the peer and `cancelled` for the application then, and the idle deadline from there.
fn stream_cut(first: ?*const Answer, first_window_ms: u64, idle_ms: u64) ?Expected {
    const cut_ms = ((first orelse return null).answered_ms orelse return null) + first_window_ms;
    var expected = drains(.idle, cut_ms + idle_ms);
    expected.seen[0] = .{ .reset = h3.constants.error_request_cancelled, .reset_ms = cut_ms };
    expected.cancelled = .send_rate;
    expected.cancelled_ms = cut_ms;
    return expected;
}

/// A peer that acknowledged too little of a response in the first window after the application
/// answered, or that held it with its connection's credit: the connection closes then.
fn send_overload(first: ?*const Answer, first_window_ms: u64) ?Expected {
    const cut_ms = ((first orelse return null).answered_ms orelse return null) + first_window_ms;
    return .{ .end = .{ .overloaded = .{ .reason = .{ .deadline = .send_rate }, .at_ms = cut_ms } } };
}

/// Bodies that together brought too little in the first window after the application read the
/// first request: the connection closes then.
fn bodies_overload(first: ?*const Answer, first_window_ms: u64) ?Expected {
    const cut_ms = (first orelse return null).read_ms + first_window_ms;
    return .{ .end = .{ .overloaded = .{ .reason = .{ .deadline = .body_rate }, .at_ms = cut_ms } } };
}

/// A peer that floods is closed with the batch that carries the first cancelled request past the
/// limit (decision 110 as amended): no batch sooner, and none later.
fn flooded_as(plan: *const Plan, record: *const Record) bool {
    const limit = server.constants.quic_peer_reset_rate_max;
    return record.requests_opened > limit and record.requests_opened <= limit + plan.flood_batch_len;
}

/// A head that is late at `head_end_ms` gets a 408 then. One that is not late when the connection
/// begins to shut down, at `shut_down_ms`, is rejected then, and its client may send the request
/// again (RFC 9114 §4.1.1). At one instant the head gets its 408.
fn late_head(head_end_ms: u64, shut_down_ms: u64) Want {
    if (head_end_ms > shut_down_ms) return .{ .reset = h3.constants.error_request_rejected, .reset_ms = shut_down_ms, .exact = true };
    return .{ .status = timeout_status, .status_ms = head_end_ms, .exact = true };
}

/// RFC 9110 §15.5.9: 408 (Request Timeout).
const timeout_status: u16 = 408;

fn ms_of(ns: u64) u64 {
    return ns / limits.ns_per_ms;
}

/// The run's trace: the plan, each answer, and how the run ended.
fn write_trace(storage: *Storage, plan: *const Plan, seed: u64) Violation!void {
    const record = &storage.run.record;
    const deadlines = &plan.deadlines;
    storage.trace_len = 0;
    try line(storage, "{s} seed=0x{x} peer={t} base_ms={d}", .{ check_name, seed, plan.peer, plan.base_ms });
    try line(storage, " limits_ms={d}/{d}/{d}/{d}", .{
        ms_of(deadlines.first_request_ns.?), ms_of(deadlines.idle_ns.?), ms_of(deadlines.head_ns.?), ms_of(deadlines.body_ns.?),
    });
    try line(storage, " rates={d}/{d}/{d}/{d}", .{
        deadlines.body_rate_min.?, deadlines.send_rate_min.?, ms_of(deadlines.rate_grace_ns), ms_of(deadlines.rate_window_ns),
    });
    try line(storage, " exchanges={d} gap_ms={d} piece_len={d} read={d}/{d} link={d} batch={d}\n", .{
        plan.exchanges_len, plan.gap_ms, plan.piece_len, plan.read_len, plan.read_gap_ms, plan.link_rate, plan.flood_batch_len,
    });
    for (record.app.answers[0..record.app.answers_len], 0..) |answered, index| {
        try line(storage, "answer={d} read_ms={d} content_end_ms={?d} answered_ms={?d} finished_ms={?d} done_ms={?d} cancelled={?t}@{?d}\n", .{
            index,                answered.read_ms, answered.content_end_ms, answered.answered_ms,
            answered.finished_ms, answered.done_ms, answered.cancelled,      answered.cancelled_ms,
        });
    }
    try line(storage, "end={t} at_ms={d} exchanges_done={d} requests={d} goaway_ms={?d}", .{
        record.end, record.end_ms, record.exchanges_done, record.requests_opened, record.goaway_ms,
    });
    if (record.close) |close| try line(storage, " close=0x{x}@{d}", .{ close.error_code, close.at_ms });
    if (record.close_reason) |reason| switch (reason) {
        .deadline => |passed| try line(storage, " deadline={t}", .{passed}),
        .limit => |passed| try line(storage, " limit={t}", .{passed}),
    };
    for (record.seen) |seen| {
        try line(storage, " seen={?d}@{?d}/{?x}@{?d}", .{ seen.status, seen.status_ms, seen.reset, seen.reset_ms });
    }
    try line(storage, " dropped={d}\n", .{record.dropped});
}

fn line(storage: *Storage, comptime format: []const u8, arguments: anytype) Violation!void {
    const written = std.fmt.bufPrint(storage.trace[storage.trace_len..], format, arguments) catch return error.TraceFull;
    storage.trace_len += written.len;
}

var check_storage: Storage align(@alignOf(Storage)) = undefined;

test "decision 110: every h3 seed replays, honest peers finish their exchanges, and the census is pinned" {
    var census: Census = .{};
    var failed_seed: ?u64 = null;
    run_check(&check_storage, limits.check_seeds_default, &census, &failed_seed) catch |failure| {
        std.debug.print("h3-deadline: seed 0x{x} failed: {t}\n", .{ failed_seed.?, failure });
        return failure;
    };
    try std.testing.expect(census.exchanges > 0 and census.requests_cut > 0);
    try std.testing.expect(census.first_request > 0 and census.idle > 0 and census.peer_resets > 0);
    try std.testing.expect(census.body_rate > 0 and census.send_rate > 0);
    try std.testing.expectEqual(census_crc32_expected, census.crc32.final());
    try std.testing.expectEqual(census_wire_crc32_expected, census.wire_crc32.final());
}
