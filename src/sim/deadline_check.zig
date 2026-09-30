//! The deadline check (design §8 step 20b, decision 110): each seed's plan (`deadline_plan.zig`)
//! run between a server and its peer in simulated time (`deadline_run.zig`), twice. So:
//!   1. the two runs must write the same trace (invariant 5);
//!   2. an honest peer's exchanges must each end with a whole response, however long the
//!      application takes to answer;
//!   3. every run must end at the deadline decision 110 names, at its instant under the plan's
//!      limits: an honest peer or an idle pinger at the idle deadline after its last response has
//!      left the server's output, a silent peer or a pinger at the first-request deadline, a slow
//!      head at the first-request or the head deadline, a slow body at the end of its first
//!      window short of the quota, or at its cap, and a peer that reads too little at the end of
//!      its first window after its answer. A PING moves no deadline;
//!   4. and as decision 110 says: a head that began gets a 408 in h11 and a GOAWAY with
//!      ENHANCE_YOUR_CALM in h2, and with none begun h11 sends nothing and h2 a GOAWAY with
//!      NO_ERROR. A slow body gets a 408: in h11 on a connection that then closes, and in h2 on
//!      its stream, with RST_STREAM and NO_ERROR, after which the connection is idle. A peer that
//!      reads too little reads nothing more, and its connection closes when its linger passes; in
//!      h2 a stream whose window is opened too slowly gets RST_STREAM with CANCEL, and a peer that
//!      never opens the connection's window a GOAWAY with ENHANCE_YOUR_CALM. A peer that opens
//!      many streams has those past the server's limit refused, and the rest cut for their bodies.
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
pub const census_crc32_expected: u32 = 0x6d3f1273;

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
    body_rate: u64 = 0,
    body: u64 = 0,
    send_rate: u64 = 0,
    settings: u64 = 0,
    drain: u64 = 0,
    /// The h2 streams the server refused, past its concurrent streams.
    streams_refused: u64 = 0,
    /// The runs in which a deadline ended a request the application held, the connection going on.
    streams_cut: u64 = 0,
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
        if (result.record.app.cancelled != null) census.streams_cut += 1;
        census.streams_refused += result.record.resets_refused;
        const passed = result.record.deadline_passed() orelse {
            census.held += 1;
            continue;
        };
        switch (passed) {
            .first_request => census.first_request += 1,
            .idle => census.idle += 1,
            .head => census.head += 1,
            .body_rate => census.body_rate += 1,
            .body => census.body += 1,
            .send_rate => census.send_rate += 1,
            .settings => census.settings += 1,
            .drain => census.drain += 1,
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
        if (record.end != .held or record.close_reason != null) return error.EndedWrong;
        return;
    };
    if (record.end != .closed or record.end_ms != expected.end_ms) return error.EndedWrong;
    if (record.deadline_passed() != expected.deadline) return error.EndedWrong;
    if (!plan.honest() and !ended_as_expected(plan, record, expected)) return error.EndedWrong;
}

/// How decision 110 says a run ends: by which deadline, at which instant, whether a request head
/// had begun, which decides the response, and where a slow body was cut.
const Expected = struct {
    deadline: server.Deadline,
    end_ms: u64,
    head: bool,
    cut: ?Cut = null,
};

/// The deadline that cut an h2 stream, or a slow h11 body, and its instant; in h2 the status of
/// the stream's response and the code of its RST_STREAM.
const Cut = struct {
    deadline: server.Deadline,
    at_ms: u64,
    status: u16,
    reset_code: u32,
};

/// How decision 110 says the run ends under the plan's limits, or null for a run the server holds
/// open until the horizon.
fn expect(plan: *const Plan, record: *const Record) ?Expected {
    const first_request_ms = ms_of(plan.deadlines.first_request_ns.?);
    const head_ms = ms_of(plan.deadlines.head_ns.?);
    return switch (plan.peer) {
        .honest, .slow_honest, .upload, .slow_reader, .idle_pinger => .{
            .deadline = .idle,
            .end_ms = record.app.last_drained_ms() + ms_of(plan.deadlines.idle_ns.?),
            .head = false,
        },
        .silent, .pinger => .{ .deadline = .first_request, .end_ms = first_request_ms, .head = false },
        .slow_head => slow_first_head(plan, first_request_ms, head_ms),
        .slow_second_head => .{
            .deadline = .head,
            .end_ms = plan.answer_delay_ms[0] + limits.second_head_after_ms + head_ms,
            .head = true,
        },
        .slow_body, .long_body => slow_body(plan),
        .reads_nothing, .reads_slowly => .{
            .deadline = .send_rate,
            .end_ms = send_cut_ms(plan) + ms_of(plan.deadlines.linger_ns.?),
            .head = false,
        },
        .opens_window_slowly => .{
            .deadline = .idle,
            .end_ms = send_cut_ms(plan) + ms_of(plan.deadlines.idle_ns.?),
            .head = false,
            .cut = .{ .deadline = .send_rate, .at_ms = send_cut_ms(plan), .status = answer_status, .reset_code = h2.constants.error_cancel },
        },
        .opens_no_connection_window => .{ .deadline = .send_rate, .end_ms = send_cut_ms(plan), .head = false },
        // Every stream's body is cut at the end of its first window, which brings nothing, and the
        // connection is idle from then.
        .many_streams => .{
            .deadline = .idle,
            .end_ms = ms_of(plan.deadlines.rate_grace_ns) + ms_of(plan.deadlines.rate_window_ns) + ms_of(plan.deadlines.idle_ns.?),
            .head = false,
        },
    };
}

/// The streams the server accepts at once, decision 110's default, which the run leaves in its
/// `server.Config`. It refuses those past it with REFUSED_STREAM (RFC 9113 §5.1.2).
const streams_limit: u32 = server.constants.h2_streams_max;

/// A peer that opens many streams has those past the server's limit refused, and each of the
/// rest ends with a 408 and RST_STREAM with NO_ERROR.
fn streams_as_expected(plan: *const Plan, record: *const Record) bool {
    if (plan.peer != .many_streams) return true;
    const accepted = @min(limits.many_streams_len, streams_limit);
    return record.resets_no_error == accepted and record.resets_refused == limits.many_streams_len - accepted and
        record.response_status == timeout_status and record.app.cancelled == .body_rate;
}

/// Where the server cuts a peer that reads too little: the end of the first window after its
/// answer began. The answer outgrows the socket and the server's output at once, and the peer
/// takes less than a window's quota of it.
fn send_cut_ms(plan: *const Plan) u64 {
    return plan.answer_delay_ms[0] + ms_of(plan.deadlines.rate_grace_ns) + ms_of(plan.deadlines.rate_window_ns);
}

/// The status of an answer: 200 (OK), RFC 9110 §15.3.1.
const answer_status: u16 = 200;

/// A slow or long body ends where `body_cut` says: in h11 with the connection, and in h2 with its stream,
/// after which the connection is idle.
fn slow_body(plan: *const Plan) Expected {
    const cut = body_cut(plan);
    return switch (plan.protocol) {
        .h11 => .{ .deadline = cut.deadline, .end_ms = cut.at_ms, .head = false, .cut = cut },
        .h2 => .{ .deadline = .idle, .end_ms = cut.at_ms + ms_of(plan.deadlines.idle_ns.?), .head = false, .cut = cut },
    };
}

/// Where the server cuts a slow body under the plan's limits, worked out from the peer's pieces:
/// the end of the first window that brings less than the quota, or the cap, whichever comes first.
/// The body's wait starts when its head arrives, at the start of the run, and a piece counts in the
/// window it arrives in; a window ends at its instant, and the cap passes first at one instant.
fn body_cut(plan: *const Plan) Cut {
    const deadlines = &plan.deadlines;
    const window_ms = ms_of(deadlines.rate_window_ns);
    const cap_ms = ms_of(deadlines.body_ns.?);
    const quota = deadlines.body_quota().?;
    var start_ms: u64 = 0;
    var end_ms = ms_of(deadlines.rate_grace_ns) + window_ms;
    // Bounded: each pass moves a window on, and the cap ends them.
    for (0..cap_ms / window_ms + 1) |_| {
        if (end_ms >= cap_ms) break;
        if (body_octets(plan, start_ms, end_ms) < quota) return body_cut_at(.body_rate, end_ms);
        start_ms = end_ms;
        end_ms += window_ms;
    }
    return body_cut_at(.body, cap_ms);
}

/// A body cut at `at_ms`: a 408, then RST_STREAM with NO_ERROR in h2.
fn body_cut_at(passed: server.Deadline, at_ms: u64) Cut {
    return .{ .deadline = passed, .at_ms = at_ms, .status = timeout_status, .reset_code = h2.constants.error_no_error };
}

/// The octets of the body's pieces that arrive from `start_ms` to before `end_ms`: one piece a gap
/// after the start and each gap after, until the body stops.
fn body_octets(plan: *const Plan, start_ms: u64, end_ms: u64) u64 {
    const first = @max(1, (start_ms + plan.gap_ms - 1) / plan.gap_ms);
    const last = @min((end_ms - 1) / plan.gap_ms, (deadline_plan.body_end_ms(plan) - 1) / plan.gap_ms);
    if (last < first) return 0;
    return (last - first + 1) * plan.piece_len;
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
    if (expected.cut) |cut| return cut_as_expected(plan, record, cut);
    return switch (plan.protocol) {
        .h11 => record.saw_timeout_response == expected.head,
        .h2 => record.goaway_code == goaway_of(plan, expected) and streams_as_expected(plan, record),
    };
}

/// The code of the GOAWAY a hostile h2 peer reads at the end, or null for one it never reads.
fn goaway_of(plan: *const Plan, expected: Expected) ?u32 {
    return switch (plan.peer) {
        // The GOAWAY waits behind the octets the peer does not read.
        .reads_nothing, .reads_slowly => null,
        .opens_no_connection_window => h2.constants.error_enhance_your_calm,
        else => if (expected.head) h2.constants.error_enhance_your_calm else h2.constants.error_no_error,
    };
}

/// A cut body reads a 408 in h11 before the connection closes. In h2 a cut stream's response ends
/// with its status and RST_STREAM at the cut's instant, the caller reads `cancelled` for it, and a
/// GOAWAY with NO_ERROR follows once the connection is idle.
fn cut_as_expected(plan: *const Plan, record: *const Record, cut: Cut) bool {
    return switch (plan.protocol) {
        .h11 => record.saw_timeout_response,
        .h2 => record.response_status == cut.status and
            record.reset_code == cut.reset_code and record.reset_at_ms == cut.at_ms and
            record.app.cancelled == cut.deadline and record.goaway_code == h2.constants.error_no_error,
    };
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
    try line(storage, "{s} seed=0x{x} protocol={t} peer={t} base_ms={d}", .{ check_name, seed, plan.protocol, plan.peer, plan.base_ms });
    try line(storage, " limits_ms={d}/{d}/{d}", .{ ms_of(deadlines.first_request_ns.?), ms_of(deadlines.idle_ns.?), ms_of(deadlines.head_ns.?) });
    try line(storage, " body={d}/{d}/{d}/{d}", .{
        deadlines.body_rate_min.?, ms_of(deadlines.rate_grace_ns), ms_of(deadlines.rate_window_ns), ms_of(deadlines.body_ns.?),
    });
    try line(storage, " exchanges={d} gap_ms={d} piece_len={d}\n", .{ plan.exchanges_len, plan.gap_ms, plan.piece_len });
    for (record.app.answers[0..record.app.answers_len], 0..) |answered, index| {
        try line(storage, "answer={d} read_ms={d} body_end_ms={?d} answered_ms={?d} sent={d} drained_ms={?d}\n", .{
            index, answered.read_ms, answered.body_end_ms, answered.answered_ms, answered.content_sent, answered.drained_ms,
        });
    }
    try line(storage, "end={t} at_ms={d} deadline={?t} exchanges_done={d}", .{ record.end, record.end_ms, record.deadline_passed(), record.exchanges_done });
    try line(storage, " timeout_response={} status={?d} reset={?d} reset_at_ms={?d} cancelled={?t} goaway={?d}", .{
        record.saw_timeout_response, record.response_status, record.reset_code, record.reset_at_ms, record.app.cancelled, record.goaway_code,
    });
    try line(storage, " resets={d}/{d}\n", .{ record.resets_no_error, record.resets_refused });
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
