//! The endpoint check (design §8 step 21b.5, decision 119): each seed's plan
//! (`endpoint_plan.zig`) run through one endpoint with fewer slots than peers, twice
//! (`endpoint_run.zig`). The program checks, while the run goes:
//!   - P1: every new request's id is new (`endpoint_ledger.zig`);
//!   - P2: every later event of a request carries the word the program set last;
//!   - P3: each request ends once, and nothing of it comes after;
//!   - P4: each connection ends once, after its requests, nothing names it after, and a call by
//!     its handle or by an ended request's id is refused (`endpoint_program_stale.zig`);
//!   - P5: after every call, `deadline_ns()` is the soonest deadline of the live slots
//!     (`endpoint_program.zig`);
//!   - P6: once a pass moves nothing, the endpoint owes no octet, no event, no datagram and no
//!     `writable`;
//!   - P7: every `send` brings an octet (`endpoint_run_route.zig`);
//!   - P8: once a pass moves nothing, the endpoint's deadline has not come.
//!
//! The two runs of a seed must write the same trace (invariant 5), and P9, that Debug and
//! ReleaseSafe agree, is the census test's CRC in both build modes.
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");
const server = @import("server");
const plan_module = @import("endpoint_plan.zig");
const run_module = @import("endpoint_run.zig");
const tcp_module = @import("endpoint_tcp.zig");
const ledger_module = @import("endpoint_ledger.zig");

const Random = sim.Random;
const limits = sim.constants.endpoint;
const Plan = plan_module.Plan;

/// The name every endpoint trace carries on its first line.
pub const check_name = "endpoint";

/// The CRC-32 of the traces of seeds `[0, check_seeds_default)`, concatenated in seed order, and
/// of the runs' wire CRC-32s. A change to the plan, to what the endpoint does or to the trace
/// format changes the first, and one to what goes over the wire changes the second. Each is
/// committed with its new value once the check passes in both build modes.
pub const census_crc32_expected: u32 = 0x560d5625;
pub const census_wire_crc32_expected: u32 = 0x5ec49f44;

pub const Violation = run_module.Error || error{
    /// Two runs of one seed wrote different traces.
    ReplayDiverged,
    /// The trace passed its buffer.
    TraceFull,
};

/// The storage one seed runs in, outside any stack frame (decision 35).
pub const Storage = struct {
    run: run_module.Storage,
    trace: [limits.trace_len_max]u8,
    trace_len: usize,
    first: [limits.trace_len_max]u8,
    first_len: usize,
};

pub const Result = struct {
    trace: []const u8,
    wire: u32,
};

/// What `run_check` counted over its seeds.
pub const Census = struct {
    seeds: u64 = 0,
    connections: u64 = 0,
    reused: u64 = 0,
    requests: u64 = 0,
    done: u64 = 0,
    cancelled_peer_reset: u64 = 0,
    cancelled_deadline: u64 = 0,
    cancelled_closed: u64 = 0,
    cancelled_program: u64 = 0,
    writable: u64 = 0,
    sends: u64 = 0,
    closes: u64 = 0,
    stale_calls: u64 = 0,
    waiting_probes: u64 = 0,
    accept_waits: u64 = 0,
    shutdowns: u64 = 0,
    unserved: u64 = 0,
    failed: u64 = 0,
    trace_octets: u64 = 0,
    crc32: std.hash.Crc32 = .init(),
    wire_crc32: std.hash.Crc32 = .init(),

    fn add(census: *Census, storage: *const Storage, result: *const Result) void {
        const run = &storage.run;
        const counts = &run.ledger.counts;
        census.seeds += 1;
        census.connections += run.ledger.connections_len;
        census.reused += run.record.reused;
        census.requests += counts.requests;
        census.done += counts.done;
        census.cancelled_peer_reset += counts.cancelled[@intFromEnum(server.CancelReason.peer_reset)];
        census.cancelled_deadline += counts.cancelled[@intFromEnum(std.meta.Tag(server.CancelReason).deadline)];
        census.cancelled_closed += counts.cancelled[@intFromEnum(server.CancelReason.closed)];
        census.cancelled_program += counts.cancelled[@intFromEnum(server.CancelReason.program)];
        census.writable += counts.writable;
        census.sends += counts.sends;
        census.closes += counts.closes;
        census.stale_calls += run.program.counts.stale_calls;
        census.waiting_probes += run.program.counts.waiting_probes;
        census.accept_waits += run.record.accept_waits;
        census.shutdowns += run.program.counts.shutdowns;
        census.unserved += run.record.unserved;
        census.failed += counts.failed;
        census.trace_octets += result.trace.len;
        census.crc32.update(result.trace);
        var wire_octets: [@sizeOf(u32)]u8 = undefined;
        std.mem.writeInt(u32, &wire_octets, result.wire, .big);
        census.wire_crc32.update(&wire_octets);
    }
};

/// The plan of `seed`.
pub fn plan_of(seed: u64) Plan {
    var random = Random.init(seed);
    return plan_module.draw(&random);
}

/// Runs one seed twice, and returns the first run's trace. A run that fails writes its trace with
/// the violation's place, which `--endpoint-seed` prints.
pub fn run_seed(storage: *Storage, seed: u64) Violation!Result {
    const plan = plan_of(seed);
    try run_once(storage, &plan, seed);
    @memcpy(storage.first[0..storage.trace_len], storage.trace[0..storage.trace_len]);
    storage.first_len = storage.trace_len;
    const wire = storage.run.record.wire.final();
    try run_once(storage, &plan, seed);
    // Invariant 5: one seed replays byte for byte.
    if (!std.mem.eql(u8, storage.first[0..storage.first_len], storage.trace[0..storage.trace_len])) return error.ReplayDiverged;
    if (wire != storage.run.record.wire.final()) return error.ReplayDiverged;
    return .{ .trace = storage.first[0..storage.first_len], .wire = wire };
}

fn run_once(storage: *Storage, plan: *const Plan, seed: u64) Violation!void {
    run_module.run(&storage.run, plan, seed) catch |failure| {
        write_trace(storage, plan, seed) catch {};
        line(storage, "violation={t} at_ms={d} call={s} slot={d} generation={d} number={d}\n", .{
            failure,
            storage.run.ledger.fault.at_ms,
            storage.run.ledger.fault.call,
            storage.run.ledger.fault.slot,
            storage.run.ledger.fault.generation,
            storage.run.ledger.fault.number,
        }) catch {};
        return failure;
    };
    try write_trace(storage, plan, seed);
}

/// Runs seeds `[0, seeds)`, adding each to `census`, and names the seed that failed.
pub fn run_check(storage: *Storage, seeds: u64, census: *Census, failed_seed: *?u64) Violation!void {
    for (0..seeds) |seed| {
        const result = run_seed(storage, seed) catch |failure| {
            failed_seed.* = seed;
            return failure;
        };
        census.add(storage, &result);
    }
}

/// The run's trace: the plan, a line for each peer, and the totals.
fn write_trace(storage: *Storage, plan: *const Plan, seed: u64) Violation!void {
    const run = &storage.run;
    storage.trace_len = 0;
    try line(storage, "{s} seed=0x{x} base_ms={d} shutdown_ms={?d}\n", .{ check_name, seed, plan.base_ms, plan.shutdown_ms });
    for (&plan.tcp, &run.tcp.peers, 0..) |*peer_plan, *peer, index| {
        try line(storage, "{s} peer={t} overlay={t} arrive_ms={d} accepted_ms={?d} exchanges_done={d}", .{
            tcp_module.kind_name(peer_plan), peer_plan.behaviour.peer, peer_plan.overlay, peer_plan.arrive_ms, peer.accepted_ms, peer.exchanges_done,
        });
        try connection_line(storage, .tcp, index);
    }
    for (&plan.quic, &run.quic.peers, 0..) |*peer_plan, *peer, index| {
        try line(storage, "quic peer={t} overlay={t} arrive_ms={d} requests={d}", .{
            peer_plan.behaviour.peer, peer_plan.overlay, peer_plan.arrive_ms, peer.peer.fetches_len,
        });
        try connection_line(storage, .quic, index);
    }
    const counts = &run.ledger.counts;
    try line(storage, "events={d}/{d}/{d}/{d}/{d}/{d}/{d}/{d} calls={d} stale={d} probes={d} deadlines_refused={d}", .{
        counts.requests,                   counts.bodies,                        counts.trailers, counts.done,              counts.writable,
        counts.sends,                      counts.closes,                        counts.ended,    run.program.counts.calls, run.program.counts.stale_calls,
        run.program.counts.waiting_probes, run.program.counts.deadlines_refused,
    });
    try line(storage, " end={t} end_ms={d} reused={d} waits={d} unserved={d} dropped={d} event_crc32=0x{x:0>8} wire_crc32=0x{x:0>8}\n", .{
        run.record.end,      run.record.end_ms,  run.record.reused,         run.record.accept_waits,
        run.record.unserved, run.record.dropped, run.ledger.events.final(), run.record.wire.final(),
    });
}

/// The end of a peer's line: its connection's handle, and when and how it ended.
fn connection_line(storage: *Storage, kind: ledger_module.Kind, index: usize) Violation!void {
    const ledger = &storage.run.ledger;
    for (ledger.connections[0..ledger.connections_len]) |*connection| {
        if (connection.kind != kind or connection.peer != index) continue;
        try line(storage, " handle={d}/{d} requests={d}/{d}/{d} ended_ms={?d} failed={}", .{
            connection.handle.slot, connection.handle.generation, connection.requests, connection.done, connection.cancelled, connection.ended_ms, connection.failed,
        });
        if (connection.reason) |reason| switch (reason) {
            .deadline => |passed| try line(storage, " deadline={t}", .{passed}),
            .limit => |passed| try line(storage, " limit={t}", .{passed}),
        };
    }
    try line(storage, "\n", .{});
}

fn line(storage: *Storage, comptime format: []const u8, arguments: anytype) Violation!void {
    const written = std.fmt.bufPrint(storage.trace[storage.trace_len..], format, arguments) catch return error.TraceFull;
    storage.trace_len += written.len;
}

var check_storage: Storage align(@alignOf(Storage)) = undefined;

test "decision 119: every seed's peers share one endpoint, each property holds, and the census is pinned" {
    var census: Census = .{};
    var failed_seed: ?u64 = null;
    run_check(&check_storage, limits.check_seeds_default, &census, &failed_seed) catch |failure| {
        std.debug.print("{s}", .{check_storage.trace[0..check_storage.trace_len]});
        std.debug.print("endpoint: seed 0x{x} failed: {t}\n", .{ failed_seed.?, failure });
        return failure;
    };
    const counted = [_]u64{
        census.connections,          census.reused,             census.requests,         census.done,
        census.cancelled_peer_reset, census.cancelled_deadline, census.cancelled_closed, census.cancelled_program,
        census.writable,             census.sends,              census.closes,           census.stale_calls,
        census.waiting_probes,       census.accept_waits,       census.shutdowns,
    };
    for (counted) |count| try std.testing.expect(count > 0);
    try std.testing.expectEqual(census_crc32_expected, census.crc32.final());
    try std.testing.expectEqual(census_wire_crc32_expected, census.wire_crc32.final());
}
