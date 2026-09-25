//! The h11 connection check (design §8 step 15b): a colibri client and a colibri server run a
//! seed's exchanges (`h11_exchange_plan.zig`) over two byte streams, one each way, delivered in
//! seeded chunks.
//!
//! The client writes each request as soon as the connection lets it (decision 88). The server reads
//! a request whole, holds it for the plan's delay while the requests pipelined behind it arrive,
//! reads nothing past it meanwhile, and answers it as the plan says (decision 92).
//!
//! Each seed runs three times: in chunks, in the same chunks again, and with each direction's
//! octets delivered whole as soon as they are written. When the client pipelines depends on when
//! responses arrive, so the trace records only what no delivery can change: for each exchange the
//! server answered, its status and both bodies' lengths and CRC-32s, then how many were answered.
//! So:
//!   1. the two chunked runs must write the same trace and draw the same values (invariant 5);
//!   2. the chunked run's trace must be the whole run's;
//!   3. every body each side read must be the plan's, with its trailer when it is chunked;
//!   4. the server must answer exactly the exchanges up to the one that closes the connection, and
//!      both sides must close after it (RFC 9112 §9.6): the close cuts no message short, and leaves
//!      unanswered only the requests the client pipelined past it.
//!
//! The census hashes the chunked traces of seeds `[0, check_seeds_default)` with CRC-32, and the
//! test requires the digest committed below, in Debug and in ReleaseSafe alike.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const h11 = @import("h11");
const sim = @import("sim");
const h11_exchange_plan = @import("h11_exchange_plan.zig");
const h11_exchange_run = @import("h11_exchange_run.zig");

const Writer = core.Writer;
const Random = sim.Random;
const Trace = sim.Trace;
const constants = sim.constants;
const Plan = h11_exchange_plan.Plan;
const Run = h11_exchange_run.Run;
const Stream = h11_exchange_run.Stream;
const Seen = h11_exchange_run.Seen;
const Connection = h11.connection.Connection;

/// The name every h11 connection-check trace carries on its first line.
pub const check_name = "h11-connection";

/// The CRC-32 of the chunked traces of seeds `[0, check_seeds_default)`, concatenated in seed
/// order. A change to the plan, either side's results or the trace format changes it, and is
/// committed with the new value after the check passes in both build modes.
pub const census_crc32_expected: u32 = 0x701b34cd;

pub const Violation = h11_exchange_run.Error || error{
    /// Two chunked runs of the seed wrote different traces or drew a different number of values.
    ReplayDiverged,
    /// The chunked run's exchanges differ from the whole run's.
    SplitChangedResult,
    /// The server answered other exchanges than the plan says, or the run did not end within its
    /// steps.
    OutcomeUnexpected,
};

/// The storage one seed runs in, outside any stack frame (decision 35).
pub const Storage = struct {
    plan: Plan,
    client: Connection,
    server: Connection,
    to_server: Stream,
    to_client: Stream,
    request_seen: [constants.h11_exchange_count_max]Seen,
    response_seen: [constants.h11_exchange_count_max]Seen,
    chunked: [constants.h11_exchange_trace_len_max]u8,
    replayed: [constants.h11_exchange_trace_len_max]u8,
    whole: [constants.h11_exchange_trace_len_max]u8,
};

pub const SeedResult = struct {
    /// Exchanges the client read a whole response to.
    answered: u32,
    /// Requests the client wrote, which a close may leave unanswered.
    sent: u32,
    /// Steps the run took, each delivering octets one way or the other.
    steps: u64,
    /// The trace, inside the storage the seed ran in.
    trace: []const u8,
};

pub fn run_seed(storage: *Storage, seed: u64) Violation!SeedResult {
    var random = Random.init(seed);
    storage.plan.draw(&random);
    var chunked_random = random;
    var replayed_random = random;
    const chunked = try run_once(storage, seed, &chunked_random, &storage.chunked);
    const replayed = try run_once(storage, seed, &replayed_random, &storage.replayed);
    const whole = try run_once(storage, seed, null, &storage.whole);
    if (!std.mem.eql(u8, chunked.trace, replayed.trace)) return error.ReplayDiverged;
    if (chunked_random.draws != replayed_random.draws) return error.ReplayDiverged;
    if (!std.mem.eql(u8, chunked.trace, whole.trace)) return error.SplitChangedResult;
    if (chunked.answered != storage.plan.answered()) return error.OutcomeUnexpected;
    return chunked;
}

/// Runs the plan with each direction delivered in chunks drawn from `random`, or whole as soon as
/// it is written when `random` is null.
fn run_once(storage: *Storage, seed: u64, random: ?*Random, buffer: []u8) Violation!SeedResult {
    storage.client.init(.client, .{});
    storage.server.init(.server, .{});
    storage.to_server = .{};
    storage.to_client = .{};
    storage.request_seen = @splat(.{});
    storage.response_seen = @splat(.{});
    var run: Run = .{
        .plan = &storage.plan,
        .client = &storage.client,
        .server = &storage.server,
        .to_server = &storage.to_server,
        .to_client = &storage.to_client,
        .request_seen = &storage.request_seen,
        .response_seen = &storage.response_seen,
    };
    var steps: u64 = 0;
    // Each step delivers at least one octet one way or the other, moves a held request closer to
    // its answer, or ends the run.
    for (0..constants.h11_exchange_steps_max) |_| {
        steps += 1;
        try run.send_requests();
        const to_server = storage.to_server.deliver(random);
        try run.serve();
        const to_client = storage.to_client.deliver(random);
        try run.read_responses();
        if (!to_server and !to_client and !run.holding) break;
    } else return error.OutcomeUnexpected;
    try run.settle();
    var output = Writer.init(buffer);
    var trace = try Trace.begin(&output, check_name, seed);
    try run.write_summary(&trace);
    try trace.end("pass");
    return .{ .answered = run.answered, .sent = run.sent, .steps = steps, .trace = output.written() };
}

/// What a range of seeds did.
pub const Census = struct {
    seeds: u64 = 0,
    answered: u64 = 0,
    unanswered: u64 = 0,
    steps: u64 = 0,
    trace_octets: u64 = 0,
    crc32: std.hash.Crc32 = .init(),

    fn count(census: *Census, result: SeedResult) void {
        census.seeds += 1;
        census.answered += result.answered;
        census.unanswered += result.sent - result.answered;
        census.steps += result.steps;
        census.trace_octets += result.trace.len;
        census.crc32.update(result.trace);
    }
};

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

/// The storage the check test runs in, placed outside any stack frame.
var test_storage: Storage = undefined;

test "h11 connection check: seeds replay, no split changes an exchange, and traces hash as committed" {
    var census: Census = .{};
    var failed_seed: ?u64 = null;
    run_check(&test_storage, constants.check_seeds_default, &census, &failed_seed) catch |failure| {
        std.debug.print("h11 connection check: seed 0x{x} failed: {t}\n", .{ failed_seed.?, failure });
        return failure;
    };
    // Some seeds close with requests pipelined past the close, which go unanswered.
    try testing.expect(census.answered > census.seeds and census.unanswered > 0);
    try testing.expect(census.steps > census.seeds);
    try testing.expectEqual(census_crc32_expected, census.crc32.final());
}
