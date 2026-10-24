//! The content-coding check (design §8 step 17e, decision 101): each seed's plan
//! (`content_coding_plan.zig`) run between a colibri client and a colibri server
//! (`content_coding_run.zig`), twice in the same seeded pieces and once whole. So:
//!   1. the two runs in pieces must write the same trace and draw the same values (invariant 5);
//!   2. the whole run must write that trace too: neither a split nor what the server takes on each
//!      write changes what arrives;
//!   3. each exchange must end as decision 101's rules say, each body must arrive octet for octet,
//!      and every encoder and decoder must be back in its pool.
//!
//! The census hashes the traces of the first runs of seeds `[0, check_seeds_default)` with CRC-32,
//! and the octets their clients wrote, and the test requires the two digests committed below, in
//! Debug and in ReleaseSafe alike.
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");
const client = @import("client");
const gzip = @import("gzip");
const zlib = @import("zlib");
const content_coding_plan = @import("content_coding_plan.zig");
const content_coding_run = @import("content_coding_run.zig");

const Random = sim.Random;
const limits = sim.constants.content_coding;
const Plan = content_coding_plan.Plan;
const Coding = client.Coding;

/// The name every content-coding trace carries on its first line.
pub const check_name = "content-coding";

/// The CRC-32 of the first runs' traces of seeds `[0, check_seeds_default)`, concatenated in seed
/// order, and of the seeds' `Result.wire`. A change to the plan, to what the modules deliver or to
/// the trace format changes the first, and one to an octet the client writes changes the second.
/// Each is committed with its new value once the check passes in both build modes.
pub const census_crc32_expected: u32 = 0x69460a6e;
pub const census_wire_crc32_expected: u32 = 0xc8625587;

pub const Violation = content_coding_run.Error || error{
    /// Two runs in the same pieces wrote different traces or drew a different number of values.
    ReplayDiverged,
    /// The run in pieces delivered something other than the run in one piece delivered.
    SplitChangedResult,
    /// An exchange ended other than decision 101 says, or a body differs from the content.
    ExchangeDiffers,
    /// An encoder or a decoder did not go back to its pool.
    PoolLeaked,
    /// The trace passed its buffer.
    TraceFull,
};

/// The storage one seed runs in, outside any stack frame (decision 35).
pub const Storage = struct {
    run: content_coding_run.Storage,
    trace: [trace_len_max]u8,
    trace_len: usize,
    first: [trace_len_max]u8,
    first_len: usize,
    decoded: [limits.content_len_max]u8,
    gzip_decoder: gzip.Decoder,
    zlib_decoder: zlib.Decoder,
};

/// Octets of one seed's trace: its first line, and a line for each exchange.
const trace_len_max: usize = line_len_max * (limits.requests_max + 1);
const line_len_max: usize = 128;

/// What distinguishes the pieces' seed from the plan's.
const pieces_mark: u64 = 0x7069_6563_6573_2121;

pub const Result = struct {
    trace: []const u8,
    requests: u32,
    /// The CRC-32 of every octet the client wrote to the server in the first run.
    wire: u32,
};

/// What `run_check` counted over its seeds.
pub const Census = struct {
    seeds: u64 = 0,
    requests: u64 = 0,
    decoded: u64 = 0,
    passed_on: u64 = 0,
    too_large: u64 = 0,
    trace_octets: u64 = 0,
    crc32: std.hash.Crc32 = .init(),
    /// The CRC-32 of each seed's `Result.wire`, least significant octet first, in seed order.
    wire_crc32: std.hash.Crc32 = .init(),
};

/// Runs one seed three times, and returns the first run's trace.
pub fn run_seed(storage: *Storage, seed: u64) Violation!Result {
    var plan_random = Random.init(seed);
    const plan = content_coding_plan.draw(&plan_random);
    var pieces = Random.init(seed ^ pieces_mark);
    try content_coding_run.run(&storage.run, &plan, seed, &pieces);
    try verify(storage, &plan, seed);
    @memcpy(storage.first[0..storage.trace_len], storage.trace[0..storage.trace_len]);
    storage.first_len = storage.trace_len;
    const first_draws = pieces.draws;
    const wire = wire_of(storage);
    var again = Random.init(seed ^ pieces_mark);
    try content_coding_run.run(&storage.run, &plan, seed, &again);
    try verify(storage, &plan, seed);
    // Invariant 5: one seed replays byte for byte, in its trace and in what its client wrote.
    if (again.draws != first_draws or wire != wire_of(storage) or !same_trace(storage)) return error.ReplayDiverged;
    // The whole run's octets are not compared: a split may change when the client writes a
    // WINDOW_UPDATE.
    try content_coding_run.run(&storage.run, &plan, seed, null);
    try verify(storage, &plan, seed);
    if (!same_trace(storage)) return error.SplitChangedResult;
    return .{ .trace = storage.first[0..storage.first_len], .requests = plan.requests_count, .wire = wire };
}

/// The CRC-32 of every octet the last run's client wrote to the server.
fn wire_of(storage: *const Storage) u32 {
    return std.hash.Crc32.hash(storage.run.to_server.octets[0..storage.run.to_server.written]);
}

fn same_trace(storage: *const Storage) bool {
    return std.mem.eql(u8, storage.first[0..storage.first_len], storage.trace[0..storage.trace_len]);
}

/// Runs seeds `[0, seeds)`, adding each to `census`, and names the seed that failed.
pub fn run_check(storage: *Storage, seeds: u64, census: *Census, failed_seed: *?u64) Violation!void {
    for (0..seeds) |seed| {
        const result = run_seed(storage, seed) catch |failure| {
            failed_seed.* = seed;
            return failure;
        };
        census.seeds += 1;
        census.requests += result.requests;
        census.trace_octets += result.trace.len;
        census.crc32.update(result.trace);
        var wire_octets: [@sizeOf(u32)]u8 = undefined;
        std.mem.writeInt(u32, &wire_octets, result.wire, .little);
        census.wire_crc32.update(&wire_octets);
        count(storage, census, seed);
    }
}

/// Counts the seed's exchanges by how they ended, from its plan.
fn count(storage: *const Storage, census: *Census, seed: u64) void {
    _ = storage;
    var plan_random = Random.init(seed);
    const plan = content_coding_plan.draw(&plan_random);
    for (plan.exchanges[0..plan.requests_count]) |*planned| {
        const expected = content_coding_plan.expect(&plan, planned);
        if (expected.too_large) census.too_large += 1 else if (expected.decoded) census.decoded += 1 else if (expected.coded != null) census.passed_on += 1;
    }
}

/// Checks every exchange of the run against decision 101, and writes the run's trace.
fn verify(storage: *Storage, plan: *const Plan, seed: u64) Violation!void {
    storage.trace_len = 0;
    try line(storage, "{s} seed=0x{x} protocol={t}\n", .{ check_name, seed, plan.protocol });
    for (plan.exchanges[0..plan.requests_count], 0..) |*planned, index| {
        const expected = content_coding_plan.expect(plan, planned);
        const arrived = try verify_exchange(storage, planned, expected, index);
        const outcome = storage.run.responses[index].result;
        const coding: []const u8 = if (expected.coded) |coded| coded.name() else "-";
        try line(storage, "exchange={d} outcome={t} status={d} coding={s} decoded={} len={d} crc32=0x{x:0>8}\n", .{
            index,
            outcome,
            planned.status,
            coding,
            expected.decoded,
            arrived.len,
            std.hash.Crc32.hash(arrived),
        });
    }
    const run = &storage.run;
    if (run.encoders.free_count() != limits.requests_max) return error.PoolLeaked;
    if (run.decoders.storage().free_count() != limits.requests_max) return error.PoolLeaked;
}

/// Checks one exchange, and returns the content it delivered: decoded, or as it arrived.
fn verify_exchange(storage: *Storage, planned: *const content_coding_plan.Exchange, expected: content_coding_plan.Expected, index: usize) Violation![]const u8 {
    const response = &storage.run.responses[index];
    if (expected.too_large) {
        if (response.result != .too_large) return error.ExchangeDiffers;
        return &.{};
    }
    if (response.result != .response or response.status != planned.status) return error.ExchangeDiffers;
    const content: []const u8 = if (planned.head) &.{} else storage.run.contents[index][0..planned.content_len];
    const reported: ?Coding = if (expected.decoded) expected.coded else null;
    if (response.coding != reported) return error.ExchangeDiffers;
    const received = response.body_received();
    // Decision 101: the client passes on a coding it did not offer, which the check decodes.
    const arrived = if (expected.coded != null and !expected.decoded) try decode(storage, expected.coded.?, received) else received;
    if (!std.mem.eql(u8, arrived, content)) return error.ExchangeDiffers;
    return arrived;
}

fn decode(storage: *Storage, coding: Coding, coded: []const u8) Violation![]const u8 {
    const whole = switch (coding) {
        .gzip => blk: {
            gzip.init(&storage.gzip_decoder, .none());
            break :blk gzip.decode_all(&storage.gzip_decoder, coded, &storage.decoded) catch return error.ExchangeDiffers;
        },
        .deflate => blk: {
            zlib.init(&storage.zlib_decoder, .none());
            break :blk zlib.decode_all(&storage.zlib_decoder, coded, &storage.decoded) catch return error.ExchangeDiffers;
        },
        // The plan draws the codings both modules code: the server encodes no other.
        .zstd, .br => unreachable,
    };
    return storage.decoded[0..whole.written];
}

fn line(storage: *Storage, comptime format: []const u8, arguments: anytype) Violation!void {
    const written = std.fmt.bufPrint(storage.trace[storage.trace_len..], format, arguments) catch return error.TraceFull;
    storage.trace_len += written.len;
}

var check_storage: Storage align(@alignOf(Storage)) = undefined;

test "decision 101: every seed's exchanges end as its rules say, and the census is pinned" {
    var census: Census = .{};
    var failed_seed: ?u64 = null;
    run_check(&check_storage, limits.check_seeds_default, &census, &failed_seed) catch |failure| {
        std.debug.print("content-coding: seed 0x{x} failed: {t}\n", .{ failed_seed.?, failure });
        return failure;
    };
    try std.testing.expect(census.decoded > 0 and census.passed_on > 0 and census.too_large > 0);
    try std.testing.expectEqual(census_crc32_expected, census.crc32.final());
    try std.testing.expectEqual(census_wire_crc32_expected, census.wire_crc32.final());
}
