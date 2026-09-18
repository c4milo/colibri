//! The check of design §8 step 2: the step 1 decoders driven through the byte pipe at seeded chunk
//! boundaries, over a range of seeds.
//!
//! Each seed draws a plan and its stream (`chunk_stream.zig`), then runs it three times:
//!
//! 1. chunked, on a copy of the generator as it stood after the stream was drawn;
//! 2. chunked again, on a second copy, which must write the same trace byte for byte and draw the
//!    same number of values (invariant 6);
//! 3. in one piece, whose accept and reject records must be the chunked run's (design §6.6).
//!
//! The run must end `pass` when the plan has no refusal and `rejected` when it has one.
//!
//! Across hosts and build modes the check compares by digest: the census hashes every chunked trace
//! of seeds `[0, check_seeds_default)` with CRC-32, and the test requires the digest committed
//! below. Debug and ReleaseSafe, macOS and Linux, all must compute that one number.
//!
//! Say plainly what this shows. At step 2 the subject is the step 1 decoders, which consume a
//! whole value or nothing, so nothing but the harness can make two runs differ: the check shows the
//! harness is self-consistent and that the decoders' verdicts do not depend on where a chunk ends.
//! The same check over a connection at step 4 is the first point at which it can fail for any other
//! reason.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const sim = @import("sim");
const chunk_stream = @import("chunk_stream.zig");

const Writer = core.Writer;
const Random = sim.Random;
const Clock = sim.Clock;
const Trace = sim.Trace;
const constants = sim.constants;

/// The name every chunk-check trace carries on its first line.
pub const check_name = "chunk";

/// The CRC-32 of the chunked traces of seeds `[0, check_seeds_default)`, concatenated in seed
/// order. A change to the harness, the stream a seed draws or the trace format changes it, and is
/// committed with the new value after the check passes on both build modes.
pub const census_crc32_expected: u32 = 0x11c9c07a;

/// The storage one seed runs in: the stream, and the three traces with the two chunk-independent
/// copies compared. The caller places it; it is too large for a stack.
pub const Storage = struct {
    stream: [constants.chunk_check_stream_len_max]u8,
    chunked: [constants.chunk_check_trace_len_max]u8,
    replayed: [constants.chunk_check_trace_len_max]u8,
    one_piece: [constants.chunk_check_trace_len_max]u8,
    chunked_independent: [constants.chunk_check_trace_len_max]u8,
    one_piece_independent: [constants.chunk_check_trace_len_max]u8,

    pub const zeroed: Storage = .{
        .stream = @splat(0),
        .chunked = @splat(0),
        .replayed = @splat(0),
        .one_piece = @splat(0),
        .chunked_independent = @splat(0),
        .one_piece_independent = @splat(0),
    };
};

/// How one seed failed the check.
pub const Violation = error{
    /// Two chunked runs of the seed wrote different traces or drew a different number of values.
    ReplayDiverged,
    /// The chunked run's accept and reject records differ from the run in one piece.
    ChunkingChangedVerdict,
    /// The run ended other than the plan says it must.
    OutcomeUnexpected,
};

/// One seed's run, as `zig build sim -- --chunk-seed` prints it.
pub const SeedResult = struct {
    outcome: sim.pipe.Outcome,
    /// The chunked trace, inside the storage the seed ran in.
    trace: []const u8,
};

pub fn run_seed(storage: *Storage, seed: u64) (Violation || sim.trace.Error)!SeedResult {
    var random = Random.init(seed);
    const plan = chunk_stream.Plan.draw(&random);
    var stream_writer = Writer.init(&storage.stream);
    try plan.write(&stream_writer);
    const stream = stream_writer.written();

    var chunked_random = random;
    var replayed_random = random;
    const run: Run = .{ .plan = &plan, .stream = stream, .seed = seed };
    const chunked = try run.once(.{ .seeded = &chunked_random }, &storage.chunked);
    const replayed = try run.once(.{ .seeded = &replayed_random }, &storage.replayed);
    const one_piece = try run.once(.one_piece, &storage.one_piece);

    // The stream holds at least one value, so the run in one piece feeds exactly once. That is
    // the harness's own contract, and the comparison below is vacuous without it.
    assert(sim.trace.count_records(one_piece.trace, sim.trace.feed_record) == 1);
    if (!std.mem.eql(u8, chunked.trace, replayed.trace)) return error.ReplayDiverged;
    if (chunked_random.draws != replayed_random.draws) return error.ReplayDiverged;
    var chunked_independent = Writer.init(&storage.chunked_independent);
    var one_piece_independent = Writer.init(&storage.one_piece_independent);
    try sim.trace.write_chunk_independent(chunked.trace, &chunked_independent);
    try sim.trace.write_chunk_independent(one_piece.trace, &one_piece_independent);
    const independent = chunked_independent.written();
    if (!std.mem.eql(u8, independent, one_piece_independent.written())) {
        return error.ChunkingChangedVerdict;
    }
    const expected: sim.pipe.Outcome = if (plan.refusal == null) .pass else .rejected;
    if (chunked.outcome != expected) return error.OutcomeUnexpected;
    return chunked;
}

/// One seed's plan and stream, which each of its three runs feeds.
const Run = struct {
    plan: *const chunk_stream.Plan,
    stream: []const u8,
    seed: u64,

    fn once(run: *const Run, schedule: sim.pipe.Schedule, buffer: []u8) sim.trace.Error!SeedResult {
        var output = Writer.init(buffer);
        var trace = try Trace.begin(&output, check_name, run.seed);
        var subject: chunk_stream.Subject = .{ .plan = run.plan };
        var clock = Clock.init();
        const Subject = chunk_stream.Subject;
        const outcome = try sim.pipe.run(Subject, &subject, run.stream, schedule, &clock, &trace);
        return .{ .outcome = outcome, .trace = output.written() };
    }
};

/// What a range of seeds did.
pub const Census = struct {
    seeds: u64 = 0,
    passed: u64 = 0,
    rejected: u64 = 0,
    trace_octets: u64 = 0,
    /// Chunks fed across every chunked run: more than one per seed, or the schedule chunked nothing.
    chunks: u64 = 0,
    crc32: std.hash.Crc32 = .init(),

    fn count(census: *Census, result: SeedResult) void {
        census.seeds += 1;
        switch (result.outcome) {
            .pass => census.passed += 1,
            .rejected => census.rejected += 1,
            .truncated => unreachable,
        }
        census.trace_octets += result.trace.len;
        census.chunks += sim.trace.count_records(result.trace, sim.trace.feed_record);
        census.crc32.update(result.trace);
    }
};

/// Runs seeds `[0, seeds)` in order. On a violation, `failed_seed` names the seed.
pub fn run_check(
    storage: *Storage,
    seeds: u64,
    census: *Census,
    failed_seed: *?u64,
) (Violation || sim.trace.Error)!void {
    for (0..seeds) |seed| {
        failed_seed.* = seed;
        census.count(try run_seed(storage, seed));
    }
    failed_seed.* = null;
    assert(census.seeds == seeds);
}

const testing = std.testing;

/// The storage the check test runs in, placed outside any stack frame.
var test_storage: Storage = .zeroed;

test "chunk check: seeds replay, chunking changes no verdict, and traces hash as committed" {
    var census: Census = .{};
    var failed_seed: ?u64 = null;
    run_check(&test_storage, constants.check_seeds_default, &census, &failed_seed) catch |failure| {
        std.debug.print("chunk check: seed 0x{x} failed: {t}\n", .{ failed_seed.?, failure });
        return failure;
    };
    try testing.expect(census.passed > 0);
    try testing.expect(census.rejected > 0);
    try testing.expect(census.chunks > census.seeds);
    try testing.expectEqual(census_crc32_expected, census.crc32.final());
}
