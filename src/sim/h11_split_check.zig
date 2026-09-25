//! The h11 split check (design §8 step 15a): a seed's pipelined HTTP/1.1 stream (`h11_plan.zig`)
//! read by h11's parsers, the way a server reads requests or a client reads responses, after
//! arriving in seeded chunks.
//!
//! Each seed runs three times: in chunks, in the same chunks again, and in one piece. The trace
//! records what the reading found and nothing about where a chunk ended: a `head` record per head,
//! a `body` record with each body's length, CRC-32 and trailer count, and a `reject` record. So:
//!   1. the two chunked runs must write the same trace and draw the same values (invariant 5);
//!   2. the chunked run's trace must be the one-piece run's, which is the check that no split
//!      changes what a parser reads;
//!   3. every body must be the octets the plan wrote, and the run must end as the plan says: every
//!      message read, or the planted defect refused with its error after the messages before it.
//!
//! The census hashes the chunked traces of seeds `[0, check_seeds_default)` with CRC-32, and the
//! test requires the digest committed below, in Debug and in ReleaseSafe alike.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const h11 = @import("h11");
const http = h11.http;
const sim = @import("sim");
const h11_plan = @import("h11_plan.zig");

const Writer = core.Writer;
const Random = sim.Random;
const Trace = sim.Trace;
const constants = sim.constants;
const Plan = h11_plan.Plan;

/// The name every h11 split-check trace carries on its first line.
pub const check_name = "h11-split";

/// The CRC-32 of the chunked traces of seeds `[0, check_seeds_default)`, concatenated in seed
/// order. A change to the plan, the parsers' results or the trace format changes it, and is
/// committed with the new value after the check passes in both build modes.
pub const census_crc32_expected: u32 = 0x793d2f38;

pub const Violation = error{
    /// Two chunked runs of the seed wrote different traces or drew a different number of values.
    ReplayDiverged,
    /// The chunked run read something other than what the run in one piece read.
    SplitChangedResult,
    /// A body read differs from the one the plan wrote.
    BodyDiffers,
    /// The run ended other than the plan says it must.
    OutcomeUnexpected,
};

/// The storage one seed runs in, outside any stack frame (decision 35).
pub const Storage = struct {
    plan: Plan,
    chunked: [constants.h11_split_trace_len_max]u8,
    replayed: [constants.h11_split_trace_len_max]u8,
    one_piece: [constants.h11_split_trace_len_max]u8,
    section: http.FieldSection,
    trailers: http.FieldSection,
};

/// How a run ended.
pub const Outcome = enum { pass, rejected };

pub const SeedResult = struct {
    outcome: Outcome,
    /// Messages read whole.
    messages: u32,
    /// Chunks fed.
    chunks: u64,
    /// The trace, inside the storage the seed ran in.
    trace: []const u8,
};

pub fn run_seed(storage: *Storage, seed: u64) (Violation || sim.trace.Error)!SeedResult {
    var random = Random.init(seed);
    storage.plan.draw(&random);
    var chunked_random = random;
    var replayed_random = random;
    const chunked = try run_once(storage, seed, &chunked_random, &storage.chunked);
    const replayed = try run_once(storage, seed, &replayed_random, &storage.replayed);
    const one_piece = try run_once(storage, seed, null, &storage.one_piece);
    if (!std.mem.eql(u8, chunked.trace, replayed.trace)) return error.ReplayDiverged;
    if (chunked_random.draws != replayed_random.draws) return error.ReplayDiverged;
    if (!std.mem.eql(u8, chunked.trace, one_piece.trace)) return error.SplitChangedResult;
    const plan = &storage.plan;
    const expected: Outcome = if (plan.defect == .none) .pass else .rejected;
    const expected_messages = if (plan.defect == .none) plan.count else plan.defect_index;
    if (chunked.outcome != expected or chunked.messages != expected_messages) return error.OutcomeUnexpected;
    return chunked;
}

/// Feeds the plan's stream in chunks drawn from `random`, or in one piece when it is null.
fn run_once(storage: *Storage, seed: u64, random: ?*Random, buffer: []u8) (Violation || sim.trace.Error)!SeedResult {
    var output = Writer.init(buffer);
    var trace = try Trace.begin(&output, check_name, seed);
    var reading: Reading = .{ .storage = storage, .trace = &trace };
    const stream = storage.plan.written();
    var fed: usize = 0;
    var chunks: u64 = 0;
    // Every chunk carries at least one octet, so a stream of n octets takes at most n chunks.
    for (0..stream.len) |_| {
        if (fed == stream.len or reading.refused) break;
        const remaining = stream.len - fed;
        fed += if (random) |seeded| seeded.between(1, @min(constants.chunk_len_max, remaining)) else remaining;
        chunks += 1;
        try reading.drain(stream[reading.consumed..fed]);
    }
    const outcome: Outcome = if (reading.refused) .rejected else .pass;
    if (outcome == .pass and reading.consumed != stream.len) return error.OutcomeUnexpected;
    try trace.end(@tagName(outcome));
    return .{ .outcome = outcome, .messages = reading.index, .chunks = chunks, .trace = output.written() };
}

/// Where the reading of the stream stands.
const Reading = struct {
    storage: *Storage,
    trace: *Trace,
    /// Octets of the stream consumed.
    consumed: usize = 0,
    /// The message being read.
    index: u32 = 0,
    state: State = .head,
    scanner: h11.message.Scanner = .{},
    decoder: h11.chunked.Decoder = .{},
    /// Body octets still to come of a fixed body, and what the body held so far.
    remaining: u64 = 0,
    body_len: u32 = 0,
    body_crc32: std.hash.Crc32 = .init(),
    refused: bool = false,

    const State = enum { head, fixed, chunked };

    /// Passes of `drain` per octet held: one that consumes it, and one that ends its message.
    const passes_per_octet = 2;

    /// Reads what `held` holds until it needs more octets, every message is read, or it refuses.
    fn drain(reading: *Reading, held: []const u8) (Violation || sim.trace.Error)!void {
        var rest = held;
        // Every pass consumes an octet or ends a message, and a message takes at least one octet,
        // so n octets take at most 2n passes, and one more finds them short.
        for (0..passes_per_octet * held.len + 1) |_| {
            if (reading.index == reading.storage.plan.count) return;
            const used = reading.step(rest) catch |failure| return reading.refuse(failure);
            const taken = used orelse return;
            reading.consumed += taken;
            rest = rest[taken..];
        }
        unreachable;
    }

    /// One step: the octets it consumed, or null when it needs more.
    fn step(reading: *Reading, held: []const u8) anyerror!?usize {
        return switch (reading.state) {
            .head => reading.read_head(held),
            .fixed => reading.read_fixed(held),
            .chunked => reading.read_chunked(held),
        };
    }

    fn read_head(reading: *Reading, held: []const u8) anyerror!?usize {
        const storage = reading.storage;
        const role = storage.plan.role;
        const head_len, const body = switch (role) {
            .request => blk: {
                const request = try h11.message.read_request(&reading.scanner, held, &storage.section) orelse return null;
                break :blk .{ request.head_len, request.body };
            },
            .response => blk: {
                const response = try h11.message.read_response(&reading.scanner, .other, held, &storage.section) orelse return null;
                break :blk .{ response.head_len, response.body };
            },
        };
        var line = try reading.trace.record("head");
        try line.number("index", reading.index);
        try line.number("fields", storage.section.len());
        try line.word("body", @tagName(body.length));
        try reading.trace.write(&line);
        reading.body_len = 0;
        reading.body_crc32 = .init();
        switch (body.length) {
            .none => try reading.end_message(0),
            .fixed => |octets| {
                reading.remaining = octets;
                reading.state = .fixed;
                if (octets == 0) try reading.end_message(0);
            },
            .chunked => {
                reading.decoder = .{};
                reading.state = .chunked;
            },
            .close_delimited, .tunnel => unreachable,
        }
        return head_len;
    }

    fn read_fixed(reading: *Reading, held: []const u8) anyerror!?usize {
        if (held.len == 0) return null;
        const taken: usize = @intCast(@min(reading.remaining, held.len));
        reading.body_crc32.update(held[0..taken]);
        reading.body_len += @intCast(taken);
        reading.remaining -= taken;
        if (reading.remaining == 0) try reading.end_message(0);
        return taken;
    }

    fn read_chunked(reading: *Reading, held: []const u8) anyerror!?usize {
        const storage = reading.storage;
        const decoded = try reading.decoder.decode(storage.plan.role, held, &storage.trailers);
        reading.body_crc32.update(decoded.data);
        reading.body_len += @intCast(decoded.data.len);
        if (decoded.done) try reading.end_message(storage.trailers.len());
        if (decoded.consumed == 0 and !decoded.done) return null;
        return decoded.consumed;
    }

    /// A message read whole: its body must be the plan's.
    fn end_message(reading: *Reading, trailers: u32) (Violation || sim.trace.Error)!void {
        const planned = reading.storage.plan.messages[reading.index];
        const crc32 = reading.body_crc32.final();
        if (reading.body_len != planned.body_len or crc32 != planned.body_crc32) return error.BodyDiffers;
        if (trailers != planned.trailers) return error.BodyDiffers;
        var line = try reading.trace.record("body");
        try line.number("index", reading.index);
        try line.number("len", reading.body_len);
        try line.number("crc32", crc32);
        try line.number("trailers", trailers);
        try reading.trace.write(&line);
        reading.index += 1;
        reading.state = .head;
    }

    /// The reading refused a message: it must be the planted defect's, with its error.
    fn refuse(reading: *Reading, failure: anyerror) (Violation || sim.trace.Error)!void {
        switch (failure) {
            error.BodyDiffers, error.NoSpaceLeft => return @errorCast(failure),
            else => {},
        }
        const plan = &reading.storage.plan;
        const expected = plan.defect.expected() orelse return error.OutcomeUnexpected;
        if (failure != expected or reading.index != plan.defect_index) return error.OutcomeUnexpected;
        var line = try reading.trace.record("reject");
        try line.number("index", reading.index);
        try line.word("error", @errorName(failure));
        try reading.trace.write(&line);
        reading.refused = true;
    }
};

/// What a range of seeds did.
pub const Census = struct {
    seeds: u64 = 0,
    passed: u64 = 0,
    rejected: u64 = 0,
    messages: u64 = 0,
    chunks: u64 = 0,
    trace_octets: u64 = 0,
    crc32: std.hash.Crc32 = .init(),

    fn count(census: *Census, result: SeedResult) void {
        census.seeds += 1;
        switch (result.outcome) {
            .pass => census.passed += 1,
            .rejected => census.rejected += 1,
        }
        census.messages += result.messages;
        census.chunks += result.chunks;
        census.trace_octets += result.trace.len;
        census.crc32.update(result.trace);
    }
};

/// Runs seeds `[0, seeds)` in order. On a violation, `failed_seed` names the seed.
pub fn run_check(storage: *Storage, seeds: u64, census: *Census, failed_seed: *?u64) (Violation || sim.trace.Error)!void {
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

test "h11 split check: seeds replay, no split changes what is read, and traces hash as committed" {
    var census: Census = .{};
    var failed_seed: ?u64 = null;
    run_check(&test_storage, constants.check_seeds_default, &census, &failed_seed) catch |failure| {
        std.debug.print("h11 split check: seed 0x{x} failed: {t}\n", .{ failed_seed.?, failure });
        return failure;
    };
    try testing.expect(census.passed > 0 and census.rejected > 0);
    try testing.expect(census.chunks > census.seeds);
    try testing.expectEqual(census_crc32_expected, census.crc32.final());
}
