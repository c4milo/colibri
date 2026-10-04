//! The h11 coding check (design §8 step 15c): a seed's messages coded with `gzip` or `deflate`
//! (`h11_coding_plan.zig`), read by a colibri server or client that has a decoder pool, delivered
//! in seeded pieces, with a seeded amount of room for decoding on each call (decision 98).
//!
//! No colibri writer codes a body (decision 91), so this check cannot be step 15b's exchange
//! between two colibri connections: the plan writes the coded side itself, and a colibri
//! connection reads it.
//!
//! Each seed runs three times: in pieces, in the same pieces again, and in one piece with the most
//! room. The trace records what the connection decoded, message by message, and the refusal a
//! planted defect meets. So:
//!   1. the two runs in pieces must write the same trace and draw the same values (invariant 5);
//!   2. their trace must be the one-piece run's: neither a split nor the room changes what decodes;
//!   3. every body must decode to the plan's octets, a defect must meet the refusal decision 91
//!      gives it after every message before it read whole, and the decoder must be back in the pool
//!      when the run ends.
//!
//! The census hashes the traces of the first runs of seeds `[0, check_seeds_default)` with
//! CRC-32, and the test requires the digest committed below, in Debug and in ReleaseSafe alike.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const h11 = @import("h11");
const sim = @import("sim");
const h11_coding_plan = @import("h11_coding_plan.zig");

const Writer = core.Writer;
const Random = sim.Random;
const Trace = sim.Trace;
const constants = sim.constants;
const limits = constants.h11_coding;
const Plan = h11_coding_plan.Plan;
const Defect = h11_coding_plan.Defect;
const Connection = h11.Connection;
const coding = h11.coding;
const Field = h11.http.Field;

/// The name every h11 coding-check trace carries on its first line.
pub const check_name = "h11-coding";

/// The CRC-32 of the first runs' traces of seeds `[0, check_seeds_default)`, concatenated in seed
/// order. A change to the plan, the connection's results or the trace format changes it, and is
/// committed with the new value after the check passes in both build modes.
pub const census_crc32_expected: u32 = 0x4b48322b;

pub const Violation = sim.trace.Error || error{
    /// Two runs in the same pieces wrote different traces or drew a different number of values.
    ReplayDiverged,
    /// A run in pieces read something other than the run in one piece read.
    SplitChangedResult,
    /// A body decoded to octets other than the plan's.
    BodyDiffers,
    /// The run ended other than the plan says it must.
    OutcomeUnexpected,
};

/// Octets of the scratch buffer the client's requests and the server's responses are written
/// into, which nothing reads: a request head, or a 204 head.
const scratch_len = 256;

/// Passes of a read per octet held: one that consumes it, one that ends its message, and those a
/// message's decoding takes past its last octet, one for each octet of room it fills.
const passes_per_octet = passes_per_octet_framing + limits.body_len_max;
const passes_per_octet_framing = 2;

/// Steps of a run: each delivers a piece, and one more finds nothing to deliver.
const steps_max = limits.stream_len_max + 1;

/// The field every request the client writes carries (RFC 9110 §7.2).
const host: []const Field = &.{.{ .name = "Host", .value = "a.example" }};

/// The storage one seed runs in, outside any stack frame (decision 35).
pub const Storage = struct {
    plan: Plan,
    encoders: h11_coding_plan.Encoders,
    stream: [limits.stream_len_max]u8,
    stream_len: usize,
    connection: Connection,
    pool: coding.Pool(1),
    holder: coding.Decoding,
    decoded: [limits.room_max]u8,
    scratch: [scratch_len]u8,
    seen: [limits.messages_max]Seen,
    pieces: [limits.trace_len_max]u8,
    replayed: [limits.trace_len_max]u8,
    one_piece: [limits.trace_len_max]u8,
};

/// What the connection decoded of one message's body.
const Seen = struct {
    len: u32 = 0,
    crc32: std.hash.Crc32 = .init(),

    fn add(seen: *Seen, data: []const u8) void {
        seen.crc32.update(data);
        seen.len += @intCast(data.len);
    }
};

pub const SeedResult = struct {
    /// Messages read whole.
    whole: u32,
    /// Whether a defect was refused.
    refused: bool,
    /// Pieces delivered, and calls to `receive`, in the first run.
    pieces: u64,
    calls: u64,
    /// The trace, inside the storage the seed ran in.
    trace: []const u8,
};

pub fn run_seed(storage: *Storage, seed: u64) Violation!SeedResult {
    var random = Random.init(seed);
    storage.plan.draw(&random);
    var stream = Writer.init(&storage.stream);
    h11_coding_plan.write_stream(&storage.plan, &random, &storage.encoders, &stream) catch return error.OutcomeUnexpected;
    storage.stream_len = stream.written().len;
    var pieces_random = random;
    var replayed_random = random;
    const pieces = try run_once(storage, seed, &pieces_random, &storage.pieces);
    const replayed = try run_once(storage, seed, &replayed_random, &storage.replayed);
    const one_piece = try run_once(storage, seed, null, &storage.one_piece);
    if (!std.mem.eql(u8, pieces.trace, replayed.trace)) return error.ReplayDiverged;
    if (pieces_random.draws != replayed_random.draws) return error.ReplayDiverged;
    if (!std.mem.eql(u8, pieces.trace, one_piece.trace)) return error.SplitChangedResult;
    return pieces;
}

/// One run: the stream in pieces drawn from `random`, or whole with the most room when it is null.
fn run_once(storage: *Storage, seed: u64, random: ?*Random, buffer: []u8) Violation!SeedResult {
    try start(storage);
    var run: Run = .{ .storage = storage, .random = random };
    // Every step delivers a piece, or is the last.
    for (0..steps_max) |_| {
        const more = run.deliver();
        if (!try run.read_held()) break;
        if (!more) break;
    } else return error.OutcomeUnexpected;
    try check_outcome(storage, &run);
    var output = Writer.init(buffer);
    var trace = try Trace.begin(&output, check_name, seed);
    try write_trace(storage, &run, &trace);
    try trace.end("pass");
    return .{ .whole = run.whole, .refused = run.refused, .pieces = run.pieces, .calls = run.calls, .trace = output.written() };
}

/// The pool and the connection as a run starts, and the requests a client has outstanding.
fn start(storage: *Storage) Violation!void {
    const pool = storage.pool.storage();
    pool.reset(coding.Features.none());
    storage.holder = .{};
    // RFC 9110 §15.6.4: the exhausted defect finds the pool's one decoder taken.
    if (storage.plan.defect == .exhausted) coding.start(&storage.holder, pool, .gzip) catch unreachable;
    storage.seen = @splat(.{});
    switch (storage.plan.role) {
        .server => storage.connection.init(.server, .{ .decoders = pool }),
        .client => {
            storage.connection.init(.client, .{ .decoders = pool });
            for (0..storage.plan.count) |_| {
                _ = storage.connection.write_request(&storage.scratch, "GET", "/m", host) catch return error.OutcomeUnexpected;
            }
        },
    }
}

const Run = struct {
    storage: *Storage,
    random: ?*Random,
    delivered: usize = 0,
    consumed: usize = 0,
    /// Heads read: the message being read is the last of them.
    heads: u32 = 0,
    whole: u32 = 0,
    refused: bool = false,
    pieces: u64 = 0,
    calls: u64 = 0,

    /// Delivers the next piece. Returns whether any octet was left to deliver.
    fn deliver(run: *Run) bool {
        const left = run.storage.stream_len - run.delivered;
        if (left == 0) return false;
        const piece = if (run.random) |random| random.between(1, @min(constants.chunk_len_max, left)) else left;
        run.delivered += @intCast(piece);
        run.pieces += 1;
        return true;
    }

    /// Reads what is held until the connection needs more octets. Returns false when it refused.
    fn read_held(run: *Run) Violation!bool {
        const passes = passes_per_octet * (run.delivered - run.consumed) + 1;
        for (0..passes) |_| {
            const room: usize = if (run.random) |random| @intCast(random.between(1, limits.room_max)) else limits.room_max;
            const held = run.storage.stream[run.consumed..run.delivered];
            run.calls += 1;
            const received = run.storage.connection.receive(held, run.storage.decoded[0..room]) catch {
                run.refused = true;
                return false;
            };
            run.consumed += received.consumed;
            const event = received.event orelse {
                if (received.consumed == 0) return true;
                continue;
            };
            try run.on_event(event);
        }
        return error.OutcomeUnexpected;
    }

    fn on_event(run: *Run, event: h11.connection.Event) Violation!void {
        switch (event) {
            .request, .response => run.heads += 1,
            .data => |data| {
                if (run.heads == 0) return error.OutcomeUnexpected;
                run.storage.seen[run.heads - 1].add(data);
            },
            .end => {
                run.whole += 1;
                // Decision 92: the server reads the next request once this one's is answered.
                if (run.storage.plan.role == .server) try run.answer();
            },
            .interim, .tunnel => return error.OutcomeUnexpected,
        }
    }

    fn answer(run: *Run) Violation!void {
        const no_content = @intFromEnum(h11.http.status.Code.no_content);
        _ = run.storage.connection.write_response(&run.storage.scratch, no_content, "No Content", &.{}) catch {
            return error.OutcomeUnexpected;
        };
    }
};

/// Requires the run to end as the plan says, with every body the plan's and the decoder back.
fn check_outcome(storage: *Storage, run: *const Run) Violation!void {
    const plan = &storage.plan;
    if (run.whole != plan.whole_expected()) return error.OutcomeUnexpected;
    if (run.refused != (plan.defect != .none)) return error.OutcomeUnexpected;
    if (run.refused) try check_refusal(storage);
    for (storage.seen[0..run.whole], plan.messages[0..run.whole], 0..) |seen, message, index| {
        const body = plan.bodies[index][0..message.body_len];
        if (seen.len != body.len or seen.crc32.final() != std.hash.Crc32.hash(body)) return error.BodyDiffers;
    }
    const pool = storage.pool.storage();
    coding.release(&storage.holder, pool);
    // Every run gives its decoder back: the pool's one decoder can be taken again.
    if (storage.connection.decoding.active()) return error.OutcomeUnexpected;
    var probe: coding.Decoding = .{};
    coding.start(&probe, pool, .gzip) catch return error.OutcomeUnexpected;
    coding.release(&probe, pool);
}

/// A server owes the status decision 91 gives the defect, and a client failed on it.
fn check_refusal(storage: *const Storage) Violation!void {
    switch (storage.plan.role) {
        .server => if (storage.connection.reply_status != storage.plan.expected_status()) return error.OutcomeUnexpected,
        .client => {
            const failure = storage.connection.failure orelse return error.OutcomeUnexpected;
            if (failure != storage.plan.expected_failure()) return error.OutcomeUnexpected;
        },
    }
}

fn write_trace(storage: *const Storage, run: *const Run, trace: *Trace) Violation!void {
    for (storage.seen[0..run.whole], storage.plan.messages[0..run.whole]) |seen, message| {
        var line = try trace.record("message");
        try line.word("coding", @tagName(message.coding));
        try line.number("len", seen.len);
        try line.number("crc32", seen.crc32.final());
        try trace.write(&line);
    }
    if (!run.refused) return;
    var line = try trace.record("refused");
    try line.word("defect", @tagName(storage.plan.defect));
    try trace.write(&line);
}

/// What a range of seeds did.
pub const Census = struct {
    seeds: u64 = 0,
    messages: u64 = 0,
    refused: u64 = 0,
    /// Seeds whose defect was each kind, `none` first.
    defects: [std.meta.fields(Defect).len]u64 = @splat(0),
    two_members: u64 = 0,
    stream_octets: u64 = 0,
    pieces: u64 = 0,
    calls: u64 = 0,
    trace_octets: u64 = 0,
    crc32: std.hash.Crc32 = .init(),

    fn count(census: *Census, storage: *const Storage, result: SeedResult) void {
        census.seeds += 1;
        census.messages += result.whole;
        if (result.refused) census.refused += 1;
        census.defects[@intFromEnum(storage.plan.defect)] += 1;
        for (storage.plan.messages[0..storage.plan.count]) |message| {
            if (message.two_members) census.two_members += 1;
        }
        census.stream_octets += storage.stream_len;
        census.pieces += result.pieces;
        census.calls += result.calls;
        census.trace_octets += result.trace.len;
        census.crc32.update(result.trace);
    }
};

/// Runs seeds `[0, seeds)` in order. On a violation, `failed_seed` names the seed.
pub fn run_check(storage: *Storage, seeds: u64, census: *Census, failed_seed: *?u64) Violation!void {
    for (0..seeds) |seed| {
        failed_seed.* = seed;
        census.count(storage, try run_seed(storage, seed));
    }
    failed_seed.* = null;
    assert(census.seeds == seeds);
}

const testing = std.testing;

/// The storage the check test runs in, placed outside any stack frame.
var test_storage: Storage align(@alignOf(Storage)) = undefined;

test "h11 coding check: seeds replay, no split or room changes a body, and traces hash as committed" {
    var census: Census = .{};
    var failed_seed: ?u64 = null;
    run_check(&test_storage, constants.check_seeds_default, &census, &failed_seed) catch |failure| {
        std.debug.print("h11 coding check: seed 0x{x} failed: {t}\n", .{ failed_seed.?, failure });
        return failure;
    };
    // Every defect is planted in some seed, and so is a gzip body of two members.
    for (census.defects) |seeds| try testing.expect(seeds > 0);
    try testing.expect(census.two_members > 0);
    try testing.expect(census.calls > census.pieces);
    try testing.expectEqual(census_crc32_expected, census.crc32.final());
}
