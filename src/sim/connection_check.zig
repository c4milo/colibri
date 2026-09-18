//! The check of design §8 step 4: one h2 connection driven through the byte pipe at seeded chunk
//! boundaries, over a range of seeds, with invariants 13 to 16 read after every frame it accepts.
//!
//! `Subject` is the connection under the pipe's contract. `step` writes what the connection owes,
//! hands it the octets the caller holds and reports what it consumed; `check` then reads the four
//! invariants off it. A broken one is a `Violation`, which ends the run and names the seed.
//!
//! Each seed draws a plan and its stream (`connection_stream.zig`), then runs it three times:
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
//! This is the step 2 check over something that can fail for a reason of its own. At step 2 the
//! subject consumed a whole value or nothing and nothing but the harness could differ; here the
//! subject holds state across frames, so a divergence between two runs, or between a chunked run
//! and one in one piece, is the connection's.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const h2 = @import("h2");
const sim = @import("sim");
const connection_stream = @import("connection_stream.zig");

const Writer = core.Writer;
const Random = sim.Random;
const Clock = sim.Clock;
const Trace = sim.Trace;
const constants = sim.constants;
const h2_constants = h2.constants;

/// The name every connection-check trace carries on its first line.
pub const check_name = "connection";

/// The CRC-32 of the chunked traces of seeds `[0, check_seeds_default)`, concatenated in seed
/// order. A change to the harness, the stream a seed draws, the trace format or the connection's
/// own behaviour changes it, and is committed with the new value after the check passes on both
/// build modes.
pub const census_crc32_expected: u32 = 0xe8f7c0b4;

/// How a seed failed the check: the harness's three, then one per invariant read off the connection.
pub const Violation = error{
    /// Two chunked runs of the seed wrote different traces or drew a different number of values.
    ReplayDiverged,
    /// The chunked run's accept and reject records differ from the run in one piece.
    ChunkingChangedVerdict,
    /// The run ended other than the plan says it must.
    OutcomeUnexpected,
    /// Invariant 13: a watermark of the stream table's slot pool decreased.
    WatermarkDecreased,
    /// Invariant 13: the highest identifier the peer opened decreased.
    PeerOpenedIdentifierDecreased,
    /// Invariant 14: the octets fed to the field-block slot passed what one HEADERS frame and
    /// `continuation_count_max` CONTINUATION frames carry.
    FieldBlockTooLong,
    /// Invariant 15: a flow-control window left the range of a signed 31-bit quantity.
    WindowOutOfRange,
    /// Invariant 16: the last stream identifier of a GOAWAY colibri sent rose.
    GoawaySentLastIdIncreased,
    /// Invariant 16: the last stream identifier of a GOAWAY the peer sent rose.
    GoawayReceivedLastIdIncreased,
};

/// Invariant 14's bound on the octets one field block feeds the slot: the opening frame and at
/// most `continuation_count_max` CONTINUATION frames, each at most `frame_size_max`.
const field_block_octets_max: u64 =
    (h2_constants.continuation_count_max + 1) * h2_constants.frame_size_max;

/// Drives one connection in the server role with a plan's stream, for `sim.pipe.run`.
pub const Subject = struct {
    connection: h2.Connection,
    /// The instant every call takes, which the pipe advances (design §4.2, non-negotiable 3).
    clock: *Clock,
    /// What the frame last accepted meant, which `describe` writes.
    event: ?h2.Event,
    /// The invariant the connection broke, or null while it has broken none.
    violation: ?Violation,
    /// What invariants 13 and 16 compare the connection's values against, as of the frame before.
    watermark: [h2_constants.stream_id_parity_count]u64,
    highest_peer_opened_id: u32,
    goaway_sent_last_id: ?u32,
    goaway_received_last_id: ?u32,
    /// Where the connection writes the frames it owes. The check reads the connection's state and
    /// not the octets it sends, so the octets are written and dropped.
    output: [constants.connection_check_output_len_max]u8,

    /// Empties the connection and the values the invariants are compared against.
    pub fn init(subject: *Subject, clock: *Clock) void {
        subject.connection.init(.server);
        subject.clock = clock;
        subject.event = null;
        subject.violation = null;
        subject.watermark = @splat(0);
        subject.highest_peer_opened_id = 0;
        subject.goaway_sent_last_id = null;
        subject.goaway_received_last_id = null;
        subject.output = @splat(0);
        assert(!subject.connection.has_failed());
        assert(subject.connection.streams.len() == 0);
    }

    pub fn step(subject: *Subject, held: []const u8) sim.pipe.Step {
        if (subject.waits_for_preface(held)) return .need_more;
        // A caller writes what the connection owes before it reads more (connection.zig): a full
        // reply queue stops the connection reading, and the stream would never end.
        _ = subject.connection.write_pending(&subject.output, subject.clock.now_ns);
        const received = subject.connection.receive(held, subject.clock.now_ns) catch |failure| {
            // RFC 9113 §5.4.1: the connection is over. The four invariants hold over the state the
            // queued GOAWAY left behind as much as over any other, so they are read here too, and
            // this is the one point at which `goaway_sent_last_id` is set (§6.8).
            if (subject.check()) |broken| return subject.refuse(broken);
            return .{ .reject = failure };
        };
        if (received.consumed == 0) return .need_more;
        subject.event = received.event;
        if (subject.check()) |broken| return subject.refuse(broken);
        return .{ .accept = received.consumed };
    }

    /// Records the invariant the connection broke and ends the run with it.
    fn refuse(subject: *Subject, broken: Violation) sim.pipe.Step {
        subject.violation = broken;
        return .{ .reject = broken };
    }

    /// Writes what the frame last accepted meant. A frame that meant nothing to the caller, a PING
    /// the connection answered among them, writes `event=none`. The connection is a server, so
    /// `response` never arrives (RFC 9113 §8.3.2) and neither does `trailers`, which needs a
    /// second field section on a stream the plan never sends one on (§8.1).
    pub fn describe(subject: *const Subject, line: *sim.trace.Record) sim.trace.Error!void {
        const event = subject.event orelse return line.word("event", "none");
        try line.word("event", @tagName(event));
        switch (event) {
            .request => |request| try describe_stream(line, request.stream_id, request.end_stream),
            .response => |response| try describe_stream(line, response.stream_id, response.end_stream),
            .trailers => |trailers| try line.number("stream_id", trailers.stream_id),
            .data => |data| {
                try describe_stream(line, data.stream_id, data.end_stream);
                try line.number("payload_len", data.payload.len);
            },
            .stream_reset => |reset| try describe_reset(line, reset),
            .stream_refused => |reset| try describe_reset(line, reset),
            .goaway => |goaway| {
                try line.number("last_stream_id", goaway.last_stream_id);
                try line.number("error_code", goaway.error_code);
            },
            .ping_acknowledged => |opaque_data| try line.octets("opaque_data", &opaque_data),
            .settings_acknowledged, .settings_applied => {},
        }
    }

    /// Whether the octets held are less than the whole client connection preface, which RFC 9113
    /// §3.4 makes 24 octets and not a frame. The connection reads whatever of it has arrived, so
    /// the subject holds the octets until all of them are there and the run's records say the same
    /// thing however the stream was chunked (design §6.6).
    fn waits_for_preface(subject: *const Subject, held: []const u8) bool {
        if (subject.connection.preface_read_len == h2_constants.client_preface_len) return false;
        return held.len < h2_constants.client_preface_len;
    }

    /// Reads invariants 13 to 16 off the connection, after every frame it read: one it accepted,
    /// or the one that ended it.
    fn check(subject: *Subject) ?Violation {
        if (subject.check_identifiers()) |broken| return broken;
        // Invariant 14: the slot holds one block, whose octets are the opening frame's and those
        // of the CONTINUATION frames the connection lets follow it.
        if (subject.connection.block.octets_fed > field_block_octets_max) return error.FieldBlockTooLong;
        // Invariant 15: the connection's own two windows, then both windows of every stream.
        if (!subject.connection.send_window.in_range()) return error.WindowOutOfRange;
        if (!subject.connection.receive_window.in_range()) return error.WindowOutOfRange;
        if (subject.check_stream_windows()) |broken| return broken;
        return subject.check_goaway();
    }

    /// Invariant 13: neither watermark of the slot pool decreases, and neither does the highest
    /// identifier the peer opened.
    fn check_identifiers(subject: *Subject) ?Violation {
        const pool = &subject.connection.streams.pool;
        for (&subject.watermark, 0..) |*seen, class| {
            const reached = pool.watermark[class] orelse 0;
            if (reached < seen.*) return error.WatermarkDecreased;
            seen.* = reached;
        }
        const opened = subject.connection.streams.highest_peer_opened_id;
        if (opened < subject.highest_peer_opened_id) return error.PeerOpenedIdentifierDecreased;
        subject.highest_peer_opened_id = opened;
        return null;
    }

    /// Invariant 15: both windows of every record the stream table holds stay in range.
    fn check_stream_windows(subject: *Subject) ?Violation {
        var records = subject.connection.streams.iterator();
        while (records.next()) |record| {
            if (!record.send_window.in_range()) return error.WindowOutOfRange;
            if (!record.receive.in_range()) return error.WindowOutOfRange;
        }
        return null;
    }

    /// Invariant 16: the last stream identifier of each endpoint's GOAWAY never rises.
    fn check_goaway(subject: *Subject) ?Violation {
        const streams = &subject.connection.streams;
        if (rises(subject.goaway_sent_last_id, streams.goaway_sent_last_id)) {
            return error.GoawaySentLastIdIncreased;
        }
        if (rises(subject.goaway_received_last_id, streams.goaway_received_last_id)) {
            return error.GoawayReceivedLastIdIncreased;
        }
        subject.goaway_sent_last_id = streams.goaway_sent_last_id;
        subject.goaway_received_last_id = streams.goaway_received_last_id;
        return null;
    }
};

fn describe_stream(line: *sim.trace.Record, stream_id: u32, end_stream: bool) sim.trace.Error!void {
    try line.number("stream_id", stream_id);
    try line.number("end_stream", @intFromBool(end_stream));
}

fn describe_reset(line: *sim.trace.Record, reset: h2.connection.StreamReset) sim.trace.Error!void {
    try line.number("stream_id", reset.stream_id);
    try line.number("error_code", reset.error_code);
}

/// Whether the identifier a GOAWAY named rose. Null is "no GOAWAY yet", and RFC 9113 §6.8 lets the
/// first one name any identifier.
fn rises(seen: ?u32, reached: ?u32) bool {
    const previous = seen orelse return false;
    return (reached orelse return false) > previous;
}

/// The octets the connection may owe at once: its own SETTINGS frame, the acknowledgments its
/// queues hold, the connection window update, every stream reply and the GOAWAY
/// (`connection_reply.zig`).
const output_len_needed: u32 = h2_constants.frame_header_len +
    h2_constants.settings_count * h2_constants.setting_len +
    h2_constants.settings_ack_pending_max * h2_constants.frame_header_len +
    h2_constants.ping_ack_pending_max * (h2_constants.frame_header_len + h2_constants.ping_len) +
    (h2_constants.stream_replies_max + 1) *
        (h2_constants.frame_header_len + h2_constants.window_update_len) +
    h2_constants.frame_header_len + h2_constants.goaway_len_min;

comptime {
    assert(output_len_needed <= constants.connection_check_output_len_max);
}

/// The storage one seed runs in: the connection, the clock it reads, the stream, and the three
/// traces with the two chunk-independent copies compared. The caller places it; it is far too
/// large for a stack.
pub const Storage = struct {
    /// The connection the seed's three runs drive, one after another. `Subject.init` empties it
    /// before each run, which is why it is `undefined` here.
    subject: Subject,
    /// The instant the pipe advances and the subject reads (design §4.2).
    clock: Clock,
    stream: [constants.connection_check_stream_len_max]u8,
    chunked: [constants.connection_check_trace_len_max]u8,
    replayed: [constants.connection_check_trace_len_max]u8,
    one_piece: [constants.connection_check_trace_len_max]u8,
    chunked_independent: [constants.connection_check_trace_len_max]u8,
    one_piece_independent: [constants.connection_check_trace_len_max]u8,

    pub const zeroed: Storage = .{
        .subject = undefined,
        .clock = .{ .now_ns = 0 },
        .stream = @splat(0),
        .chunked = @splat(0),
        .replayed = @splat(0),
        .one_piece = @splat(0),
        .chunked_independent = @splat(0),
        .one_piece_independent = @splat(0),
    };
};

/// One seed's run, as `zig build sim -- --connection-seed` prints it.
pub const SeedResult = struct {
    outcome: sim.pipe.Outcome,
    /// The chunked trace, inside the storage the seed ran in.
    trace: []const u8,
    /// The invariant the run broke, or null.
    violation: ?Violation,
};

pub fn run_seed(storage: *Storage, seed: u64) (Violation || sim.trace.Error)!SeedResult {
    var random = Random.init(seed);
    const plan = connection_stream.Plan.draw(&random);
    var stream_writer = Writer.init(&storage.stream);
    try plan.write(&stream_writer);

    var chunked_random = random;
    var replayed_random = random;
    const run: Run = .{ .stream = stream_writer.written(), .seed = seed, .storage = storage };
    const chunked = try run.once(.{ .seeded = &chunked_random }, &storage.chunked);
    const replayed = try run.once(.{ .seeded = &replayed_random }, &storage.replayed);
    const one_piece = try run.once(.one_piece, &storage.one_piece);
    if (first_violation(&.{ chunked, replayed, one_piece })) |broken| return broken;

    // The stream holds at least one frame, so the run in one piece feeds exactly once. That is the
    // harness's own contract, and the comparison below is vacuous without it.
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

/// The invariant the first of `results` that broke one broke, or null when none did.
fn first_violation(results: []const SeedResult) ?Violation {
    for (results) |result| {
        if (result.violation) |broken| return broken;
    }
    return null;
}

/// One seed's stream, which each of its three runs feeds to a connection of its own.
const Run = struct {
    stream: []const u8,
    seed: u64,
    storage: *Storage,

    fn once(run: *const Run, schedule: sim.pipe.Schedule, buffer: []u8) sim.trace.Error!SeedResult {
        var output = Writer.init(buffer);
        var trace = try Trace.begin(&output, check_name, run.seed);
        const storage = run.storage;
        storage.clock = Clock.init();
        storage.subject.init(&storage.clock);
        const outcome = try sim.pipe.run(
            Subject,
            &storage.subject,
            run.stream,
            schedule,
            &storage.clock,
            &trace,
        );
        return .{
            .outcome = outcome,
            .trace = output.written(),
            .violation = storage.subject.violation,
        };
    }
};

/// What a range of seeds did.
pub const Census = struct {
    seeds: u64 = 0,
    passed: u64 = 0,
    rejected: u64 = 0,
    trace_octets: u64 = 0,
    /// Frames the connection consumed across every chunked run: one accept record each.
    frames: u64 = 0,
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
        census.frames += sim.trace.count_records(result.trace, accept_record);
        census.chunks += sim.trace.count_records(result.trace, sim.trace.feed_record);
        census.crc32.update(result.trace);
    }
};

/// The record the pipe writes for every frame the connection consumed (`pipe.zig`).
const accept_record = "accept";

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

/// The storage the check tests run in, placed outside any stack frame.
var test_storage: Storage = .zeroed;

test "connection check: seeds replay, chunking changes no verdict, and traces hash as committed" {
    var census: Census = .{};
    var failed_seed: ?u64 = null;
    run_check(&test_storage, constants.check_seeds_default, &census, &failed_seed) catch |failure| {
        std.debug.print("connection check: seed 0x{x} failed: {t}\n", .{ failed_seed.?, failure });
        return failure;
    };
    try testing.expect(census.passed > 0);
    try testing.expect(census.rejected > 0);
    try testing.expect(census.frames > census.seeds);
    try testing.expect(census.chunks > census.seeds);
    try testing.expectEqual(census_crc32_expected, census.crc32.final());
}

/// Feeds `stream` to a fresh connection in one piece and returns how the run ended. Test-only.
fn run_stream(stream: []const u8) !sim.pipe.Outcome {
    var output = Writer.init(&test_storage.chunked);
    var trace = try Trace.begin(&output, check_name, 0);
    test_storage.clock = Clock.init();
    test_storage.subject.init(&test_storage.clock);
    const subject = &test_storage.subject;
    return sim.pipe.run(Subject, subject, stream, .one_piece, &test_storage.clock, &trace);
}

/// The connection error code RFC 9113 gives each refusal. The trace's reject record names the
/// error `receive` returned and not the code, so the code is checked here. Test-only.
fn code_of(refusal: connection_stream.Refusal) u32 {
    return switch (refusal) {
        // RFC 9113 §5.1.1 for the identifier, §4.3 for the interrupted field block, §6.8 for the
        // GOAWAY that names a higher stream.
        .headers_below_watermark, .frame_inside_field_block, .goaway_last_id_rises => h2_constants.error_protocol_error,
        // RFC 9113 §6.9.1: a window taken above its maximum.
        .connection_window_overflow => h2_constants.error_flow_control_error,
    };
}

test "every refusal ends the connection with its code, and the plan that drops it is accepted whole" {
    for (std.enums.values(connection_stream.Refusal)) |refusal| {
        var random = Random.init(0);
        var plan = connection_stream.Plan.draw(&random);
        plan.refusal = null;
        var without = Writer.init(&test_storage.stream);
        try plan.write(&without);
        try testing.expectEqual(sim.pipe.Outcome.pass, try run_stream(without.written()));
        try testing.expect(!test_storage.subject.connection.has_failed());
        plan.refusal = refusal;
        var with = Writer.init(&test_storage.stream);
        try plan.write(&with);
        try testing.expectEqual(sim.pipe.Outcome.rejected, try run_stream(with.written()));
        // RFC 9113 §5.4.1: a connection error queues the GOAWAY that says why it ended.
        try testing.expectEqual(code_of(refusal), test_storage.subject.connection.failure);
        try testing.expectEqual(null, test_storage.subject.violation);
    }
}

test "a connection that read nothing breaks none of invariants 13 to 16" {
    test_storage.clock = Clock.init();
    test_storage.subject.init(&test_storage.clock);
    try testing.expectEqual(null, test_storage.subject.check());
    try testing.expectEqual(null, test_storage.subject.violation);
    try testing.expect(rises(1, 2));
    try testing.expect(!rises(2, 1));
    try testing.expect(!rises(null, 2));
    try testing.expect(!rises(2, 2));
}
