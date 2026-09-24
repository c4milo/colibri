//! The QPACK check of design §8 step 11: `qpack`'s encoder and decoder joined by the three
//! streams RFC 9204 §4.2 and §4.5 name, with one seed choosing what a network could.
//!
//! Each step does one thing the seed picks among those possible:
//! - the encoder writes the next section, given a random amount of encoder stream credit
//!   (§2.1.3), so some inserts do not fit;
//! - some of the encoder stream reaches the decoder, cut anywhere, even inside an instruction;
//! - a section reaches the decoder, on any stream, but in order within its stream (§2.2.1);
//! - some of the decoder stream reaches the encoder, cut anywhere;
//! - a stream is cancelled, rarely, and its sections are never delivered (§2.2.2.2).
//!
//! Every decoded section must be the one the plan wrote, line for line. No decoder or encoder
//! may refuse what the other sent: that would be a blocked stream past the limit, a reference to
//! an evicted entry, or an acknowledgment for nothing. At the end every section is decoded or
//! cancelled, nothing is blocked, every octet was read, and the encoder has nothing outstanding.
//! Each seed runs twice, and the two runs must write the same trace and draw the same count of
//! values (invariant 6).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const sim = @import("sim");
const qpack = @import("qpack");
const qpack_plan = @import("qpack_plan.zig");

const Reader = core.Reader;
const Writer = core.Writer;
const Random = sim.Random;
const Trace = sim.Trace;
const constants = sim.constants;
const FieldSection = qpack.http.field_section.FieldSection;

/// The name every QPACK-check trace carries on its first line.
pub const check_name = "qpack";

/// The CRC-32 of the traces of seeds `[0, check_seeds_default)`, concatenated in seed order.
pub const census_crc32_expected: u32 = 0xf7bc7677;

/// Where one planned section is.
const State = enum { unwritten, written, blocked, decoded, cancelled };

/// One octet stream between the two endpoints: what was written, what reached the other side,
/// and what the other side has read.
const Stream = struct {
    written: u32 = 0,
    delivered: u32 = 0,
    consumed: u32 = 0,
};

/// The storage one seed runs in, too large for a stack frame.
pub const Storage = struct {
    plan: qpack_plan.Plan,
    encoder: qpack.encoder.Encoder,
    decoder: qpack.decoder.Decoder,
    states: [constants.qpack_check_sections_max]State,
    section_octets: [constants.qpack_check_sections_max][constants.qpack_check_section_len_max]u8,
    section_lens: [constants.qpack_check_sections_max]u32,
    encoder_octets: [constants.qpack_check_encoder_stream_len_max]u8,
    decoder_octets: [constants.qpack_check_decoder_stream_len_max]u8,
    written_section: FieldSection,
    decoded_section: FieldSection,
    strings: [core.constants.field_section_size_max]u8,
    first: [constants.qpack_check_trace_len_max]u8,
    second: [constants.qpack_check_trace_len_max]u8,
};

pub const Violation = error{
    /// The two runs of the seed wrote different traces or drew a different count of values.
    ReplayDiverged,
    /// The decoder refused what the encoder wrote.
    DecoderFailed,
    /// The encoder refused what the decoder wrote.
    EncoderFailed,
    /// A section decoded to lines other than the ones written.
    DecodedWrong,
    /// The steps ran out, or the run ended with a section, an octet or a reference left over.
    Unfinished,
};

/// What one run did, beside its trace.
pub const Counts = struct {
    decoded: u64 = 0,
    lines: u64 = 0,
    blocked: u64 = 0,
    cancelled: u64 = 0,
    inserts: u64 = 0,
    octets: u64 = 0,
};

pub const SeedResult = struct {
    trace: []const u8,
    counts: Counts,
};

pub fn run_seed(storage: *Storage, seed: u64) (Violation || sim.trace.Error)!SeedResult {
    var random = Random.init(seed);
    storage.plan.draw(&random);
    var first_random = random;
    var second_random = random;
    const first = try run_once(storage, seed, &first_random, &storage.first);
    const second = try run_once(storage, seed, &second_random, &storage.second);
    if (!std.mem.eql(u8, first.trace, second.trace)) return error.ReplayDiverged;
    if (first_random.draws != second_random.draws) return error.ReplayDiverged;
    return first;
}

fn run_once(storage: *Storage, seed: u64, random: *Random, buffer: []u8) (Violation || sim.trace.Error)!SeedResult {
    var output = Writer.init(buffer);
    var trace = try Trace.begin(&output, check_name, seed);
    var run: Run = .{ .storage = storage, .random = random, .trace = &trace };
    run.start();
    for (0..constants.qpack_check_steps_max) |_| {
        const action = run.choose() orelse break;
        try run.act(action);
    } else return error.Unfinished;
    try run.finish();
    try trace.end("pass");
    return .{ .trace = output.written(), .counts = run.counts };
}

const Action = enum { encode, encoder_stream, section, decoder_stream, cancel };

const Run = struct {
    storage: *Storage,
    random: *Random,
    trace: *Trace,
    counts: Counts = .{},
    next_section: u32 = 0,
    encoder_stream: Stream = .{},
    decoder_stream: Stream = .{},
    cancelled_streams: [constants.qpack_check_streams]bool = @splat(false),

    fn start(run: *Run) void {
        const storage = run.storage;
        storage.encoder.init(storage.plan.huffman);
        const settings = storage.plan.settings;
        storage.encoder.on_settings(.{ .max_table_capacity = settings.max_table_capacity, .blocked_streams = settings.blocked_streams });
        storage.decoder.init(settings);
        @memset(storage.states[0..storage.plan.len], .unwritten);
    }

    /// One action among those possible now, or null when nothing is left to do.
    fn choose(run: *Run) ?Action {
        var possible: [std.meta.fields(Action).len]Action = undefined;
        var count: usize = 0;
        if (run.next_section < run.storage.plan.len) {
            possible[count] = .encode;
            count += 1;
        }
        if (run.encoder_stream.delivered < run.encoder_stream.written) {
            possible[count] = .encoder_stream;
            count += 1;
        }
        if (run.deliverable(0) != null) {
            possible[count] = .section;
            count += 1;
        }
        if (qpack.decoder_stream.owes(&run.storage.decoder) or run.decoder_stream.delivered < run.decoder_stream.written) {
            possible[count] = .decoder_stream;
            count += 1;
        }
        if (run.cancellable(0) != null and run.random.below(constants.qpack_check_cancel_one_in) == 0) {
            possible[count] = .cancel;
            count += 1;
        }
        if (count == 0) return null;
        return possible[run.random.below(count)];
    }

    fn act(run: *Run, action: Action) (Violation || sim.trace.Error)!void {
        switch (action) {
            .encode => try run.encode(),
            .encoder_stream => try run.deliver_encoder_stream(),
            .section => try run.deliver_section(),
            .decoder_stream => try run.deliver_decoder_stream(),
            .cancel => try run.cancel(),
        }
    }

    /// The encoder writes the next planned section, with a random share of the encoder stream's
    /// room as its credit (RFC 9204 §2.1.3).
    fn encode(run: *Run) (Violation || sim.trace.Error)!void {
        const storage = run.storage;
        const index = run.next_section;
        run.next_section += 1;
        const section = &storage.plan.sections[index];
        if (run.cancelled_streams[stream_slot(section.stream_id)]) {
            storage.states[index] = .cancelled;
            return;
        }
        var indexing: [constants.qpack_check_lines_max]qpack.encoder.Indexing = undefined;
        storage.written_section.init();
        for (storage.plan.lines(index), 0..) |line, at| {
            storage.written_section.append(line.name, line.value) catch unreachable;
            indexing[at] = line.indexing;
        }
        const room = storage.encoder_octets.len - run.encoder_stream.written;
        const credit = run.random.below(room + 1);
        var output = Writer.init(&storage.section_octets[index]);
        var instructions = Writer.init(storage.encoder_octets[run.encoder_stream.written..][0..credit]);
        const inserted = storage.encoder.table.insert_count();
        storage.encoder.write_section(section.stream_id, &output, &instructions, &storage.written_section, indexing[0..section.len]) catch
            return error.Unfinished;
        storage.section_lens[index] = @intCast(output.written().len);
        run.encoder_stream.written += @intCast(instructions.written().len);
        storage.states[index] = .written;
        run.counts.inserts += storage.encoder.table.insert_count() - inserted;
        run.counts.octets += output.written().len + instructions.written().len;
        var line = try run.trace.record("encode");
        try line.number("section", index);
        try line.number("stream", section.stream_id);
        try line.number("octets", output.written().len);
        try line.number("instruction_octets", instructions.written().len);
        try run.trace.write(&line);
    }

    /// Some of the encoder stream reaches the decoder, and every stream it unblocks is decoded.
    fn deliver_encoder_stream(run: *Run) (Violation || sim.trace.Error)!void {
        const stream = &run.encoder_stream;
        stream.delivered += @intCast(run.random.between(1, stream.written - stream.delivered));
        var reader = Reader.init(run.storage.encoder_octets[stream.consumed..stream.delivered]);
        run.storage.decoder.read_encoder_stream(&reader) catch return error.DecoderFailed;
        stream.consumed = stream.delivered - @as(u32, @intCast(reader.remaining_len()));
        var line = try run.trace.record("encoder_stream");
        try line.number("delivered", stream.delivered);
        try line.number("consumed", stream.consumed);
        try run.trace.write(&line);
        // RFC 9204 §2.2.1: a blocked stream unblocks once the insert count reaches what it needs.
        // Bounded by the sections, each of which is decoded once.
        while (run.storage.decoder.ready_stream()) |stream_id| {
            const index = run.blocked_on(stream_id) orelse return error.Unfinished;
            if (try run.decode(index) != .decoded) return error.DecoderFailed;
        }
    }

    /// A section reaches the decoder: the first undecoded one of a stream the seed picks.
    fn deliver_section(run: *Run) (Violation || sim.trace.Error)!void {
        const index = run.deliverable(run.random.next()).?;
        if (try run.decode(index) == .blocked) run.counts.blocked += 1;
    }

    /// Some of what the decoder owes reaches the encoder.
    fn deliver_decoder_stream(run: *Run) (Violation || sim.trace.Error)!void {
        try run.write_decoder_stream();
        const stream = &run.decoder_stream;
        if (stream.delivered == stream.written) return;
        stream.delivered += @intCast(run.random.between(1, stream.written - stream.delivered));
        var reader = Reader.init(run.storage.decoder_octets[stream.consumed..stream.delivered]);
        run.storage.encoder.read_decoder_stream(&reader) catch return error.EncoderFailed;
        stream.consumed = stream.delivered - @as(u32, @intCast(reader.remaining_len()));
        var line = try run.trace.record("decoder_stream");
        try line.number("delivered", stream.delivered);
        try line.number("consumed", stream.consumed);
        try run.trace.write(&line);
    }

    /// RFC 9204 §2.2.2.2: a stream is reset before its sections are decoded, and the decoder
    /// abandons it.
    fn cancel(run: *Run) (Violation || sim.trace.Error)!void {
        const storage = run.storage;
        const stream_id = storage.plan.sections[run.cancellable(run.random.next()).?].stream_id;
        if (storage.decoder.abandon_stream(stream_id) == .owes_instructions) {
            try run.write_decoder_stream();
            if (storage.decoder.abandon_stream(stream_id) != .cancelled) return error.Unfinished;
        }
        run.cancelled_streams[stream_slot(stream_id)] = true;
        for (storage.plan.sections[0..storage.plan.len], storage.states[0..storage.plan.len]) |section, *state| {
            if (section.stream_id != stream_id) continue;
            if (state.* == .written or state.* == .blocked) {
                state.* = .cancelled;
                run.counts.cancelled += 1;
            }
        }
        var line = try run.trace.record("cancel");
        try line.number("stream", stream_id);
        try run.trace.write(&line);
    }

    /// Hands section `index` to the decoder, writing out what the decoder owes when its queue is
    /// full, and checks what it decodes.
    fn decode(run: *Run, index: u32) (Violation || sim.trace.Error)!qpack.decoder.Outcome {
        const storage = run.storage;
        const stream_id = storage.plan.sections[index].stream_id;
        // Bounded: once the queue is written the decoder decodes or blocks.
        for (0..decode_attempts) |_| {
            storage.decoded_section.init();
            var reader = Reader.init(storage.section_octets[index][0..storage.section_lens[index]]);
            var strings = Writer.init(&storage.strings);
            const outcome = storage.decoder.read_section(stream_id, &reader, &strings, &storage.decoded_section) catch
                return error.DecoderFailed;
            if (outcome == .owes_instructions) {
                try run.write_decoder_stream();
                continue;
            }
            storage.states[index] = if (outcome == .decoded) .decoded else .blocked;
            if (outcome == .decoded) try run.check_decoded(index);
            var line = try run.trace.record("section");
            try line.number("section", index);
            try line.number("stream", stream_id);
            try line.word("outcome", @tagName(outcome));
            try run.trace.write(&line);
            return outcome;
        }
        return error.Unfinished;
    }

    fn check_decoded(run: *Run, index: u32) Violation!void {
        const lines = run.storage.plan.lines(index);
        const decoded = &run.storage.decoded_section;
        if (decoded.len() != lines.len) return error.DecodedWrong;
        for (lines, 0..) |line, at| {
            const got = decoded.get(@intCast(at));
            if (!std.mem.eql(u8, got.name, line.name) or !std.mem.eql(u8, got.value, line.value)) return error.DecodedWrong;
        }
        run.counts.decoded += 1;
        run.counts.lines += lines.len;
    }

    fn write_decoder_stream(run: *Run) Violation!void {
        const stream = &run.decoder_stream;
        var writer = Writer.init(run.storage.decoder_octets[stream.written..]);
        run.storage.decoder.write_decoder_stream(&writer);
        stream.written += @intCast(writer.written().len);
        if (qpack.decoder_stream.owes(&run.storage.decoder)) return error.Unfinished;
    }

    /// The `pick`-th section, counting round, that is the first undecoded section of its stream
    /// with nothing of that stream blocked, or null when there is none.
    fn deliverable(run: *const Run, pick: u64) ?u32 {
        var candidates: [constants.qpack_check_streams]u32 = undefined;
        var count: usize = 0;
        var seen: [constants.qpack_check_streams]bool = @splat(false);
        for (run.storage.states[0..run.storage.plan.len], 0..) |state, index| {
            const slot = stream_slot(run.storage.plan.sections[index].stream_id);
            if (seen[slot]) continue;
            switch (state) {
                .decoded, .cancelled => continue,
                .unwritten, .blocked => seen[slot] = true,
                .written => {
                    seen[slot] = true;
                    candidates[count] = @intCast(index);
                    count += 1;
                },
            }
        }
        if (count == 0) return null;
        return candidates[pick % count];
    }

    /// The `pick`-th written section, counting round, not yet decoded or cancelled.
    fn cancellable(run: *const Run, pick: u64) ?u32 {
        var candidates: [constants.qpack_check_sections_max]u32 = undefined;
        var count: usize = 0;
        for (run.storage.states[0..run.storage.plan.len], 0..) |state, index| {
            if (state != .written and state != .blocked) continue;
            candidates[count] = @intCast(index);
            count += 1;
        }
        if (count == 0) return null;
        return candidates[pick % count];
    }

    fn blocked_on(run: *const Run, stream_id: u64) ?u32 {
        for (run.storage.states[0..run.storage.plan.len], 0..) |state, index| {
            if (state == .blocked and run.storage.plan.sections[index].stream_id == stream_id) return @intCast(index);
        }
        return null;
    }

    /// Nothing may be left: every section decoded or cancelled, nothing blocked, every octet read,
    /// and nothing outstanding at the encoder.
    fn finish(run: *const Run) Violation!void {
        for (run.storage.states[0..run.storage.plan.len]) |state| {
            if (state != .decoded and state != .cancelled) return error.Unfinished;
        }
        if (run.storage.decoder.blocked_len != 0) return error.Unfinished;
        if (run.encoder_stream.consumed != run.encoder_stream.written) return error.Unfinished;
        if (run.decoder_stream.consumed != run.decoder_stream.written) return error.Unfinished;
        if (run.storage.encoder.state.len != 0) return error.Unfinished;
    }
};

/// A section is read at most twice: once more after the decoder's full queue is written out.
const decode_attempts: usize = 2;

fn stream_slot(stream_id: u64) usize {
    return @intCast(stream_id / constants.qpack_check_stream_id_step);
}

/// What a range of seeds did.
pub const Census = struct {
    seeds: u64 = 0,
    counts: Counts = .{},
    trace_octets: u64 = 0,
    crc32: std.hash.Crc32 = .init(),

    fn count(census: *Census, result: SeedResult) void {
        census.seeds += 1;
        inline for (std.meta.fields(Counts)) |field| {
            @field(census.counts, field.name) += @field(result.counts, field.name);
        }
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

test "qpack check: every seed decodes what it wrote, replays, and hashes as committed" {
    var census: Census = .{};
    var failed_seed: ?u64 = null;
    run_check(&test_storage, constants.check_seeds_default, &census, &failed_seed) catch |failure| {
        std.debug.print("qpack check: seed 0x{x} failed: {t}\n", .{ failed_seed.?, failure });
        return failure;
    };
    // Every path the check exists for was taken: sections decoded, blocked and cancelled, and
    // entries inserted.
    try testing.expect(census.counts.decoded > census.seeds);
    try testing.expect(census.counts.blocked > 0);
    try testing.expect(census.counts.cancelled > 0);
    try testing.expect(census.counts.inserts > 0);
    try testing.expectEqual(census_crc32_expected, census.crc32.final());
}
