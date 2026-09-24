//! The QPACK input check of design §8 step 11: hostile octets for each of the three inputs colibri
//! reads from a peer, drawn from one seed. It stands where the fuzzer would: Zig 0.16.0 cannot
//! build its fuzz mode (design §8 step 1), and `core.fuzz.sweep` covers only inputs of two octets.
//!
//! Each input starts from what colibri's own encoder writes for a planned section, so it reaches
//! past the first octet, and then takes up to `qpack_input_check_edits_max` edits: an octet
//! changed, inserted or removed, or the end cut off. It goes to one of:
//! - the decoder's `read_section`, after the encoder stream the section was written with;
//! - the decoder's `read_encoder_stream`;
//! - the encoder's `read_decoder_stream`, after the section was written.
//!
//! Every input must be taken or refused with an error value, and never crash or trip an
//! assertion: RFC 9204 §6 makes each refusal a connection or stream error, never a halt. Each seed
//! runs twice and must reach the same outcomes (invariant 6).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const sim = @import("sim");
const qpack = @import("qpack");
const qpack_plan = @import("qpack_plan.zig");

const Reader = core.Reader;
const Writer = core.Writer;
const Random = sim.Random;
const constants = sim.constants;
const FieldSection = qpack.http.field_section.FieldSection;

/// The CRC-32 of the outcomes of seeds `[0, check_seeds_default)`, in order.
pub const census_crc32_expected: u32 = 0x0452f651;

const Target = enum { section, encoder_stream, decoder_stream };

/// What one input did.
pub const Outcome = enum(u8) { taken, blocked, refused };

pub const Storage = struct {
    plan: qpack_plan.Plan,
    encoder: qpack.encoder.Encoder,
    decoder: qpack.decoder.Decoder,
    section: FieldSection,
    decoded: FieldSection,
    strings: [core.constants.field_section_size_max]u8,
    encoded: [constants.qpack_check_section_len_max]u8,
    instructions: [constants.qpack_check_section_len_max]u8,
    input: [constants.qpack_input_check_input_len_max]u8,
    first: [constants.qpack_input_check_inputs]Outcome,
    second: [constants.qpack_input_check_inputs]Outcome,
};

pub const Violation = error{
    /// The two runs of the seed reached different outcomes.
    ReplayDiverged,
};

pub const Counts = struct {
    inputs: u64 = 0,
    taken: u64 = 0,
    blocked: u64 = 0,
    refused: u64 = 0,
};

pub fn run_seed(storage: *Storage, seed: u64) Violation!Counts {
    var random = Random.init(seed);
    storage.plan.draw(&random);
    var first_random = random;
    var second_random = random;
    run_once(storage, &first_random, &storage.first);
    run_once(storage, &second_random, &storage.second);
    if (!std.mem.eql(Outcome, &storage.first, &storage.second)) return error.ReplayDiverged;
    if (first_random.draws != second_random.draws) return error.ReplayDiverged;
    var counts: Counts = .{ .inputs = storage.first.len };
    for (storage.first) |outcome| switch (outcome) {
        .taken => counts.taken += 1,
        .blocked => counts.blocked += 1,
        .refused => counts.refused += 1,
    };
    return counts;
}

fn run_once(storage: *Storage, random: *Random, outcomes: []Outcome) void {
    for (outcomes) |*outcome| {
        const index: u32 = @intCast(random.below(storage.plan.len));
        const target: Target = @enumFromInt(random.below(std.meta.fields(Target).len));
        outcome.* = one_input(storage, random, index, target);
    }
}

/// Writes planned section `index` with a fresh encoder, edits one of its outputs, and hands the
/// edited octets to `target`.
fn one_input(storage: *Storage, random: *Random, index: u32, target: Target) Outcome {
    const written = encode(storage, index);
    const base = switch (target) {
        .section => written.section,
        .encoder_stream => written.instructions,
        .decoder_stream => acknowledgment(storage, written.stream_id),
    };
    const input = edit(storage, random, base);
    return switch (target) {
        .section => read_section(storage, written, input),
        .encoder_stream => read_encoder_stream(storage, input),
        .decoder_stream => read_decoder_stream(storage, input),
    };
}

const Written = struct {
    section: []const u8,
    instructions: []const u8,
    stream_id: u64,
};

fn encode(storage: *Storage, index: u32) Written {
    const settings = storage.plan.settings;
    storage.encoder.init(storage.plan.huffman);
    storage.encoder.on_settings(.{ .max_table_capacity = settings.max_table_capacity, .blocked_streams = settings.blocked_streams });
    storage.section.init();
    for (storage.plan.lines(index)) |line| storage.section.append(line.name, line.value) catch unreachable;
    var output = Writer.init(&storage.encoded);
    var instructions = Writer.init(&storage.instructions);
    const stream_id = storage.plan.sections[index].stream_id;
    storage.encoder.write_section(stream_id, &output, &instructions, &storage.section, &.{}) catch unreachable;
    return .{ .section = output.written(), .instructions = instructions.written(), .stream_id = stream_id };
}

/// The Section Acknowledgment a decoder would send for the section, in `storage.input`'s place.
fn acknowledgment(storage: *Storage, stream_id: u64) []const u8 {
    var writer = Writer.init(&storage.encoded);
    qpack.instruction.write_decoder(&writer, .{ .section_acknowledgment = stream_id }) catch unreachable;
    return writer.written();
}

/// Copies `base` into the input buffer and makes up to `qpack_input_check_edits_max` edits.
fn edit(storage: *Storage, random: *Random, base: []const u8) []const u8 {
    const input = &storage.input;
    var len: usize = @min(base.len, input.len);
    @memcpy(input[0..len], base[0..len]);
    const edits = random.below(constants.qpack_input_check_edits_max + 1);
    for (0..edits) |_| {
        const at = random.below(len + 1);
        const kind: Edit = @enumFromInt(random.below(std.meta.fields(Edit).len));
        switch (kind) {
            .change => if (at < len) {
                input[at] = @truncate(random.next());
            },
            .insert => if (len < input.len) {
                std.mem.copyBackwards(u8, input[at + 1 .. len + 1], input[at..len]);
                input[at] = @truncate(random.next());
                len += 1;
            },
            .remove => if (at < len) {
                std.mem.copyForwards(u8, input[at .. len - 1], input[at + 1 .. len]);
                len -= 1;
            },
            .cut => len = at,
        }
    }
    return input[0..len];
}

/// The edits: an octet changed, inserted or removed, or the end cut off at the drawn offset.
const Edit = enum { change, insert, remove, cut };

fn read_section(storage: *Storage, written: Written, input: []const u8) Outcome {
    const settings = storage.plan.settings;
    storage.decoder.init(settings);
    var instructions = Reader.init(written.instructions);
    storage.decoder.read_encoder_stream(&instructions) catch unreachable;
    storage.decoded.init();
    var reader = Reader.init(input);
    var strings = Writer.init(&storage.strings);
    const outcome = storage.decoder.read_section(written.stream_id, &reader, &strings, &storage.decoded) catch return .refused;
    return switch (outcome) {
        .decoded => .taken,
        .blocked => .blocked,
        .owes_instructions, .read_ready_first => unreachable,
    };
}

fn read_encoder_stream(storage: *Storage, input: []const u8) Outcome {
    storage.decoder.init(storage.plan.settings);
    var reader = Reader.init(input);
    storage.decoder.read_encoder_stream(&reader) catch return .refused;
    assert(storage.decoder.table.size <= storage.decoder.table.capacity);
    return .taken;
}

fn read_decoder_stream(storage: *Storage, input: []const u8) Outcome {
    var reader = Reader.init(input);
    storage.encoder.read_decoder_stream(&reader) catch return .refused;
    assert(storage.encoder.state.known_received <= storage.encoder.table.insert_count());
    return .taken;
}

pub const Census = struct {
    seeds: u64 = 0,
    counts: Counts = .{},
    crc32: std.hash.Crc32 = .init(),

    fn count(census: *Census, storage: *const Storage, counts: Counts) void {
        census.seeds += 1;
        inline for (std.meta.fields(Counts)) |field| {
            @field(census.counts, field.name) += @field(counts, field.name);
        }
        census.crc32.update(std.mem.sliceAsBytes(&storage.first));
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
var test_storage: Storage = undefined;

test "qpack input check: every edited input is taken or refused, replays, and hashes as committed" {
    var census: Census = .{};
    var failed_seed: ?u64 = null;
    run_check(&test_storage, constants.check_seeds_default, &census, &failed_seed) catch |failure| {
        std.debug.print("qpack input check: seed 0x{x} failed: {t}\n", .{ failed_seed.?, failure });
        return failure;
    };
    // Each outcome occurs, so the edits reach both the refusals and the paths past them.
    try testing.expect(census.counts.taken > 0);
    try testing.expect(census.counts.blocked > 0);
    try testing.expect(census.counts.refused > 0);
    try testing.expectEqual(census_crc32_expected, census.crc32.final());
}
