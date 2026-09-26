//! The h2 input check: hostile octets for the h2 frame reader, drawn from one seed
//! (https://github.com/c4milo/colibri/issues/53). It stands where the fuzzer would, as
//! `qpack_input_check.zig` and `quic_input_check.zig` do: Zig 0.16.0 cannot build its fuzz mode
//! (design §8 step 1), and `core.fuzz.sweep` covers only inputs of two octets.
//!
//! Each input is a stream of frames colibri's writers produce (`h2_input_frames.zig`), which must
//! be read whole, and then takes up to `h2_input_check_edits_max` edits (`input_edit.zig`). The
//! edited stream must be read, cut short or refused, never crash, and keep the rules
//! `h2_input_frames.zig` names. Each seed runs twice and must reach the same outcomes
//! (invariant 6).
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");
const frames = @import("h2_input_frames.zig");

const constants = sim.constants;
const Random = sim.Random;

pub const Outcome = frames.Outcome;

/// The CRC-32 of the outcomes of seeds `[0, check_seeds_default)`, in order, and the frames the
/// same seeds read. They change when a writer, the reader or a draw changes, and are committed
/// with the new values after both build modes agree.
pub const census_crc32_expected: u32 = 0x0d547a5d;
pub const census_frames_read_expected: u64 = 157_943;

pub const Storage = struct {
    /// The random octets every drawn string is a slice of, drawn once per seed.
    material: [constants.h2_input_check_material_len]u8,
    frames: frames.Storage,
    input: [constants.h2_input_check_input_len_max]u8,
    first: [constants.h2_input_check_inputs]Outcome,
    second: [constants.h2_input_check_inputs]Outcome,
};

pub const Violation = frames.Violation || error{
    /// What colibri's writers produced was not read whole by colibri's reader.
    WrittenNotRead,
    /// The two runs of the seed reached different outcomes.
    ReplayDiverged,
};

/// The inputs of each outcome, and the frames accepted in the written streams and the edited ones.
pub const Counts = struct {
    outcomes: [std.meta.fields(Outcome).len]u64 = @splat(0),
    frames_read: u64 = 0,

    fn add(counts: *Counts, other: Counts) void {
        for (&counts.outcomes, other.outcomes) |*sum, value| sum.* += value;
        counts.frames_read += other.frames_read;
    }
};

pub fn run_seed(storage: *Storage, seed: u64) Violation!Counts {
    var random = Random.init(seed);
    for (&storage.material) |*octet| octet.* = @truncate(random.next());
    var first_random = random;
    var second_random = random;
    var counts: Counts = .{};
    try run_once(storage, &first_random, &storage.first, &counts);
    var replay_counts: Counts = .{};
    try run_once(storage, &second_random, &storage.second, &replay_counts);
    if (!std.mem.eql(Outcome, &storage.first, &storage.second)) return error.ReplayDiverged;
    if (first_random.draws != second_random.draws) return error.ReplayDiverged;
    if (!std.meta.eql(counts, replay_counts)) return error.ReplayDiverged;
    return counts;
}

fn run_once(storage: *Storage, random: *Random, outcomes: []Outcome, counts: *Counts) Violation!void {
    for (outcomes) |*outcome| {
        const base = frames.draw_stream(&storage.frames, random, &storage.material);
        if (try frames.read_stream(&storage.frames, base, &counts.frames_read) != .taken) return error.WrittenNotRead;
        const input = sim.input_edit.edit(random, &storage.input, base, constants.h2_input_check_edits_max);
        outcome.* = try frames.read_stream(&storage.frames, input, &counts.frames_read);
        counts.outcomes[@intFromEnum(outcome.*)] += 1;
    }
}

pub const Census = struct {
    seeds: u64 = 0,
    counts: Counts = .{},
    crc32: std.hash.Crc32 = .init(),

    fn count(census: *Census, storage: *const Storage, counts: Counts) void {
        census.seeds += 1;
        census.counts.add(counts);
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

test "h2 input check: what colibri writes it reads, every edit is read, cut or refused, and it replays" {
    var census: Census = .{};
    var failed_seed: ?u64 = null;
    run_check(&test_storage, constants.check_seeds_default, &census, &failed_seed) catch |failure| {
        std.debug.print("h2 input check: seed 0x{x} failed: {t}\n", .{ failed_seed.?, failure });
        return failure;
    };
    // Every outcome occurs, so the edits reach the refusals and the paths past them.
    for (census.counts.outcomes) |outcome_count| try testing.expect(outcome_count > 0);
    try testing.expectEqual(census_frames_read_expected, census.counts.frames_read);
    try testing.expectEqual(census_crc32_expected, census.crc32.final());
}
