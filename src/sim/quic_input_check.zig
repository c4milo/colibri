//! The QUIC input check: hostile octets for three readers of what a QUIC peer sends, drawn from
//! one seed (https://github.com/c4milo/colibri/issues/53). It stands where the fuzzer would, as
//! `qpack_input_check.zig` does for QPACK: Zig 0.16.0 cannot build its fuzz mode (design §8 step
//! 1), and `core.fuzz.sweep` covers only inputs of two octets.
//!
//! Each input starts from what colibri's own writer produces, so it reaches past the first octet,
//! and then takes up to `quic_input_check_edits_max` edits (`input_edit.zig`). It goes to one of:
//! - `quic.frame.read`, a payload frame by frame (`quic_input_frames.zig`);
//! - `quic.packet.header.read`, a datagram packet by packet (`quic_input_packets.zig`);
//! - `quic.transport_parameters_read.read`, as a client's or a server's (`quic_input_packets.zig`).
//!
//! What the writer produced must be read whole before it is edited. The edited input must be read
//! or refused with an error value, never crash, and keep the rules each target file names. Each
//! seed runs twice and must reach the same outcomes (invariant 6). This module has no HTTP module
//! in its graph (decision 5).
const std = @import("std");
const assert = std.debug.assert;
const sim = @import("sim");
const quic = @import("quic");
const frames = @import("quic_input_frames.zig");
const packets = @import("quic_input_packets.zig");

const constants = sim.constants;
const Random = sim.Random;
const Role = quic.transport_parameters.Role;

/// The CRC-32 of the outcomes of seeds `[0, check_seeds_default)`, in order, and the frames the
/// same seeds read. They change when a writer, a reader or a draw changes, and are committed with
/// the new values after both build modes agree.
pub const census_crc32_expected: u32 = 0x1cfa0ad6;
pub const census_frames_read_expected: u64 = 54_437;

const Target = enum { frames, datagram, parameters };

/// What one input did: read whole, or refused.
pub const Outcome = enum(u8) { taken, refused };

pub const Storage = struct {
    /// The random octets every drawn string is a slice of, drawn once per seed.
    material: [constants.quic_input_check_material_len]u8,
    frames: frames.Storage,
    packets: packets.Storage,
    input: [constants.quic_input_check_input_len_max]u8,
    first: [constants.quic_input_check_inputs]Outcome,
    second: [constants.quic_input_check_inputs]Outcome,
};

pub const Violation = frames.Violation || packets.Violation || error{
    /// What colibri's writer produced was not read whole by colibri's reader.
    WrittenNotRead,
    /// The two runs of the seed reached different outcomes.
    ReplayDiverged,
};

/// The inputs of each target taken and refused, and the frames the frame target accepted, in the
/// written payloads and the edited ones.
pub const Counts = struct {
    taken: [target_count]u64 = @splat(0),
    refused: [target_count]u64 = @splat(0),
    frames_read: u64 = 0,

    fn add(counts: *Counts, other: Counts) void {
        for (&counts.taken, other.taken) |*sum, value| sum.* += value;
        for (&counts.refused, other.refused) |*sum, value| sum.* += value;
        counts.frames_read += other.frames_read;
    }
};

const target_count = std.meta.fields(Target).len;

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
        const target: Target = @enumFromInt(random.below(std.meta.fields(Target).len));
        const sender: Role = if (frames.chosen(random)) .client else .server;
        outcome.* = try one_input(storage, random, target, sender, counts);
        switch (outcome.*) {
            .taken => counts.taken[@intFromEnum(target)] += 1,
            .refused => counts.refused[@intFromEnum(target)] += 1,
        }
    }
}

/// Draws what the writer produces for `target`, reads it whole, edits it, and reads the edit.
fn one_input(storage: *Storage, random: *Random, target: Target, sender: Role, counts: *Counts) Violation!Outcome {
    const base = switch (target) {
        .frames => frames.draw_payload(&storage.frames, random, &storage.material),
        .datagram => packets.draw_datagram(&storage.packets, random, &storage.material),
        .parameters => packets.draw_parameters(&storage.packets, random, &storage.material, sender),
    };
    if (!try read(storage, target, base, sender, counts)) return error.WrittenNotRead;
    const input = sim.input_edit.edit(random, &storage.input, base, constants.quic_input_check_edits_max);
    return if (try read(storage, target, input, sender, counts)) .taken else .refused;
}

fn read(storage: *Storage, target: Target, input: []const u8, sender: Role, counts: *Counts) Violation!bool {
    return switch (target) {
        .frames => frames.read_payload(&storage.frames, input, &counts.frames_read),
        .datagram => packets.read_datagram(&storage.packets, input),
        .parameters => packets.read_parameters(&storage.packets, input, sender),
    };
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

test "quic input check: what colibri writes it reads, every edit is read or refused, and it replays" {
    var census: Census = .{};
    var failed_seed: ?u64 = null;
    run_check(&test_storage, constants.check_seeds_default, &census, &failed_seed) catch |failure| {
        std.debug.print("quic input check: seed 0x{x} failed: {t}\n", .{ failed_seed.?, failure });
        return failure;
    };
    // Both outcomes occur for every target, so the edits reach both the refusals and the paths
    // past them.
    for (census.counts.taken, census.counts.refused) |taken, refused| {
        try testing.expect(taken > 0);
        try testing.expect(refused > 0);
    }
    try testing.expectEqual(census_frames_read_expected, census.counts.frames_read);
    try testing.expectEqual(census_crc32_expected, census.crc32.final());
}
