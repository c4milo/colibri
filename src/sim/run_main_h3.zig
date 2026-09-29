//! The simulator's QPACK and h3 commands (design §8 steps 11 and 12), split off `run_main.zig`
//! because a hand-written source file stays at or under 500 lines (CLAUDE.md). `run_main.zig`
//! parses the command line and calls these.
const std = @import("std");
const qpack_check = @import("qpack_check.zig");
const qpack_input_check = @import("qpack_input_check.zig");
const h3_check = @import("h3_check.zig");

/// The storage each check writes into, placed outside any stack frame.
var qpack_storage: qpack_check.Storage align(@alignOf(qpack_check.Storage)) = undefined;
var qpack_input_storage: qpack_input_check.Storage align(@alignOf(qpack_input_check.Storage)) = undefined;
var h3_storage: h3_check.Storage align(@alignOf(h3_check.Storage)) = undefined;

/// The octets of `text` up to and including its last newline: the whole lines a trace holds.
fn whole_lines_len(text: []const u8) usize {
    const last = std.mem.lastIndexOfScalar(u8, text, '\n') orelse return 0;
    return last + 1;
}

/// One seed of the QPACK check: its trace, then what it did.
pub fn qpack_seed(seed: u64) !void {
    const result = qpack_check.run_seed(&qpack_storage, seed) catch |failure| {
        std.debug.print("{s}", .{qpack_storage.first[0..whole_lines_len(&qpack_storage.first)]});
        std.debug.print("qpack: seed 0x{x} failed: {t}\n", .{ seed, failure });
        return failure;
    };
    const counts = result.counts;
    std.debug.print("{s}qpack: seed 0x{x} decoded={d} blocked={d} cancelled={d} inserts={d}\n", .{
        result.trace, seed, counts.decoded, counts.blocked, counts.cancelled, counts.inserts,
    });
}

/// The QPACK check of design §8 step 11, over `[0, seeds)`.
pub fn qpack_check_seeds(seeds: u64) !void {
    var census: qpack_check.Census = .{};
    var failed_seed: ?u64 = null;
    qpack_check.run_check(&qpack_storage, seeds, &census, &failed_seed) catch |failure| {
        std.debug.print("qpack: seed 0x{x} failed: {t}; rerun it with --qpack-seed\n", .{ failed_seed.?, failure });
        return failure;
    };
    const counts = census.counts;
    std.debug.print("qpack: seeds={d} decoded={d} lines={d} blocked={d} cancelled={d} inserts={d} octets={d}" ++
        " trace_octets={d} crc32=0x{x:0>8}\n", .{
        census.seeds,   counts.decoded, counts.lines,        counts.blocked,       counts.cancelled,
        counts.inserts, counts.octets,  census.trace_octets, census.crc32.final(),
    });
}

/// The QPACK input check of design §8 step 11, over `[0, seeds)`.
pub fn qpack_input_check_seeds(seeds: u64) !void {
    var census: qpack_input_check.Census = .{};
    var failed_seed: ?u64 = null;
    qpack_input_check.run_check(&qpack_input_storage, seeds, &census, &failed_seed) catch |failure| {
        std.debug.print("qpack-input: seed 0x{x} failed: {t}\n", .{ failed_seed.?, failure });
        return failure;
    };
    const counts = census.counts;
    std.debug.print("qpack-input: seeds={d} inputs={d} taken={d} blocked={d} refused={d} crc32=0x{x:0>8}\n", .{
        census.seeds, counts.inputs, counts.taken, counts.blocked, counts.refused, census.crc32.final(),
    });
}

/// The h3 check of design §8 step 12, over `[0, seeds)`, in the normal or the long shape.
pub fn h3_check_seeds(seeds: u64, shape: h3_check.Shape) !void {
    h3_storage.shape = shape;
    h3_storage.logged = false;
    var census: h3_check.Census = .{};
    var failed_seed: ?u64 = null;
    h3_check.run_check(&h3_storage, seeds, &census, &failed_seed) catch |failure| {
        std.debug.print("{s}: seed 0x{x} failed: {t}\n", .{ label_of(shape), failed_seed.?, failure });
        return failure;
    };
    std.debug.print("{s}: seeds={d} exchanges={d} content={d} inserts={d} acknowledged_dropped={d} datagrams={d} dropped={d} crc32=0x{x:0>8}\n", .{
        label_of(shape),             census.seeds,     census.exchanges, census.content_len,   census.inserts,
        census.acknowledged_dropped, census.datagrams, census.dropped,   census.crc32.final(),
    });
}

/// The name a census line starts with, which `tools/ci.sh` looks for.
fn label_of(shape: h3_check.Shape) []const u8 {
    return if (shape.exchanges_max == h3_check.Shape.long.exchanges_max) "h3-long" else "h3";
}
