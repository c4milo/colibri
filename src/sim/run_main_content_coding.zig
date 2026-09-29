//! The simulator's content-coding commands (design §8 step 17e, decision 101), split off
//! `run_main.zig` because a hand-written source file stays at or under 500 lines (CLAUDE.md).
//! `run_main.zig` parses the command line and calls these: one runs a seed and prints its trace,
//! the other runs a range of seeds and prints the census.
const std = @import("std");
const content_coding_check = @import("content_coding_check.zig");

/// The storage the check writes into, placed outside any stack frame.
var storage: content_coding_check.Storage align(@alignOf(content_coding_check.Storage)) = undefined;

pub fn seed(value: u64) !void {
    const result = content_coding_check.run_seed(&storage, value) catch |failure| {
        std.debug.print("content-coding: seed 0x{x} failed: {t}\n", .{ value, failure });
        return failure;
    };
    std.debug.print("{s}", .{result.trace});
}

pub fn check(seeds: u64) !void {
    var census: content_coding_check.Census = .{};
    var failed_seed: ?u64 = null;
    content_coding_check.run_check(&storage, seeds, &census, &failed_seed) catch |failure| {
        std.debug.print("content-coding: seed 0x{x} failed: {t}; rerun it with --coding-seed\n", .{ failed_seed.?, failure });
        return failure;
    };
    const census_format = "content-coding: seeds={d} exchanges={d} decoded={d} passed_on={d} too_large={d}" ++
        " trace_octets={d} crc32=0x{x:0>8}\n";
    std.debug.print(census_format, .{
        census.seeds,
        census.exchanges,
        census.decoded,
        census.passed_on,
        census.too_large,
        census.trace_octets,
        census.crc32.final(),
    });
}
