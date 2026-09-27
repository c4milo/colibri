//! The simulator's h11 commands (design §8 step 15), split off `run_main.zig` because a
//! hand-written source file stays at or under 500 lines (CLAUDE.md). `run_main.zig` parses the
//! command line and calls these; each runs one seed and prints its trace, or runs a range of seeds
//! and prints the census.
const std = @import("std");
const h11_split_check = @import("h11_split_check.zig");
const h11_exchange_check = @import("h11_exchange_check.zig");
const h11_coding_check = @import("h11_coding_check.zig");

/// The storage each check writes into, placed outside any stack frame.
var h11_split_storage: h11_split_check.Storage align(@alignOf(h11_split_check.Storage)) = undefined;
var h11_exchange_storage: h11_exchange_check.Storage align(@alignOf(h11_exchange_check.Storage)) = undefined;
var h11_coding_storage: h11_coding_check.Storage align(@alignOf(h11_coding_check.Storage)) = undefined;

pub fn split_seed(seed: u64) !void {
    const result = h11_split_check.run_seed(&h11_split_storage, seed) catch |failure| {
        std.debug.print("h11-split: seed 0x{x} failed: {t}\n", .{ seed, failure });
        return failure;
    };
    std.debug.print("{s}", .{result.trace});
}

pub fn split_check(seeds: u64) !void {
    var census: h11_split_check.Census = .{};
    var failed_seed: ?u64 = null;
    h11_split_check.run_check(&h11_split_storage, seeds, &census, &failed_seed) catch |failure| {
        std.debug.print("h11-split: seed 0x{x} failed: {t}; rerun it with --h11-split-seed\n", .{
            failed_seed.?,
            failure,
        });
        return failure;
    };
    const census_format = "h11-split: seeds={d} passed={d} rejected={d} messages={d} chunks={d}" ++
        " trace_octets={d} crc32=0x{x:0>8}\n";
    std.debug.print(census_format, .{
        census.seeds,
        census.passed,
        census.rejected,
        census.messages,
        census.chunks,
        census.trace_octets,
        census.crc32.final(),
    });
}

pub fn connection_seed(seed: u64) !void {
    const result = h11_exchange_check.run_seed(&h11_exchange_storage, seed) catch |failure| {
        std.debug.print("h11-connection: seed 0x{x} failed: {t}\n", .{ seed, failure });
        return failure;
    };
    std.debug.print("{s}h11-connection: seed 0x{x} sent={d} steps={d}\n", .{ result.trace, seed, result.sent, result.steps });
}

pub fn connection_check(seeds: u64) !void {
    var census: h11_exchange_check.Census = .{};
    var failed_seed: ?u64 = null;
    h11_exchange_check.run_check(&h11_exchange_storage, seeds, &census, &failed_seed) catch |failure| {
        std.debug.print("h11-connection: seed 0x{x} failed: {t}; rerun it with --h11-connection-seed\n", .{
            failed_seed.?,
            failure,
        });
        return failure;
    };
    const census_format = "h11-connection: seeds={d} answered={d} unanswered={d} steps={d}" ++
        " trace_octets={d} crc32=0x{x:0>8}\n";
    std.debug.print(census_format, .{
        census.seeds,
        census.answered,
        census.unanswered,
        census.steps,
        census.trace_octets,
        census.crc32.final(),
    });
}

pub fn coding_seed(seed: u64) !void {
    const result = h11_coding_check.run_seed(&h11_coding_storage, seed) catch |failure| {
        std.debug.print("h11-coding: seed 0x{x} failed: {t}\n", .{ seed, failure });
        return failure;
    };
    std.debug.print("{s}h11-coding: seed 0x{x} pieces={d} calls={d}\n", .{ result.trace, seed, result.pieces, result.calls });
}

pub fn coding_check(seeds: u64) !void {
    var census: h11_coding_check.Census = .{};
    var failed_seed: ?u64 = null;
    h11_coding_check.run_check(&h11_coding_storage, seeds, &census, &failed_seed) catch |failure| {
        std.debug.print("h11-coding: seed 0x{x} failed: {t}; rerun it with --h11-coding-seed\n", .{
            failed_seed.?,
            failure,
        });
        return failure;
    };
    const census_format = "h11-coding: seeds={d} messages={d} refused={d} two_members={d}" ++
        " stream_octets={d} pieces={d} calls={d} trace_octets={d} crc32=0x{x:0>8}\n";
    std.debug.print(census_format, .{
        census.seeds,
        census.messages,
        census.refused,
        census.two_members,
        census.stream_octets,
        census.pieces,
        census.calls,
        census.trace_octets,
        census.crc32.final(),
    });
}
