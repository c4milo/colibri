//! The simulator's deadline commands (design §8 step 20b, decision 110), split off `run_main.zig`
//! because a hand-written source file stays at or under 500 lines (CLAUDE.md). `run_main.zig`
//! parses the command line and calls these: one runs a seed and prints its trace, the other runs a
//! range of seeds and prints the census.
const std = @import("std");
const deadline_check = @import("deadline_check.zig");

/// The storage the check writes into, placed outside any stack frame.
var storage: deadline_check.Storage align(@alignOf(deadline_check.Storage)) = undefined;

pub fn seed(value: u64) !void {
    const result = deadline_check.run_seed(&storage, value) catch |failure| {
        // The trace the run wrote before it failed says where it went wrong.
        std.debug.print("{s}", .{storage.trace[0..storage.trace_len]});
        std.debug.print("deadline: seed 0x{x} failed: {t}\n", .{ value, failure });
        return failure;
    };
    std.debug.print("{s}", .{result.trace});
}

pub fn check(seeds: u64) !void {
    var census: deadline_check.Census = .{};
    var failed_seed: ?u64 = null;
    deadline_check.run_check(&storage, seeds, &census, &failed_seed) catch |failure| {
        std.debug.print("deadline: seed 0x{x} failed: {t}; rerun it with --deadline-seed\n", .{ failed_seed.?, failure });
        return failure;
    };
    const format = "deadline: seeds={d} exchanges={d} first_request={d} idle={d} head={d} body_rate={d} body={d}" ++
        " send_rate={d} settings={d} drain={d} streams_cut={d} held={d} trace_octets={d} crc32=0x{x:0>8}\n";
    std.debug.print(format, .{
        census.seeds,
        census.exchanges,
        census.first_request,
        census.idle,
        census.head,
        census.body_rate,
        census.body,
        census.send_rate,
        census.settings,
        census.drain,
        census.streams_cut,
        census.held,
        census.trace_octets,
        census.crc32.final(),
    });
}
