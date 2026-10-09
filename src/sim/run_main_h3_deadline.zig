//! The simulator's h3 deadline commands (design §8 step 20c, decision 110 as amended), split off
//! `run_main.zig` because a hand-written source file stays at or under 500 lines (CLAUDE.md).
//! `run_main.zig` parses the command line and calls these: one runs a seed and prints its trace,
//! the other runs a range of seeds and prints the census.
const std = @import("std");
const h3_deadline_check = @import("h3_deadline_check.zig");

/// The storage the check writes into, placed outside any stack frame.
var storage: h3_deadline_check.Storage align(@alignOf(h3_deadline_check.Storage)) = undefined;

pub fn seed(value: u64) !void {
    const result = h3_deadline_check.run_seed(&storage, value) catch |failure| {
        // The trace the run wrote before it failed says where it went wrong.
        std.debug.print("{s}", .{storage.trace[0..storage.trace_len]});
        std.debug.print("h3-deadline: seed 0x{x}, a peer that is {t}, failed: {t}\n", .{ value, h3_deadline_check.plan_of(value).peer, failure });
        return failure;
    };
    std.debug.print("{s}", .{result.trace});
}

pub fn check(seeds: u64) !void {
    var census: h3_deadline_check.Census = .{};
    var failed_seed: ?u64 = null;
    h3_deadline_check.run_check(&storage, seeds, &census, &failed_seed) catch |failure| {
        std.debug.print("h3-deadline: seed 0x{x} failed: {t}; rerun it with --h3-deadline-seed\n", .{ failed_seed.?, failure });
        return failure;
    };
    const format = "h3-deadline: seeds={d} exchanges={d} first_request={d} idle={d} body_rate={d} send_rate={d}" ++
        " peer_resets={d} requests_cut={d} trace_octets={d} crc32=0x{x:0>8} wire_crc32=0x{x:0>8}\n";
    std.debug.print(format, .{
        census.seeds,
        census.exchanges,
        census.first_request,
        census.idle,
        census.body_rate,
        census.send_rate,
        census.peer_resets,
        census.requests_cut,
        census.trace_octets,
        census.crc32.final(),
        census.wire_crc32.final(),
    });
}
