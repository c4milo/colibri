//! The simulator's endpoint commands (design §8 step 21b.5, decision 119), split off
//! `run_main.zig` because a hand-written source file stays at or under 500 lines (CLAUDE.md).
//! `run_main.zig` parses the command line and calls these: one runs a seed and prints its trace,
//! the other runs a range of seeds and prints the census.
const std = @import("std");
const endpoint_check = @import("endpoint/endpoint_check.zig");

/// The storage the check writes into, placed outside any stack frame.
var storage: endpoint_check.Storage align(@alignOf(endpoint_check.Storage)) = undefined;

pub fn seed(value: u64) !void {
    const result = endpoint_check.run_seed(&storage, value) catch |failure| {
        // The trace the run wrote before it failed says where it went wrong.
        std.debug.print("{s}", .{storage.trace[0..storage.trace_len]});
        std.debug.print("endpoint: seed 0x{x} failed: {t}\n", .{ value, failure });
        return failure;
    };
    std.debug.print("{s}", .{result.trace});
}

pub fn check(seeds: u64) !void {
    var census: endpoint_check.Census = .{};
    var failed_seed: ?u64 = null;
    endpoint_check.run_check(&storage, seeds, &census, &failed_seed) catch |failure| {
        std.debug.print("endpoint: seed 0x{x} failed: {t}; rerun it with --endpoint-seed\n", .{ failed_seed.?, failure });
        return failure;
    };
    const format = "endpoint: seeds={d} connections={d} reused={d} requests={d} done={d} cancelled_peer_reset={d}" ++
        " cancelled_deadline={d} cancelled_closed={d} cancelled_program={d} writable={d} sends={d} closes={d}" ++
        " stale_calls={d} waiting_probes={d} accept_waits={d} shutdowns={d} unserved={d} failed={d}" ++
        " trace_octets={d} crc32=0x{x:0>8} wire_crc32=0x{x:0>8}\n";
    std.debug.print(format, .{
        census.seeds,              census.connections,          census.reused,             census.requests,
        census.done,               census.cancelled_peer_reset, census.cancelled_deadline, census.cancelled_closed,
        census.cancelled_program,  census.writable,             census.sends,              census.closes,
        census.stale_calls,        census.waiting_probes,       census.accept_waits,       census.shutdowns,
        census.unserved,           census.failed,               census.trace_octets,       census.crc32.final(),
        census.wire_crc32.final(),
    });
}
