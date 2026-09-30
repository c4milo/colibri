//! The simulator's h2 stall commands (https://github.com/c4milo/colibri/issues/85), split off
//! `run_main.zig` because a hand-written source file stays at or under 500 lines (CLAUDE.md).
//! `run_main.zig` parses the command line and calls these: one runs a seed and prints its plan and
//! what the run did, and the other runs a range of seeds and prints the census.
const std = @import("std");
const sim = @import("sim");
const h2_stall_check = @import("h2_stall_check.zig");
const h2_stall_plan = @import("h2_stall_plan.zig");

const limits = sim.constants.h2_stall;

/// The storage the check writes into, placed outside any stack frame.
var storage: h2_stall_check.Storage align(@alignOf(h2_stall_check.Storage)) = undefined;

pub fn seed(value: u64) !void {
    const result = h2_stall_check.run_seed(&storage, value) catch |failure| {
        std.debug.print("h2-stall: seed 0x{x} failed: {t}\n", .{ value, failure });
        return failure;
    };
    const plan = &result.plan;
    std.debug.print("h2-stall: seed=0x{x} shape={t} capacity={d} streams={d} chunk={d} writes={d} frames={d} client_owed_first={d} server_owed_first={d}\n", .{
        value,                                plan.shape,                           plan.capacity, plan.streams, plan.chunk_len, plan.writes_per_turn, plan.frames_per_turn,
        @intFromBool(plan.client_owed_first), @intFromBool(plan.server_owed_first),
    });
    const record = &result.record;
    std.debug.print("h2-stall: outcome={t} rounds={d} octets={d} client_queue_full={d} server_queue_full={d} to_server={d} to_client={d}" ++
        " client_replies_most={d} server_replies_most={d} reads_stopped_full={d}\n", .{
        record.outcome,
        record.rounds,
        record.octets,
        @intFromBool(record.client_queue_full),
        @intFromBool(record.server_queue_full),
        record.to_server_len,
        record.to_client_len,
        record.client_replies_most,
        record.server_replies_most,
        record.reads_stopped_full,
    });
}

pub fn check(seeds: u64) !void {
    var census: h2_stall_check.Census = .{};
    var failed_seed: ?u64 = null;
    h2_stall_check.run_check(&storage, seeds, &census, &failed_seed) catch |failure| {
        std.debug.print("h2-stall: seed 0x{x} failed: {t}; rerun it with --h2-stall-seed\n", .{ failed_seed.?, failure });
        return failure;
    };
    std.debug.print("h2-stall: seeds={d} octets={d} stalled={d}\n", .{ census.seeds, census.octets, census.stalled() });
    for (std.enums.values(h2_stall_plan.Shape)) |shape| {
        for (limits.capacities) |capacity| {
            const cell = census.cell(shape, capacity);
            std.debug.print("h2-stall: {t} capacity={d} runs={d} finished={d} stalled={d} both_full={d} replies_most={d} reads_stopped_full={d}\n", .{
                shape, capacity, cell.runs, cell.finished, cell.stalled, cell.both_full, cell.replies_most, cell.reads_stopped_full,
            });
        }
    }
    for (std.enums.values(h2_stall_plan.Order), census.orders) |order, cell| {
        std.debug.print("h2-stall: order={t} runs={d} finished={d} stalled={d} both_full={d} reads_stopped_full={d}\n", .{
            order, cell.runs, cell.finished, cell.stalled, cell.both_full, cell.reads_stopped_full,
        });
    }
}
