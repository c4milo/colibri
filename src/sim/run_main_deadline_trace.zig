//! The simulator's deadline trace commands (https://github.com/c4milo/colibri/issues/86), split off
//! `run_main.zig` because a hand-written source file stays at or under 500 lines (CLAUDE.md).
//! `run_main.zig` parses the command line and calls these: one runs a range of seeds and prints the
//! census, and one writes a seed's trace as TLA+. `run_main.zig` saves those files for
//! `tools/deadline_trace.sh`, because it is the one simulator file that does I/O.
const std = @import("std");
const h2 = @import("h2");
const sim = @import("sim");
const deadline_trace_check = @import("deadline_trace_check.zig");
const deadline_trace_tla = @import("deadline_trace_tla.zig");

const limits = sim.constants.deadline_trace;

/// The storage the run writes into, and one seed's files, outside any stack frame.
var storage: deadline_trace_check.Storage align(@alignOf(deadline_trace_check.Storage)) = undefined;
var text: [limits.module_len_max]u8 = undefined;
var name_storage: [sim.constants.check_name_len_max]u8 = undefined;

/// One seed's trace as TLA+: the module, and the TLC configuration that checks it, both named for
/// the seed.
pub const Files = struct {
    name: []const u8,
    module: []const u8,
    config: []const u8,
};

/// The deadline trace run over `[0, seeds)`.
pub fn check(seeds: u64) !void {
    var census: deadline_trace_check.Census = .{};
    var failed_seed: ?u64 = null;
    deadline_trace_check.run_check(&storage, seeds, &census, &failed_seed) catch |failure| {
        std.debug.print("deadline-trace: seed 0x{x} failed: {t}\n", .{ failed_seed.?, failure });
        return failure;
    };
    std.debug.print("deadline-trace: seeds={d} states={d} requests={d} responses={d} bodies_timed={d} sends_timed={d}\n", .{
        census.seeds, census.states, census.requests, census.responses, census.bodies_timed, census.sends_timed,
    });
}

/// Runs `seed` and writes its trace as TLA+. The files stay valid until the next call.
pub fn files_of(seed: u64) !Files {
    _ = deadline_trace_check.run_seed(&storage, seed) catch |failure| {
        std.debug.print("deadline-trace: seed 0x{x} failed: {t}\n", .{ seed, failure });
        return failure;
    };
    const name = deadline_trace_tla.module_name(seed, &name_storage);
    var module_writer = h2.core.Writer.init(&text);
    try deadline_trace_tla.write_module(&module_writer, name, storage.plan.streams, storage.trace());
    const module_len = module_writer.written().len;
    var config_writer = h2.core.Writer.init(text[module_len..]);
    try deadline_trace_tla.write_config(&config_writer, &storage.plan, &storage.world, limits.steps_between_max);
    return .{ .name = name, .module = text[0..module_len], .config = config_writer.written() };
}
