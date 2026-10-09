//! The simulator's h3 deadline trace commands (design §8 step 20d), split off `run_main.zig`
//! because a hand-written source file stays at or under 500 lines (CLAUDE.md). `run_main.zig`
//! parses the command line and calls these: one runs a range of seeds and prints the census, and
//! one writes a seed's trace as TLA+. `run_main.zig` saves those files for
//! `tools/h3_deadline_trace.sh`, because it is the one simulator file that does I/O.
const std = @import("std");
const quic = @import("quic");
const sim = @import("sim");
const h3_deadline_trace_check = @import("h3_deadline_trace_check.zig");
const h3_deadline_trace_tla = @import("h3_deadline_trace_tla.zig");

const limits = sim.constants.h3_deadline_trace;

/// The storage the run writes into, and one seed's files, outside any stack frame.
var storage: h3_deadline_trace_check.Storage align(@alignOf(h3_deadline_trace_check.Storage)) = undefined;
var text: [limits.module_len_max]u8 = undefined;
var name_storage: [sim.constants.check_name_len_max]u8 = undefined;

/// One seed's trace as TLA+: the module, and the TLC configuration that checks it, both named for
/// the seed.
pub const Files = struct {
    name: []const u8,
    module: []const u8,
    config: []const u8,
};

/// The h3 deadline trace run over `[0, seeds)`.
pub fn check(seeds: u64) !void {
    var census: h3_deadline_trace_check.Census = .{};
    var failed_seed: ?u64 = null;
    h3_deadline_trace_check.run_check(&storage, seeds, &census, &failed_seed) catch |failure| {
        std.debug.print("h3-deadline-trace: seed 0x{x} failed: {t}\n", .{ failed_seed.?, failure });
        return failure;
    };
    const total = census.total;
    std.debug.print("h3-deadline-trace: seeds={d} states={d} opened={d} responses={d} timeouts={d} rejected={d} cancelled={d} drained={d} drain_passed={d}\n", .{
        census.seeds,   total.states,    total.opened,  total.responses,    total.timeouts,
        total.rejected, total.cancelled, total.drained, total.drain_passed,
    });
}

/// Runs `seed` and writes its trace as TLA+. The files stay valid until the next call.
pub fn files_of(seed: u64) !Files {
    _ = h3_deadline_trace_check.run_seed(&storage, seed) catch |failure| {
        std.debug.print("h3-deadline-trace: seed 0x{x} failed: {t}\n", .{ seed, failure });
        return failure;
    };
    const name = h3_deadline_trace_tla.module_name(seed, &name_storage);
    var module_writer = quic.core.Writer.init(&text);
    try h3_deadline_trace_tla.write_module(&module_writer, name, storage.plan.requests, storage.trace());
    const module_len = module_writer.written().len;
    var config_writer = quic.core.Writer.init(text[module_len..]);
    try h3_deadline_trace_tla.write_config(&config_writer, &storage.plan, limits.steps_between_max);
    return .{ .name = name, .module = text[0..module_len], .config = config_writer.written() };
}
