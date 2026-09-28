//! The simulator's h2 trace commands (https://github.com/c4milo/colibri/issues/75, decision 104),
//! split off `run_main.zig` because a hand-written source file stays at or under 500 lines
//! (CLAUDE.md). `run_main.zig` parses the command line and calls these: one runs a range of seeds
//! and prints the census, and one writes a seed's trace as TLA+. `run_main.zig` saves those files
//! for `tools/h2_trace.sh`, because it is the one simulator file that does I/O.
const std = @import("std");
const h2 = @import("h2");
const sim = @import("sim");
const h2_trace_check = @import("h2_trace_check.zig");
const h2_trace_tla = @import("h2_trace_tla.zig");

const limits = sim.constants.h2_trace;

/// The storage the run writes into, and one seed's files, outside any stack frame.
var storage: h2_trace_check.Storage align(@alignOf(h2_trace_check.Storage)) = undefined;
var text: [limits.module_len_max]u8 = undefined;
var name_storage: [sim.constants.check_name_len_max]u8 = undefined;

/// One seed's trace as TLA+: the module, and the TLC configuration that checks it, both named for
/// the seed.
pub const Files = struct {
    name: []const u8,
    module: []const u8,
    config: []const u8,
};

/// The h2 trace run over `[0, seeds)`.
pub fn check(seeds: u64) !void {
    var census: h2_trace_check.Census = .{};
    var failed_seed: ?u64 = null;
    h2_trace_check.run_check(&storage, seeds, &census, &failed_seed) catch |failure| {
        std.debug.print("h2-trace: seed 0x{x} failed: {t}\n", .{ failed_seed.?, failure });
        return failure;
    };
    std.debug.print("h2-trace: seeds={d} opened={d} responses={d} resets={d} goaways={d} refused={d}\n", .{
        census.seeds, census.opened, census.responses, census.resets, census.goaways, census.refused,
    });
}

/// Runs `seed` and writes its trace as TLA+. The files stay valid until the next call.
pub fn files_of(seed: u64) !Files {
    _ = h2_trace_check.run_seed(&storage, seed) catch |failure| {
        std.debug.print("h2-trace: seed 0x{x} failed: {t}\n", .{ seed, failure });
        return failure;
    };
    const name = h2_trace_tla.module_name(seed, &name_storage);
    var module_writer = h2.core.Writer.init(&text);
    try h2_trace_tla.write_module(&module_writer, name, &storage.plan, storage.trace());
    const module_len = module_writer.written().len;
    var config_writer = h2.core.Writer.init(text[module_len..]);
    try h2_trace_tla.write_config(&config_writer, &storage.plan, limits.steps_between_max);
    return .{ .name = name, .module = text[0..module_len], .config = config_writer.written() };
}
