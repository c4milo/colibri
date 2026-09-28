//! The simulator's client trace commands (decision 105), split off `run_main.zig` because a
//! hand-written source file stays at or under 500 lines (CLAUDE.md). `run_main.zig` parses the
//! command line and calls these: one runs a range of seeds and prints the census, one runs one
//! seed and prints its trace, and one writes a seed's trace as TLA+. `run_main.zig` saves those
//! files for `tools/client_trace.sh`, because it is the one simulator file that does I/O.
const std = @import("std");
const quic = @import("quic");
const sim = @import("sim");
const client_trace_check = @import("client_trace_check.zig");
const client_trace_tla = @import("client_trace_tla.zig");

const limits = sim.constants.client_trace;

/// The storage the run writes into, and one seed's files, outside any stack frame.
var storage: client_trace_check.Storage align(@alignOf(client_trace_check.Storage)) = undefined;
var text: [limits.module_len_max]u8 = undefined;
var name_storage: [sim.constants.check_name_len_max]u8 = undefined;

pub const Files = struct {
    name: []const u8,
    module: []const u8,
    config: []const u8,
};

/// The client trace run over `[0, seeds)`.
pub fn check(seeds: u64) !void {
    var census: client_trace_check.Census = .{};
    var failed_seed: ?u64 = null;
    client_trace_check.run_check(&storage, seeds, &census, &failed_seed) catch |failure| {
        std.debug.print("client-trace: seed 0x{x} failed: {t}\n", .{ failed_seed.?, failure });
        return failure;
    };
    const result = census.result;
    std.debug.print("client-trace: seeds={d} exchanges={d} responses={d} refused={d} failed={d} cancelled={d}", .{
        census.seeds, result.exchanges, result.responses, result.refused, result.failed, result.cancelled,
    });
    std.debug.print(" moved={d} quic={d} tcp={d} goaways={d} learned={d} states={d} closing_ms_max={d}\n", .{
        result.moved,                                                       result.quic_connections, result.tcp_connections, result.goaways, result.learned, result.states,
        census.closing_max_ns / quic.constants.nanoseconds_per_millisecond,
    });
}

/// Runs `seed` and prints its plan's shape and its trace as TLA+.
pub fn seed_trace(seed: u64) !void {
    const files = try files_of(seed);
    std.debug.print("{s}\n{s}", .{ files.module, files.config });
}

/// Runs `seed` and writes its trace as TLA+. The files stay valid until the next call.
pub fn files_of(seed: u64) !Files {
    _ = client_trace_check.run_seed(&storage, seed) catch |failure| {
        std.debug.print("client-trace: seed 0x{x} failed: {t}\n", .{ seed, failure });
        return failure;
    };
    const name = client_trace_tla.module_name(seed, &name_storage);
    var module_writer = quic.core.Writer.init(&text);
    const trace = storage.trace();
    try client_trace_tla.write_module(&module_writer, name, &storage.world.plan, trace);
    const module_len = module_writer.written().len;
    var config_writer = quic.core.Writer.init(text[module_len..]);
    try client_trace_tla.write_config(&config_writer, &storage.world.plan, &trace[trace.len - 1], storage.world.ledger.goaways, limits.steps_between_max);
    return .{ .name = name, .module = text[0..module_len], .config = config_writer.written() };
}
