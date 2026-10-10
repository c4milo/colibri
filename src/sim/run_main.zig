//! The simulator's command line, split off `run.zig` so that the driver file names the checks and
//! this one holds the ways to ask for a run:
//!
//!     (the commands are listed in `run_main_command.zig`, with their parser)
//!
//! The h11 commands are in `run_main_h11.zig`, and the QPACK and h3 ones in `run_main_h3.zig`,
//! split off for length.
//!
//! It is the one file under `src/sim/` that reads its arguments and writes to the terminal, and
//! `tools/lint/io.zig` exempts it by path for that reason. Nothing reaches it but `zig build sim`.
const std = @import("std");
const sim = @import("sim");
const chunk_check = @import("chunk_check.zig");
const run_main_command = @import("run_main_command.zig");
const run_main_h11 = @import("run_main_h11.zig");
const run_main_content_coding = @import("run_main_content_coding.zig");
const run_main_h3 = @import("run_main_h3.zig");
const run_main_deadline = @import("run_main_deadline.zig");
const run_main_h3_deadline = @import("run_main_h3_deadline.zig");
const run_main_h2_trace = @import("run_main_h2_trace.zig");
const run_main_deadline_trace = @import("run_main_deadline_trace.zig");
const run_main_h3_deadline_trace = @import("run_main_h3_deadline_trace.zig");
const run_main_h2_stall = @import("run_main_h2_stall.zig");
const run_main_client_trace = @import("run_main_client_trace.zig");
const run_main_tcp_trace = @import("run_main_tcp_trace.zig");
const run_main_endpoint = @import("run_main_endpoint.zig");
const connection_check = @import("connection_check.zig");
const tls_check = @import("tls_check.zig");
const h2_input_check = @import("h2_input_check.zig");
const h3_trace_check = @import("h3_trace_check.zig");
const h3_trace_state = @import("h3_trace_state.zig");
const h3_trace_tla = @import("h3_trace_tla.zig");
const quic = @import("quic");

const constants = sim.constants;

/// The exit status of a usage error, beside 0 for a pass and 1 for a failed seed.
const exit_usage = 2;

/// The storage each check writes into, placed outside any stack frame.
var chunk_storage: chunk_check.Storage align(@alignOf(chunk_check.Storage)) = .zeroed;
var connection_storage: connection_check.Storage align(@alignOf(connection_check.Storage)) = .zeroed;
var tls_storage: tls_check.Storage align(@alignOf(tls_check.Storage)) = .zeroed;
var h2_input_storage: h2_input_check.Storage align(@alignOf(h2_input_check.Storage)) = undefined;
var h3_trace_storage: h3_trace_check.Storage align(@alignOf(h3_trace_check.Storage)) = undefined;
var h3_trace_module: [constants.h3_trace.module_len_max]u8 = undefined;

pub fn main(init: std.process.Init) !void {
    var arguments: [run_main_command.arguments_max][]const u8 = @splat("");
    var count: usize = 0;
    var iterator = init.minimal.args.iterate();
    _ = iterator.next();
    const command = while (iterator.next()) |argument| {
        if (count == run_main_command.arguments_max) break error.Usage;
        arguments[count] = argument;
        count += 1;
    } else run_main_command.parse(arguments[0..count]);
    const parsed = command catch {
        std.debug.print(run_main_command.usage, .{});
        std.process.exit(exit_usage);
    };
    switch (parsed) {
        .chunk_seed => |seed| try chunk_seed(seed),
        .chunk_check => |seeds| try chunk_check_seeds(seeds),
        .connection_seed => |seed| try connection_seed(seed),
        .connection_check => |seeds| try connection_check_seeds(seeds),
        .tls_check => |seeds| try tls_check_seeds(seeds),
        .qpack_seed => |seed| try run_main_h3.qpack_seed(seed),
        .qpack_check => |seeds| try run_main_h3.qpack_check_seeds(seeds),
        .qpack_input_check => |seeds| try run_main_h3.qpack_input_check_seeds(seeds),
        .h2_input_check => |seeds| try h2_input_check_seeds(seeds),
        .h3_check => |seeds| try run_main_h3.h3_check_seeds(seeds, .normal),
        .h3_long_check => |seeds| try run_main_h3.h3_check_seeds(seeds, .long),
        .h3_trace_check => |seeds| try h3_trace_check_seeds(seeds),
        .h3_trace_write => |directory| try h3_trace_write(init.io, directory),
        .h2_trace_check => |seeds| try run_main_h2_trace.check(seeds),
        .h2_trace_write => |directory| try h2_trace_write(init.io, directory),
        .client_trace_seed => |seed| try run_main_client_trace.seed_trace(seed),
        .client_trace_check => |seeds| try run_main_client_trace.check(seeds),
        .client_trace_write => |directory| try client_trace_write(init.io, directory),
        .h11_split_seed => |seed| try run_main_h11.split_seed(seed),
        .h11_split_check => |seeds| try run_main_h11.split_check(seeds),
        .h11_connection_seed => |seed| try run_main_h11.connection_seed(seed),
        .h11_connection_check => |seeds| try run_main_h11.connection_check(seeds),
        .h11_coding_seed => |seed| try run_main_h11.coding_seed(seed),
        .h11_coding_check => |seeds| try run_main_h11.coding_check(seeds),
        .content_coding_seed => |seed| try run_main_content_coding.seed(seed),
        .content_coding_check => |seeds| try run_main_content_coding.check(seeds),
        .deadline_seed => |seed| try run_main_deadline.seed(seed),
        .deadline_check => |seeds| try run_main_deadline.check(seeds),
        .deadline_trace_check => |seeds| try run_main_deadline_trace.check(seeds),
        .deadline_trace_write => |directory| try deadline_trace_write(init.io, directory),
        .h3_deadline_seed => |seed| try run_main_h3_deadline.seed(seed),
        .h3_deadline_check => |seeds| try run_main_h3_deadline.check(seeds),
        .h3_deadline_trace_check => |seeds| try run_main_h3_deadline_trace.check(seeds),
        .h3_deadline_trace_write => |directory| try h3_deadline_trace_write(init.io, directory),
        .h2_stall_seed => |seed| try run_main_h2_stall.seed(seed),
        .h2_stall_check => |seeds| try run_main_h2_stall.check(seeds),
        .tcp_trace_check => |seeds| try run_main_tcp_trace.check(seeds),
        .tcp_trace_write => |directory| try tcp_trace_write(init.io, directory),
        .endpoint_seed => |seed| try run_main_endpoint.seed(seed),
        .endpoint_check => |seeds| try run_main_endpoint.check(seeds),
    }
}

fn chunk_seed(seed: u64) !void {
    const result = chunk_check.run_seed(&chunk_storage, seed) catch |failure| {
        std.debug.print("{s}", .{chunk_storage.chunked[0..whole_lines_len(&chunk_storage.chunked)]});
        std.debug.print("chunk: seed 0x{x} failed: {t}\n", .{ seed, failure });
        return failure;
    };
    std.debug.print("{s}chunk: seed 0x{x} outcome={t}\n", .{ result.trace, seed, result.outcome });
}

fn connection_seed(seed: u64) !void {
    const storage = &connection_storage;
    const result = connection_check.run_seed(storage, seed) catch |failure| {
        std.debug.print("{s}", .{storage.chunked[0..whole_lines_len(&storage.chunked)]});
        std.debug.print("connection: seed 0x{x} failed: {t}\n", .{ seed, failure });
        return failure;
    };
    const format = "{s}connection: seed 0x{x} outcome={t}\n";
    std.debug.print(format, .{ result.trace, seed, result.outcome });
}

/// The octets of `text` up to and including its last newline: the whole lines a trace holds.
fn whole_lines_len(text: []const u8) usize {
    const last = std.mem.lastIndexOfScalar(u8, text, '\n') orelse return 0;
    return last + 1;
}

fn chunk_check_seeds(seeds: u64) !void {
    var census: chunk_check.Census = .{};
    var failed_seed: ?u64 = null;
    chunk_check.run_check(&chunk_storage, seeds, &census, &failed_seed) catch |failure| {
        std.debug.print("chunk: seed 0x{x} failed: {t}; rerun it with --chunk-seed\n", .{
            failed_seed.?,
            failure,
        });
        return failure;
    };
    const census_format = "chunk: seeds={d} passed={d} rejected={d} chunks={d} trace_octets={d}" ++
        " crc32=0x{x:0>8}\n";
    std.debug.print(census_format, .{
        census.seeds,
        census.passed,
        census.rejected,
        census.chunks,
        census.trace_octets,
        census.crc32.final(),
    });
}

fn connection_check_seeds(seeds: u64) !void {
    var census: connection_check.Census = .{};
    var failed_seed: ?u64 = null;
    connection_check.run_check(&connection_storage, seeds, &census, &failed_seed) catch |failure| {
        std.debug.print("connection: seed 0x{x} failed: {t}; rerun it with --connection-seed\n", .{
            failed_seed.?,
            failure,
        });
        return failure;
    };
    const census_format = "connection: seeds={d} passed={d} rejected={d} frames={d} chunks={d}" ++
        " trace_octets={d} crc32=0x{x:0>8}\n";
    std.debug.print(census_format, .{
        census.seeds,
        census.passed,
        census.rejected,
        census.frames,
        census.chunks,
        census.trace_octets,
        census.crc32.final(),
    });
}

const testing = std.testing;

test {
    // The parser's tests, in the file it was split into.
    _ = run_main_command;
}

test "a failed seed prints only whole trace lines" {
    try testing.expectEqual(0, whole_lines_len("feed at_ns=0"));
    try testing.expectEqual("feed\n".len, whole_lines_len("feed\nacce"));
}

/// The TLS check of design §8 step 5's colibri side, over `[0, seeds)`.
fn tls_check_seeds(seeds: u64) !void {
    sim.NullProvider.install();
    var census: tls_check.Census = .{};
    var failed_seed: ?u64 = null;
    tls_check.run_check(&tls_storage, seeds, &census, &failed_seed) catch |failure| {
        std.debug.print("tls: seed 0x{x} failed: {t}\n", .{ failed_seed.?, failure });
        return failure;
    };
    std.debug.print("tls: seeds={d} events={d} crc32=0x{x:0>8}\n", .{
        census.seeds,
        census.events,
        census.crc32.final(),
    });
}

/// The h2 input check (https://github.com/c4milo/colibri/issues/53), over `[0, seeds)`.
fn h2_input_check_seeds(seeds: u64) !void {
    var census: h2_input_check.Census = .{};
    var failed_seed: ?u64 = null;
    h2_input_check.run_check(&h2_input_storage, seeds, &census, &failed_seed) catch |failure| {
        std.debug.print("h2-input: seed 0x{x} failed: {t}\n", .{ failed_seed.?, failure });
        return failure;
    };
    const outcomes = census.counts.outcomes;
    std.debug.print("h2-input: seeds={d} taken={d} incomplete={d} refused={d} frames={d} crc32=0x{x:0>8}\n", .{
        census.seeds,                                              outcomes[@intFromEnum(h2_input_check.Outcome.taken)],
        outcomes[@intFromEnum(h2_input_check.Outcome.incomplete)], outcomes[@intFromEnum(h2_input_check.Outcome.refused)],
        census.counts.frames_read,                                 census.crc32.final(),
    });
}

/// The h3 trace run of https://github.com/c4milo/colibri/issues/58, over `[0, seeds)`.
fn h3_trace_check_seeds(seeds: u64) !void {
    var census: h3_trace_check.Census = .{};
    var failed_seed: ?u64 = null;
    h3_trace_check.run_check(&h3_trace_storage, seeds, &census, &failed_seed) catch |failure| {
        std.debug.print("h3-trace: seed 0x{x} failed: {t}\n", .{ failed_seed.?, failure });
        return failure;
    };
    std.debug.print("h3-trace: seeds={d} requests={d} responses={d} rejections={d} cancels={d} goaways={d} inserts={d}\n", .{
        census.seeds,   census.requests, census.responses, census.rejections,
        census.cancels, census.goaways,  census.inserts,
    });
}

/// Writes seeds `[0, h3_trace.written_seeds)` of the h3 trace run into `directory`: a TLA+ module
/// holding each seed's trace, and the TLC configuration that checks it.
fn h3_trace_write(io: std.Io, directory: []const u8) !void {
    for (0..constants.h3_trace.written_seeds) |seed| {
        _ = h3_trace_check.run_seed(&h3_trace_storage, seed) catch |failure| {
            std.debug.print("h3-trace: seed 0x{x} failed: {t}\n", .{ seed, failure });
            return failure;
        };
        const scope: h3_trace_state.Scope = .of(&h3_trace_storage.plan);
        var name_storage: [constants.check_name_len_max]u8 = undefined;
        const name = h3_trace_tla.module_name(seed, &name_storage);
        var module = quic.core.Writer.init(&h3_trace_module);
        try h3_trace_tla.write_module(&module, name, scope, h3_trace_storage.trace());
        try write_file(io, directory, name, ".tla", module.written());
        var config = quic.core.Writer.init(&h3_trace_module);
        try h3_trace_tla.write_config(&config, scope, constants.h3_trace.steps_between_max);
        try write_file(io, directory, name, ".cfg", config.written());
    }
    std.debug.print("h3-trace: wrote {d} seeds to {s}\n", .{ constants.h3_trace.written_seeds, directory });
}

/// Writes seeds `[0, written_seeds)` of the h2 trace run into `directory`: a TLA+ module holding
/// each seed's trace, and the TLC configuration that checks it.
fn h2_trace_write(io: std.Io, directory: []const u8) !void {
    for (0..constants.h2_trace.written_seeds) |seed| {
        const files = try run_main_h2_trace.files_of(seed);
        try write_file(io, directory, files.name, ".tla", files.module);
        try write_file(io, directory, files.name, ".cfg", files.config);
    }
    std.debug.print("h2-trace: wrote {d} seeds to {s}\n", .{ constants.h2_trace.written_seeds, directory });
}

/// Writes seeds `[0, written_seeds)` of the client trace run into `directory`, as
/// `h2_trace_write` does for the h2 run (decision 105).
fn client_trace_write(io: std.Io, directory: []const u8) !void {
    const seeds = try run_main_client_trace.written_seeds(&client_trace_seeds);
    for (seeds) |seed| {
        const files = try run_main_client_trace.files_of(seed);
        try write_file(io, directory, files.name, ".tla", files.module);
        try write_file(io, directory, files.name, ".cfg", files.config);
    }
    std.debug.print("client-trace: wrote {d} seeds to {s}\n", .{ seeds.len, directory });
}

/// Writes seeds `[0, written_seeds)` of the deadline trace run into `directory`, as
/// `h2_trace_write` does for the h2 run (https://github.com/c4milo/colibri/issues/86).
fn deadline_trace_write(io: std.Io, directory: []const u8) !void {
    for (0..constants.deadline_trace.written_seeds) |seed| {
        const files = try run_main_deadline_trace.files_of(seed);
        try write_file(io, directory, files.name, ".tla", files.module);
        try write_file(io, directory, files.name, ".cfg", files.config);
    }
    std.debug.print("deadline-trace: wrote {d} seeds to {s}\n", .{ constants.deadline_trace.written_seeds, directory });
}

/// Writes seeds `[0, written_seeds)` of the h3 deadline trace run into `directory`, as
/// `deadline_trace_write` does for the h2 one (design §8 step 20d).
fn h3_deadline_trace_write(io: std.Io, directory: []const u8) !void {
    for (0..constants.h3_deadline_trace.written_seeds) |seed| {
        const files = try run_main_h3_deadline_trace.files_of(seed);
        try write_file(io, directory, files.name, ".tla", files.module);
        try write_file(io, directory, files.name, ".cfg", files.config);
    }
    std.debug.print("h3-deadline-trace: wrote {d} seeds to {s}\n", .{ constants.h3_deadline_trace.written_seeds, directory });
}

/// Writes seeds `[0, tcp_trace.written_seeds)` of the TCP trace run into `directory`: a TLA+ module
/// and a TLC configuration each, for `tools/tcp_trace.sh`.
fn tcp_trace_write(io: std.Io, directory: []const u8) !void {
    for (0..constants.tcp_trace.written_seeds) |seed| {
        const files = try run_main_tcp_trace.files_of(seed);
        try write_file(io, directory, files.name, ".tla", files.module);
        try write_file(io, directory, files.name, ".cfg", files.config);
    }
    std.debug.print("tcp-trace: wrote {d} seeds to {s}\n", .{ constants.tcp_trace.written_seeds, directory });
}

var client_trace_seeds: [constants.client_trace.written_seeds + constants.client_trace.idle_seeds_written_max]u64 = undefined;

fn write_file(io: std.Io, directory: []const u8, name: []const u8, extension: []const u8, data: []const u8) !void {
    var path_storage: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_storage, "{s}/{s}{s}", .{ directory, name, extension });
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = data });
}
