//! The simulator's command line, split off `run.zig` so that the driver file names the checks and
//! this one holds the ways to ask for a run:
//!
//!     sim --chunk-seed <hex>           one seed: its chunked trace, then its outcome
//!     sim --chunk-check [seeds]         seeds [0, seeds): the census, or the seed that failed
//!     sim --connection-seed <hex>      the same, over one h2 connection (design §8 step 4)
//!     sim --connection-check [seeds]
//!     sim --qpack-seed <hex>           the same, over a QPACK encoder and decoder (step 11)
//!     sim --qpack-check [seeds]
//!     sim --qpack-input-check [seeds]  edited QPACK input, taken or refused (step 11)
//!     sim --h3-check [seeds]           h3 exchanges over a lossy network (step 12)
//!     sim --h3-long-check [seeds]      long h3 connections, which outgrow h3's buffers
//!     sim --h3-trace-check [seeds]     the h3 model's actions acted out (#58)
//!     sim --h3-trace-write <directory> each seed's trace as TLA+, for tools/h3_trace.sh
//!     sim --h11-split-seed <hex>       one seed's h11 messages read after a split (step 15a)
//!     sim --h11-split-check [seeds]
//!     sim --h11-connection-seed <hex>  one seed's h11 exchanges between a client and a server
//!     sim --h11-connection-check [seeds] (step 15b)
//!
//! It is the one file under `src/sim/` that reads its arguments and writes to the terminal, and
//! `tools/lint/io.zig` exempts it by path for that reason. Nothing reaches it but `zig build sim`.
const std = @import("std");
const sim = @import("sim");
const chunk_check = @import("chunk_check.zig");
const h11_split_check = @import("h11_split_check.zig");
const h11_exchange_check = @import("h11_exchange_check.zig");
const connection_check = @import("connection_check.zig");
const tls_check = @import("tls_check.zig");
const qpack_check = @import("qpack_check.zig");
const qpack_input_check = @import("qpack_input_check.zig");
const h3_check = @import("h3_check.zig");
const h3_trace_check = @import("h3_trace_check.zig");
const h3_trace_state = @import("h3_trace_state.zig");
const h3_trace_tla = @import("h3_trace_tla.zig");
const quic = @import("quic");

const constants = sim.constants;

/// The exit status of a usage error, beside 0 for a pass and 1 for a failed seed.
const exit_usage = 2;

/// Most arguments a command takes after the program name: a flag and its value.
const arguments_max = 2;

/// The base a seed is written in on the command line, with or without `0x`, and a seed count's.
const seed_radix = 16;
const count_radix = 10;
const hex_prefix = "0x";

const usage = "usage: sim --chunk-seed <hex> | --chunk-check [seeds]" ++
    " | --connection-seed <hex> | --connection-check [seeds] | --tls-check [seeds]" ++
    " | --qpack-seed <hex> | --qpack-check [seeds] | --qpack-input-check [seeds] | --h3-check [seeds] | --h3-long-check [seeds]" ++
    " | --h3-trace-check [seeds] | --h3-trace-write <directory>" ++
    " | --h11-split-seed <hex> | --h11-split-check [seeds]" ++
    " | --h11-connection-seed <hex> | --h11-connection-check [seeds]\n";

pub const Command = union(enum) {
    chunk_seed: u64,
    chunk_check: u64,
    connection_seed: u64,
    connection_check: u64,
    tls_check: u64,
    qpack_seed: u64,
    qpack_check: u64,
    qpack_input_check: u64,
    h3_check: u64,
    h3_long_check: u64,
    h3_trace_check: u64,
    h3_trace_write: []const u8,
    h11_split_seed: u64,
    h11_split_check: u64,
    h11_connection_seed: u64,
    h11_connection_check: u64,
};

/// The storage each check writes into, placed outside any stack frame.
var chunk_storage: chunk_check.Storage = .zeroed;
var connection_storage: connection_check.Storage = .zeroed;
var tls_storage: tls_check.Storage = .zeroed;
var qpack_storage: qpack_check.Storage = undefined;
var qpack_input_storage: qpack_input_check.Storage = undefined;
var h3_storage: h3_check.Storage = undefined;
var h3_trace_storage: h3_trace_check.Storage = undefined;
var h3_trace_module: [constants.h3_trace_module_len_max]u8 = undefined;
var h11_split_storage: h11_split_check.Storage = undefined;
var h11_exchange_storage: h11_exchange_check.Storage = undefined;

pub fn main(init: std.process.Init) !void {
    var arguments: [arguments_max][]const u8 = @splat("");
    var count: usize = 0;
    var iterator = init.minimal.args.iterate();
    _ = iterator.next();
    const command = while (iterator.next()) |argument| {
        if (count == arguments_max) break error.Usage;
        arguments[count] = argument;
        count += 1;
    } else parse(arguments[0..count]);
    const parsed = command catch {
        std.debug.print(usage, .{});
        std.process.exit(exit_usage);
    };
    switch (parsed) {
        .chunk_seed => |seed| try chunk_seed(seed),
        .chunk_check => |seeds| try chunk_check_seeds(seeds),
        .connection_seed => |seed| try connection_seed(seed),
        .connection_check => |seeds| try connection_check_seeds(seeds),
        .tls_check => |seeds| try tls_check_seeds(seeds),
        .qpack_seed => |seed| try qpack_seed(seed),
        .qpack_check => |seeds| try qpack_check_seeds(seeds),
        .qpack_input_check => |seeds| try qpack_input_check_seeds(seeds),
        .h3_check => |seeds| try h3_check_seeds(seeds, .normal),
        .h3_long_check => |seeds| try h3_check_seeds(seeds, .long),
        .h3_trace_check => |seeds| try h3_trace_check_seeds(seeds),
        .h3_trace_write => |directory| try h3_trace_write(init.io, directory),
        .h11_split_seed => |seed| try h11_split_seed(seed),
        .h11_split_check => |seeds| try h11_split_check_seeds(seeds),
        .h11_connection_seed => |seed| try h11_connection_seed(seed),
        .h11_connection_check => |seeds| try h11_connection_check_seeds(seeds),
    }
}

/// The command `arguments`, the program name left out, asks for.
pub fn parse(arguments: []const []const u8) error{Usage}!Command {
    if (arguments.len == 0 or arguments.len > arguments_max) return error.Usage;
    const value: ?[]const u8 = if (arguments.len == arguments_max) arguments[1] else null;
    const flag = arguments[0];
    if (std.mem.eql(u8, flag, "--chunk-seed")) return .{ .chunk_seed = try parse_seed(value) };
    if (std.mem.eql(u8, flag, "--chunk-check")) return .{ .chunk_check = try parse_seeds(value) };
    if (std.mem.eql(u8, flag, "--connection-seed")) {
        return .{ .connection_seed = try parse_seed(value) };
    }
    if (std.mem.eql(u8, flag, "--connection-check")) {
        return .{ .connection_check = try parse_seeds(value) };
    }
    // The TLS check writes no trace, so it has no single-seed form: what it compares is the
    // events of three runs of one seed, which the check itself prints when they differ.
    if (std.mem.eql(u8, flag, "--tls-check")) return .{ .tls_check = try parse_seeds(value) };
    return parse_step_eleven_on(flag, value);
}

/// The commands of the checks from design §8 step 11 on.
fn parse_step_eleven_on(flag: []const u8, value: ?[]const u8) error{Usage}!Command {
    if (std.mem.eql(u8, flag, "--qpack-seed")) return .{ .qpack_seed = try parse_seed(value) };
    if (std.mem.eql(u8, flag, "--qpack-check")) return .{ .qpack_check = try parse_seeds(value) };
    if (std.mem.eql(u8, flag, "--qpack-input-check")) return .{ .qpack_input_check = try parse_seeds(value) };
    if (std.mem.eql(u8, flag, "--h3-check")) return .{ .h3_check = try parse_seeds(value) };
    if (std.mem.eql(u8, flag, "--h3-long-check")) {
        return .{ .h3_long_check = if (value == null) constants.h3_long_check_seeds else try parse_seeds(value) };
    }
    if (std.mem.eql(u8, flag, "--h3-trace-check")) return .{ .h3_trace_check = try parse_seeds(value) };
    if (std.mem.eql(u8, flag, "--h3-trace-write")) return .{ .h3_trace_write = value orelse return error.Usage };
    if (std.mem.eql(u8, flag, "--h11-split-seed")) return .{ .h11_split_seed = try parse_seed(value) };
    if (std.mem.eql(u8, flag, "--h11-split-check")) return .{ .h11_split_check = try parse_seeds(value) };
    if (std.mem.eql(u8, flag, "--h11-connection-seed")) return .{ .h11_connection_seed = try parse_seed(value) };
    if (std.mem.eql(u8, flag, "--h11-connection-check")) return .{ .h11_connection_check = try parse_seeds(value) };
    return error.Usage;
}

/// A seed in hexadecimal, with or without `0x`: the form a trace's first line prints it in.
fn parse_seed(text: ?[]const u8) error{Usage}!u64 {
    const given = text orelse return error.Usage;
    const digits = if (std.mem.startsWith(u8, given, hex_prefix)) given[hex_prefix.len..] else given;
    return std.fmt.parseInt(u64, digits, seed_radix) catch error.Usage;
}

/// A seed count in decimal, or the default when the command line gives none.
fn parse_seeds(text: ?[]const u8) error{Usage}!u64 {
    const given = text orelse return constants.check_seeds_default;
    return std.fmt.parseInt(u64, given, count_radix) catch error.Usage;
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

fn h11_split_seed(seed: u64) !void {
    const result = h11_split_check.run_seed(&h11_split_storage, seed) catch |failure| {
        std.debug.print("h11-split: seed 0x{x} failed: {t}\n", .{ seed, failure });
        return failure;
    };
    std.debug.print("{s}", .{result.trace});
}

fn h11_split_check_seeds(seeds: u64) !void {
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

fn h11_connection_seed(seed: u64) !void {
    const result = h11_exchange_check.run_seed(&h11_exchange_storage, seed) catch |failure| {
        std.debug.print("h11-connection: seed 0x{x} failed: {t}\n", .{ seed, failure });
        return failure;
    };
    std.debug.print("{s}h11-connection: seed 0x{x} sent={d} steps={d}\n", .{ result.trace, seed, result.sent, result.steps });
}

fn h11_connection_check_seeds(seeds: u64) !void {
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

const testing = std.testing;

test "a seed parses in hexadecimal with or without 0x, and a check count in decimal" {
    const prefixed: Command = .{ .chunk_seed = 0xc0ffee };
    try testing.expectEqual(prefixed, try parse(&.{ "--chunk-seed", "0xc0ffee" }));
    try testing.expectEqual(Command{ .chunk_seed = 0x10 }, try parse(&.{ "--chunk-seed", "10" }));
    try testing.expectEqual(Command{ .chunk_check = 10 }, try parse(&.{ "--chunk-check", "10" }));
    const default: Command = .{ .chunk_check = constants.check_seeds_default };
    try testing.expectEqual(default, try parse(&.{"--chunk-check"}));
}

test "the connection check takes the same two forms" {
    const seed: Command = .{ .connection_seed = 0xbeef };
    try testing.expectEqual(seed, try parse(&.{ "--connection-seed", "0xbeef" }));
    try testing.expectEqual(Command{ .connection_check = 7 }, try parse(&.{ "--connection-check", "7" }));
    const default: Command = .{ .connection_check = constants.check_seeds_default };
    try testing.expectEqual(default, try parse(&.{"--connection-check"}));
    try testing.expectError(error.Usage, parse(&.{"--connection-seed"}));
    try testing.expectError(error.Usage, parse(&.{ "--connection-check", "0x10" }));
}

test "anything else is a usage error" {
    try testing.expectError(error.Usage, parse(&.{}));
    try testing.expectError(error.Usage, parse(&.{"--chunk-seed"}));
    try testing.expectError(error.Usage, parse(&.{ "--chunk-seed", "0xg" }));
    try testing.expectError(error.Usage, parse(&.{ "--chunk-check", "0x10" }));
    try testing.expectError(error.Usage, parse(&.{ "--seed", "10" }));
    try testing.expectError(error.Usage, parse(&.{ "--chunk-check", "10", "extra" }));
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

/// One seed of the QPACK check: its trace, then what it did.
fn qpack_seed(seed: u64) !void {
    const result = qpack_check.run_seed(&qpack_storage, seed) catch |failure| {
        std.debug.print("{s}", .{qpack_storage.first[0..whole_lines_len(&qpack_storage.first)]});
        std.debug.print("qpack: seed 0x{x} failed: {t}\n", .{ seed, failure });
        return failure;
    };
    const counts = result.counts;
    std.debug.print("{s}qpack: seed 0x{x} decoded={d} blocked={d} cancelled={d} inserts={d}\n", .{
        result.trace, seed, counts.decoded, counts.blocked, counts.cancelled, counts.inserts,
    });
}

/// The QPACK check of design §8 step 11, over `[0, seeds)`.
fn qpack_check_seeds(seeds: u64) !void {
    var census: qpack_check.Census = .{};
    var failed_seed: ?u64 = null;
    qpack_check.run_check(&qpack_storage, seeds, &census, &failed_seed) catch |failure| {
        std.debug.print("qpack: seed 0x{x} failed: {t}; rerun it with --qpack-seed\n", .{ failed_seed.?, failure });
        return failure;
    };
    const counts = census.counts;
    std.debug.print("qpack: seeds={d} decoded={d} lines={d} blocked={d} cancelled={d} inserts={d} octets={d}" ++
        " trace_octets={d} crc32=0x{x:0>8}\n", .{
        census.seeds,   counts.decoded, counts.lines,        counts.blocked,       counts.cancelled,
        counts.inserts, counts.octets,  census.trace_octets, census.crc32.final(),
    });
}

/// The QPACK input check of design §8 step 11, over `[0, seeds)`.
fn qpack_input_check_seeds(seeds: u64) !void {
    var census: qpack_input_check.Census = .{};
    var failed_seed: ?u64 = null;
    qpack_input_check.run_check(&qpack_input_storage, seeds, &census, &failed_seed) catch |failure| {
        std.debug.print("qpack-input: seed 0x{x} failed: {t}\n", .{ failed_seed.?, failure });
        return failure;
    };
    const counts = census.counts;
    std.debug.print("qpack-input: seeds={d} inputs={d} taken={d} blocked={d} refused={d} crc32=0x{x:0>8}\n", .{
        census.seeds, counts.inputs, counts.taken, counts.blocked, counts.refused, census.crc32.final(),
    });
}

/// The h3 check of design §8 step 12, over `[0, seeds)`, in the normal or the long shape.
fn h3_check_seeds(seeds: u64, shape: h3_check.Shape) !void {
    h3_storage.shape = shape;
    var census: h3_check.Census = .{};
    var failed_seed: ?u64 = null;
    h3_check.run_check(&h3_storage, seeds, &census, &failed_seed) catch |failure| {
        std.debug.print("{s}: seed 0x{x} failed: {t}\n", .{ label_of(shape), failed_seed.?, failure });
        return failure;
    };
    std.debug.print("{s}: seeds={d} exchanges={d} content={d} inserts={d} acknowledged_dropped={d} datagrams={d} dropped={d} crc32=0x{x:0>8}\n", .{
        label_of(shape),             census.seeds,     census.exchanges, census.content_len,   census.inserts,
        census.acknowledged_dropped, census.datagrams, census.dropped,   census.crc32.final(),
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

/// Writes seeds `[0, h3_trace_written_seeds)` of the h3 trace run into `directory`: a TLA+ module
/// holding each seed's trace, and the TLC configuration that checks it.
fn h3_trace_write(io: std.Io, directory: []const u8) !void {
    for (0..constants.h3_trace_written_seeds) |seed| {
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
        try h3_trace_tla.write_config(&config, scope, constants.h3_trace_steps_between_max);
        try write_file(io, directory, name, ".cfg", config.written());
    }
    std.debug.print("h3-trace: wrote {d} seeds to {s}\n", .{ constants.h3_trace_written_seeds, directory });
}

fn write_file(io: std.Io, directory: []const u8, name: []const u8, extension: []const u8, data: []const u8) !void {
    var path_storage: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_storage, "{s}/{s}{s}", .{ directory, name, extension });
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = data });
}

/// The name a census line starts with, which `tools/ci.sh` looks for.
fn label_of(shape: h3_check.Shape) []const u8 {
    return if (shape.exchanges_max == h3_check.Shape.long.exchanges_max) "h3-long" else "h3";
}
