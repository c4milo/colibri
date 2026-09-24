//! The simulator's command line, split off `run.zig` so that the driver file names the checks and
//! this one holds the ways to ask for a run:
//!
//!     sim --chunk-seed <hex>           one seed: its chunked trace, then its outcome
//!     sim --chunk-check [seeds]         seeds [0, seeds): the census, or the seed that failed
//!     sim --connection-seed <hex>      the same, over one h2 connection (design §8 step 4)
//!     sim --connection-check [seeds]
//!     sim --qpack-seed <hex>           the same, over a QPACK encoder and decoder (step 11)
//!     sim --qpack-check [seeds]
//!
//! It is the one file under `src/sim/` that reads its arguments and writes to the terminal, and
//! `tools/lint/io.zig` exempts it by path for that reason. Nothing reaches it but `zig build sim`.
const std = @import("std");
const sim = @import("sim");
const chunk_check = @import("chunk_check.zig");
const connection_check = @import("connection_check.zig");
const tls_check = @import("tls_check.zig");
const qpack_check = @import("qpack_check.zig");

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
    " | --qpack-seed <hex> | --qpack-check [seeds]\n";

pub const Command = union(enum) {
    chunk_seed: u64,
    chunk_check: u64,
    connection_seed: u64,
    connection_check: u64,
    tls_check: u64,
    qpack_seed: u64,
    qpack_check: u64,
};

/// The storage each check writes into, placed outside any stack frame.
var chunk_storage: chunk_check.Storage = .zeroed;
var connection_storage: connection_check.Storage = .zeroed;
var tls_storage: tls_check.Storage = .zeroed;
var qpack_storage: qpack_check.Storage = undefined;

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
    if (std.mem.eql(u8, flag, "--qpack-seed")) return .{ .qpack_seed = try parse_seed(value) };
    if (std.mem.eql(u8, flag, "--qpack-check")) return .{ .qpack_check = try parse_seeds(value) };
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
