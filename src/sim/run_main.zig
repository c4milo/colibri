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
//!     sim --h2-input-check [seeds]     edited h2 frames, read, cut or refused (step 4)
//!     sim --h3-check [seeds]           h3 exchanges over a lossy network (step 12)
//!     sim --h3-long-check [seeds]      long h3 connections, which outgrow h3's buffers
//!     sim --h3-trace-check [seeds]     the h3 model's actions acted out (#58)
//!     sim --h3-trace-write <directory> each seed's trace as TLA+, for tools/h3_trace.sh
//!     sim --h2-trace-check [seeds]     the h2 model's actions acted out (#75)
//!     sim --h2-trace-write <directory> each seed's trace as TLA+, for tools/h2_trace.sh
//!     sim --client-trace-seed <hex>    one seed of the client model's exchanges, as TLA+ (17d)
//!     sim --client-trace-check [seeds]
//!     sim --client-trace-write <directory> each seed's trace as TLA+, for tools/client_trace.sh
//!     sim --h11-split-seed <hex>       one seed's h11 messages read after a split (step 15a)
//!     sim --h11-split-check [seeds]
//!     sim --h11-connection-seed <hex>  one seed's h11 exchanges between a client and a server
//!     sim --h11-connection-check [seeds] (step 15b)
//!     sim --h11-coding-seed <hex>      one seed's gzip and deflate bodies an h11 connection decodes
//!     sim --h11-coding-check [seeds]   (step 15c)
//!     sim --content-coding-seed <hex>  one seed's content codings, client to server
//!     sim --content-coding-check [seeds] (step 17e)
//!     sim --deadline-seed <hex>        one seed's peer against a server's deadlines (step 20b)
//!     sim --deadline-check [seeds]
//!     sim --deadline-trace-check [seeds] colibri's endpoints in the deadline model's terms (#86)
//!     sim --deadline-trace-write <directory> each seed's trace as TLA+, for tools/deadline_trace.sh
//!     sim --h2-stall-seed <hex>        one seed's h2 exchange over a small transport (#85)
//!     sim --h2-stall-check [seeds]
//!
//! The h11 commands are in `run_main_h11.zig`, and the QPACK and h3 ones in `run_main_h3.zig`,
//! split off for length.
//!
//! It is the one file under `src/sim/` that reads its arguments and writes to the terminal, and
//! `tools/lint/io.zig` exempts it by path for that reason. Nothing reaches it but `zig build sim`.
const std = @import("std");
const sim = @import("sim");
const chunk_check = @import("chunk_check.zig");
const run_main_h11 = @import("run_main_h11.zig");
const run_main_content_coding = @import("run_main_content_coding.zig");
const run_main_h3 = @import("run_main_h3.zig");
const run_main_deadline = @import("run_main_deadline.zig");
const run_main_h2_trace = @import("run_main_h2_trace.zig");
const run_main_deadline_trace = @import("run_main_deadline_trace.zig");
const run_main_h2_stall = @import("run_main_h2_stall.zig");
const run_main_client_trace = @import("run_main_client_trace.zig");
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

/// Most arguments a command takes after the program name: a flag and its value.
const arguments_max = 2;

/// The base a seed is written in on the command line, with or without `0x`, and a seed count's.
const seed_radix = 16;
const count_radix = 10;
const hex_prefix = "0x";

const usage = "usage: sim --chunk-seed <hex> | --chunk-check [seeds]" ++
    " | --connection-seed <hex> | --connection-check [seeds] | --tls-check [seeds]" ++
    " | --qpack-seed <hex> | --qpack-check [seeds] | --qpack-input-check [seeds] | --h2-input-check [seeds] | --h3-check [seeds] | --h3-long-check [seeds]" ++
    " | --h3-trace-check [seeds] | --h3-trace-write <directory>" ++
    " | --h2-trace-check [seeds] | --h2-trace-write <directory>" ++
    " | --client-trace-seed <hex> | --client-trace-check [seeds] | --client-trace-write <directory>" ++
    " | --h11-split-seed <hex> | --h11-split-check [seeds]" ++
    " | --h11-connection-seed <hex> | --h11-connection-check [seeds]" ++
    " | --h11-coding-seed <hex> | --h11-coding-check [seeds] | --content-coding-seed <hex> | --content-coding-check [seeds]" ++
    " | --deadline-seed <hex> | --deadline-check [seeds]" ++
    " | --deadline-trace-check [seeds] | --deadline-trace-write <directory>" ++
    " | --h2-stall-seed <hex> | --h2-stall-check [seeds]\n";

pub const Command = union(enum) {
    chunk_seed: u64,
    chunk_check: u64,
    connection_seed: u64,
    connection_check: u64,
    tls_check: u64,
    qpack_seed: u64,
    qpack_check: u64,
    qpack_input_check: u64,
    h2_input_check: u64,
    h3_check: u64,
    h3_long_check: u64,
    h3_trace_check: u64,
    h3_trace_write: []const u8,
    h2_trace_check: u64,
    h2_trace_write: []const u8,
    client_trace_seed: u64,
    client_trace_check: u64,
    client_trace_write: []const u8,
    h11_split_seed: u64,
    h11_split_check: u64,
    h11_connection_seed: u64,
    h11_connection_check: u64,
    h11_coding_seed: u64,
    h11_coding_check: u64,
    content_coding_seed: u64,
    content_coding_check: u64,
    deadline_seed: u64,
    deadline_check: u64,
    deadline_trace_check: u64,
    deadline_trace_write: []const u8,
    h2_stall_seed: u64,
    h2_stall_check: u64,
};

/// The storage each check writes into, placed outside any stack frame.
var chunk_storage: chunk_check.Storage align(@alignOf(chunk_check.Storage)) = .zeroed;
var connection_storage: connection_check.Storage align(@alignOf(connection_check.Storage)) = .zeroed;
var tls_storage: tls_check.Storage align(@alignOf(tls_check.Storage)) = .zeroed;
var h2_input_storage: h2_input_check.Storage align(@alignOf(h2_input_check.Storage)) = undefined;
var h3_trace_storage: h3_trace_check.Storage align(@alignOf(h3_trace_check.Storage)) = undefined;
var h3_trace_module: [constants.h3_trace_module_len_max]u8 = undefined;

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
        .h2_stall_seed => |seed| try run_main_h2_stall.seed(seed),
        .h2_stall_check => |seeds| try run_main_h2_stall.check(seeds),
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
    if (std.mem.eql(u8, flag, "--h2-input-check")) return .{ .h2_input_check = try parse_seeds(value) };
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
    return parse_h11(flag, value);
}

/// The commands of the h11 checks, design §8 step 15.
fn parse_h11(flag: []const u8, value: ?[]const u8) error{Usage}!Command {
    if (std.mem.eql(u8, flag, "--h11-split-seed")) return .{ .h11_split_seed = try parse_seed(value) };
    if (std.mem.eql(u8, flag, "--h11-split-check")) return .{ .h11_split_check = try parse_seeds(value) };
    if (std.mem.eql(u8, flag, "--h11-connection-seed")) return .{ .h11_connection_seed = try parse_seed(value) };
    if (std.mem.eql(u8, flag, "--h11-connection-check")) return .{ .h11_connection_check = try parse_seeds(value) };
    if (std.mem.eql(u8, flag, "--h11-coding-seed")) return .{ .h11_coding_seed = try parse_seed(value) };
    if (std.mem.eql(u8, flag, "--h11-coding-check")) return .{ .h11_coding_check = try parse_seeds(value) };
    if (std.mem.eql(u8, flag, "--content-coding-seed")) return .{ .content_coding_seed = try parse_seed(value) };
    if (std.mem.eql(u8, flag, "--content-coding-check")) return .{ .content_coding_check = if (value == null) constants.content_coding.check_seeds_default else try parse_seeds(value) };
    return parse_h2_trace(flag, value);
}

/// The commands of the h2 trace run, https://github.com/c4milo/colibri/issues/75, and of the client
/// trace run, decision 105.
fn parse_h2_trace(flag: []const u8, value: ?[]const u8) error{Usage}!Command {
    if (std.mem.eql(u8, flag, "--h2-trace-check")) return .{ .h2_trace_check = try parse_seeds(value) };
    if (std.mem.eql(u8, flag, "--h2-trace-write")) return .{ .h2_trace_write = value orelse return error.Usage };
    if (std.mem.eql(u8, flag, "--client-trace-seed")) return .{ .client_trace_seed = try parse_seed(value) };
    if (std.mem.eql(u8, flag, "--client-trace-check")) return .{ .client_trace_check = try parse_seeds(value) };
    if (std.mem.eql(u8, flag, "--client-trace-write")) return .{ .client_trace_write = value orelse return error.Usage };
    return parse_deadline(flag, value);
}

/// The commands of the deadline check, decision 110, and of its trace run,
/// https://github.com/c4milo/colibri/issues/86.
fn parse_deadline(flag: []const u8, value: ?[]const u8) error{Usage}!Command {
    if (std.mem.eql(u8, flag, "--deadline-seed")) return .{ .deadline_seed = try parse_seed(value) };
    if (std.mem.eql(u8, flag, "--deadline-check")) return .{ .deadline_check = if (value == null) constants.deadline.check_seeds_default else try parse_seeds(value) };
    if (std.mem.eql(u8, flag, "--deadline-trace-check")) return .{ .deadline_trace_check = if (value == null) constants.deadline_trace.written_seeds else try parse_seeds(value) };
    if (std.mem.eql(u8, flag, "--deadline-trace-write")) return .{ .deadline_trace_write = value orelse return error.Usage };
    return parse_h2_stall(flag, value);
}

/// The commands of the h2 stall check, https://github.com/c4milo/colibri/issues/85.
fn parse_h2_stall(flag: []const u8, value: ?[]const u8) error{Usage}!Command {
    if (std.mem.eql(u8, flag, "--h2-stall-seed")) return .{ .h2_stall_seed = try parse_seed(value) };
    if (std.mem.eql(u8, flag, "--h2-stall-check")) return .{ .h2_stall_check = if (value == null) constants.h2_stall.check_seeds_default else try parse_seeds(value) };
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

test "the content-coding check runs the seeds its census test pins when given no count" {
    const default: Command = .{ .content_coding_check = constants.content_coding.check_seeds_default };
    try testing.expectEqual(default, try parse(&.{"--content-coding-check"}));
}

test "the deadline check runs the seeds its census test pins when given no count" {
    const default: Command = .{ .deadline_check = constants.deadline.check_seeds_default };
    try testing.expectEqual(default, try parse(&.{"--deadline-check"}));
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

var client_trace_seeds: [constants.client_trace.written_seeds + constants.client_trace.idle_seeds_written_max]u64 = undefined;

fn write_file(io: std.Io, directory: []const u8, name: []const u8, extension: []const u8, data: []const u8) !void {
    var path_storage: [std.fs.max_path_bytes]u8 = undefined;
    const path = try std.fmt.bufPrint(&path_storage, "{s}/{s}{s}", .{ directory, name, extension });
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = data });
}
