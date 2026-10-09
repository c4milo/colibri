//! The simulator's command line, split off `run_main.zig` because a hand-written source file
//! stays at or under 500 lines (CLAUDE.md): the commands, and the parser that reads one.
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
//!     sim --h3-deadline-seed <hex>     one seed's peer against a server's deadlines over QUIC
//!     sim --h3-deadline-check [seeds]  (step 20c)
//!     sim --h3-deadline-trace-check [seeds] colibri's h3 endpoint in the h3 deadline model's terms
//!     sim --h3-deadline-trace-write <directory> each seed's trace as TLA+, for
//!                                      tools/h3_deadline_trace.sh (step 20d)
//!     sim --h2-stall-seed <hex>        one seed's h2 exchange over a small transport (#85)
//!     sim --h2-stall-check [seeds]
//!     sim --tcp-trace-check [seeds]    a client and a server connection in the h2 model's terms (#79)
//!     sim --tcp-trace-write <directory> each seed's trace as TLA+, for tools/tcp_trace.sh
//!
//! `run_main.zig` runs the command `parse` returns.
const std = @import("std");
const sim = @import("sim");

const constants = sim.constants;

/// Most arguments a command takes after the program name: a flag and its value.
pub const arguments_max = 2;

/// The base a seed is written in on the command line, with or without `0x`, and a seed count's.
const seed_radix = 16;
const count_radix = 10;
const hex_prefix = "0x";

pub const usage = "usage: sim --chunk-seed <hex> | --chunk-check [seeds]" ++
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
    " | --h3-deadline-seed <hex> | --h3-deadline-check [seeds]" ++
    " | --h3-deadline-trace-check [seeds] | --h3-deadline-trace-write <directory>" ++
    " | --h2-stall-seed <hex> | --h2-stall-check [seeds]" ++
    " | --tcp-trace-check [seeds] | --tcp-trace-write <directory>\n";

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
    h3_deadline_seed: u64,
    h3_deadline_check: u64,
    h3_deadline_trace_check: u64,
    h3_deadline_trace_write: []const u8,
    h2_stall_seed: u64,
    h2_stall_check: u64,
    tcp_trace_check: u64,
    tcp_trace_write: []const u8,
};

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

/// The commands of the h3 deadline check, decision 110 as amended (design §8 step 20c), and of its
/// trace run (step 20d).
fn parse_h3_deadline(flag: []const u8, value: ?[]const u8) error{Usage}!Command {
    if (std.mem.eql(u8, flag, "--h3-deadline-seed")) return .{ .h3_deadline_seed = try parse_seed(value) };
    if (std.mem.eql(u8, flag, "--h3-deadline-check")) return .{ .h3_deadline_check = if (value == null) constants.h3_deadline.check_seeds_default else try parse_seeds(value) };
    if (std.mem.eql(u8, flag, "--h3-deadline-trace-check")) return .{ .h3_deadline_trace_check = if (value == null) constants.h3_deadline_trace.written_seeds else try parse_seeds(value) };
    if (std.mem.eql(u8, flag, "--h3-deadline-trace-write")) return .{ .h3_deadline_trace_write = value orelse return error.Usage };
    return parse_h2_stall(flag, value);
}

/// The commands of the deadline check, decision 110, and of its trace run,
/// https://github.com/c4milo/colibri/issues/86.
fn parse_deadline(flag: []const u8, value: ?[]const u8) error{Usage}!Command {
    if (std.mem.eql(u8, flag, "--deadline-seed")) return .{ .deadline_seed = try parse_seed(value) };
    if (std.mem.eql(u8, flag, "--deadline-check")) return .{ .deadline_check = if (value == null) constants.deadline.check_seeds_default else try parse_seeds(value) };
    if (std.mem.eql(u8, flag, "--deadline-trace-check")) return .{ .deadline_trace_check = if (value == null) constants.deadline_trace.written_seeds else try parse_seeds(value) };
    if (std.mem.eql(u8, flag, "--deadline-trace-write")) return .{ .deadline_trace_write = value orelse return error.Usage };
    return parse_h3_deadline(flag, value);
}

/// The commands of the h2 stall check, https://github.com/c4milo/colibri/issues/85.
fn parse_h2_stall(flag: []const u8, value: ?[]const u8) error{Usage}!Command {
    if (std.mem.eql(u8, flag, "--h2-stall-seed")) return .{ .h2_stall_seed = try parse_seed(value) };
    if (std.mem.eql(u8, flag, "--h2-stall-check")) return .{ .h2_stall_check = if (value == null) constants.h2_stall.check_seeds_default else try parse_seeds(value) };
    return parse_tcp_trace(flag, value);
}

/// The commands of the TCP trace run, https://github.com/c4milo/colibri/issues/79.
fn parse_tcp_trace(flag: []const u8, value: ?[]const u8) error{Usage}!Command {
    if (std.mem.eql(u8, flag, "--tcp-trace-check")) return .{ .tcp_trace_check = if (value == null) constants.tcp_trace.written_seeds else try parse_seeds(value) };
    if (std.mem.eql(u8, flag, "--tcp-trace-write")) return .{ .tcp_trace_write = value orelse return error.Usage };
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
    const default_h3: Command = .{ .h3_deadline_check = constants.h3_deadline.check_seeds_default };
    try testing.expectEqual(default_h3, try parse(&.{"--h3-deadline-check"}));
}

test "anything else is a usage error" {
    try testing.expectError(error.Usage, parse(&.{}));
    try testing.expectError(error.Usage, parse(&.{"--chunk-seed"}));
    try testing.expectError(error.Usage, parse(&.{ "--chunk-seed", "0xg" }));
    try testing.expectError(error.Usage, parse(&.{ "--chunk-check", "0x10" }));
    try testing.expectError(error.Usage, parse(&.{ "--seed", "10" }));
    try testing.expectError(error.Usage, parse(&.{ "--chunk-check", "10", "extra" }));
}
