//! magic-numbers: every limit is named in a constant and never written inline (CLAUDE.md
//! non-negotiable 4).
//!
//! Over every `.zig` file under `src/`, the rule reports an integer literal greater than 1 unless
//! it is the whole value of a `const` declaration or a container field, which names it. `test` and
//! `comptime` blocks are not read: a test states the numbers it checks, and a layout assert checks
//! a number rather than using one as a limit. A fuzz property function is not a `test` block, so
//! its input size is named at file level.
//!
//! Four kinds of file are not read, because each is a table of numbers rather than code that uses
//! one:
//!
//! - `constants.zig`, where the names live.
//! - `huffman_table.zig`, which `zig build huffman-table` generates from RFC 7541 Appendix B.
//! - `src/golden/corpus_cases.zig`, the octets and values the corpus cases are built from.
//! - `src/golden/mutations.zig`, the offsets and octets each corpus mutation writes.
//!
//! The width of an octet is `@bitSizeOf(u8)`, never 8, so a shift by a whole octet names what it
//! shifts by.
//!
//! The rule is pepegrillo's `magic_numbers` (decision 36). This file holds colibri's configuration
//! of it and the fixtures that pin that configuration.

const std = @import("std");
const pepegrillo = @import("pepegrillo");
const lint = pepegrillo.lint;
const magic_numbers = lint.rules.magic_numbers;

/// The configuration: `.zig` files under `src/`, but for the tables the header names.
pub const config: magic_numbers.Config = .{
    .scope = .{
        .extensions = &.{lint.paths.zig_extension},
        .include_directories = &.{"src"},
        .exclude_basenames = &.{ "constants.zig", "huffman_table.zig" },
        .exclude_paths = &.{ "src/golden/corpus_cases.zig", "src/golden/mutations.zig" },
    },
};

const Rule = magic_numbers.Rule(config);
pub const name = Rule.name;
pub const check = Rule.check;

// Tests. Each fixture pins one shape from the header.

const testing = std.testing;
const harness = lint.harness;

fn expect_findings(path: []const u8, source: [:0]const u8, expected: []const []const u8) !void {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try harness.run(arena_state.allocator(), Rule, path, source);
    try harness.expect_messages(findings, expected);
}

const failing_fixture: [:0]const u8 =
    \\pub fn decode(octets: []const u8) u64 {
    \\    var value: u64 = 0;
    \\    for (octets) |octet| value = (value << 8) | octet;
    \\    var buffer: [16]u8 = @splat(0);
    \\    _ = &buffer;
    \\    return value;
    \\}
;

test "magic-numbers passes named constants, the octet width, tests and comptime asserts" {
    try expect_findings("src/wire/varint.zig",
        \\const length_bits = 2;
        \\const fuzz_input_len_max = 32;
        \\pub fn decode(octets: []const u8) u64 {
        \\    var value: u64 = 0;
        \\    for (octets) |octet| value = (value << @bitSizeOf(u8)) | octet;
        \\    var buffer: [fuzz_input_len_max]u8 = @splat(0);
        \\    _ = &buffer;
        \\    comptime std.debug.assert(length_bits * 4 == 8);
        \\    return value + 1;
        \\}
        \\test "eight" {
        \\    try std.testing.expectEqual(8, decode(&.{ 0, 8 }));
        \\}
    , &.{});
}

test "magic-numbers flags an inline shift width and an inline array length" {
    try expect_findings("src/wire/varint.zig", failing_fixture, &.{
        "integer literal 8",
        "integer literal 16",
    });
}

test "magic-numbers reads src/ but not its constants or its tables" {
    try expect_findings("src/quic/quic.zig", failing_fixture, &.{
        "integer literal 8",
        "integer literal 16",
    });
    try expect_findings("src/golden/corpus.zig", failing_fixture, &.{
        "integer literal 8",
        "integer literal 16",
    });
    try expect_findings("src/wire/constants.zig", failing_fixture, &.{});
    try expect_findings("src/wire/huffman_table.zig", failing_fixture, &.{});
    try expect_findings("src/golden/corpus_cases.zig", failing_fixture, &.{});
    try expect_findings("src/golden/mutations.zig", failing_fixture, &.{});
    try expect_findings("tools/golden.zig", failing_fixture, &.{});
    try expect_findings("build/modules.zig", failing_fixture, &.{});
}
