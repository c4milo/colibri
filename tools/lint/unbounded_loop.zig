//! unbounded-loop: every loop over peer-supplied counts is bounded by a named limit
//! (docs/invariants.md INV-8, CLAUDE.md non-negotiable 4). INV-8 names this file as its check and
//! `while (reader.remaining() > 0)` over a peer-controlled buffer as its violation.
//!
//! Over every `.zig` file under `src/` but not under `src/testing/`, the rule reports two shapes:
//!   1. `while (true)`. With no `break` anywhere in the body, nothing ends the loop at all. With a
//!      `break` but no named limit anywhere in the loop, a peer decides how many iterations run
//!      before the break fires.
//!   2. a condition that compares a length read against an integer literal, with no named limit
//!      anywhere in the loop: `while (reader.remaining() > 0)`, `while (chunk.len != 0)`. A length
//!      read is a call or a field whose last name is one of `length_reader_names`.
//!
//! A named limit is a chain holding the segment `constants` or ending in `_max`, which is how
//! INV-8 says a bound is written: read from a `constants.zig` value, never from a literal and
//! never from the peer's value alone. Finding one anywhere in the loop's condition, continue
//! expression or body is what clears the loop.
//!
//! What the rule cannot do. It reads the shape of the source, not its arithmetic, so it cannot
//! prove that a named limit it found is the thing bounding the trip count — a loop that mentions
//! `constants.field_count_max` for any reason passes check 1 and check 2. It does not follow a
//! bound through a local: `const limit = constants.field_count_max;` in one function and
//! `while (index < limit)` in another reads as a bare identifier and is not checked. It says
//! nothing about `for` loops, which iterate a slice whose length is already fixed, and nothing
//! about a `while` whose condition is any other expression — `while (index < count)`,
//! `while (iterator.next()) |item|` and `while (!done)` are all outside both checks. A loop it
//! passes is therefore not proved bounded; the runtime assertion INV-8 asks for is what proves
//! that, and this rule catches the two shapes that are unbounded on their face.
//!
//! The rule is pepegrillo's `unbounded_loop` (decision 36). This file holds colibri's configuration of it
//! and the fixtures that pin that configuration.

const std = @import("std");
const pepegrillo = @import("pepegrillo");
const lint = pepegrillo.lint;
const unbounded_loop = lint.rules.unbounded_loop;

/// The last name of a length read. A call or a field with one of these names, compared against an
/// integer literal, is the shape of check 2.
const length_reader_names = [_][]const u8{
    "remaining",
    "len",
    "size",
    "count",
    "bytes_remaining",
    "bytes_left",
};

/// The configuration. It reads `src/`. A chain holding the segment `constants` names a limit from
/// a module's `constants.zig`, and a chain whose last segment ends with `_max` names a limit:
/// `field_count_max`, `streams_per_connection_max`. pepegrillo numbers the length-read check 3;
/// the header above calls it check 2.
pub const config: unbounded_loop.Config = .{
    .scope = .{
        .extensions = &.{lint.paths.zig_extension},
        .include_directories = &.{"src"},
        // `src/testing/` holds the test-only endpoints of docs/design.md §9, which own the socket
        // the `io` rule exempts them for. Their accept loop and their per-connection read loop run
        // until the operator stops the process or the peer closes, and neither trip count is a
        // peer-supplied count, which is what INV-8 bounds. Every other file under `src/` is read.
        .exclude_directories = &.{"src/testing"},
    },
    .forever = .unless_bounded_break,
    .length_read = true,
    .bound = .{ .segments = &.{"constants"}, .last_segment_suffixes = &.{"_max"} },
    .length_reader_names = &length_reader_names,
    .messages = .{
        .forever_without_break = "while (true) has no break; nothing ends the loop (invariant 8)",
        .forever_without_bound = "while (true) breaks on no named limit;" ++
            " bound it with a constants.zig value (invariant 8)",
        .length_read = "the condition reads {[read]s} against a literal" ++
            " and the loop names no limit (invariant 8)",
    },
};

const Rule = unbounded_loop.Rule(config);
pub const name = Rule.name;
pub const check = Rule.check;

// Tests. Each fixture pins one shape from the header.

const testing = std.testing;
const harness = lint.harness;

fn findings_of(
    arena: std.mem.Allocator,
    path: []const u8,
    source: [:0]const u8,
) ![]const lint.report.Finding {
    return harness.run(arena, Rule, path, source);
}

const passing_fixture: [:0]const u8 =
    \\const constants = @import("constants.zig");
    \\
    \\/// RFC 9113 §6.5: every setting in the payload, capped by the named limit.
    \\pub fn read_settings(self: *Connection, reader: *Reader) !void {
    \\    var read: u32 = 0;
    \\    while (reader.remaining() > 0) {
    \\        if (read == constants.settings_count_max) return error.TooManySettings;
    \\        try self.apply(try reader.read_setting());
    \\        read += 1;
    \\    }
    \\}
    \\
    \\pub fn drain(self: *Connection) void {
    \\    var index: u32 = 0;
    \\    while (true) {
    \\        if (index == constants.streams_per_connection_max) break;
    \\        self.streams[index].reset();
    \\        index += 1;
    \\    }
    \\}
;

const failing_fixture: [:0]const u8 =
    \\pub fn read_settings(self: *Connection, reader: *Reader) !void {
    \\    while (reader.remaining() > 0) {
    \\        try self.apply(try reader.read_setting());
    \\    }
    \\}
    \\
    \\pub fn spin(self: *Connection) void {
    \\    while (true) {
    \\        self.step();
    \\    }
    \\}
;

test "unbounded-loop passes loops a named limit bounds" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try findings_of(arena_state.allocator(), "src/h2/settings.zig", passing_fixture);
    try harness.expect_messages(findings, &.{});
}

test "unbounded-loop flags a peer length read and a while (true) with no break" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try findings_of(arena_state.allocator(), "src/h2/settings.zig", failing_fixture);
    try harness.expect_messages(findings, &.{
        "the condition reads reader.remaining against a literal and the loop names no limit (invariant 8)",
        "while (true) has no break; nothing ends the loop (invariant 8)",
    });
    try testing.expectEqual(2, findings[0].line);
    try testing.expectEqual(8, findings[1].line);
}

test "unbounded-loop flags a while (true) whose break rests on no named limit" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try findings_of(arena_state.allocator(), "src/h2/settings.zig",
        \\pub fn drain(self: *Connection, reader: *Reader) void {
        \\    while (true) {
        \\        const frame = reader.next() orelse break;
        \\        self.apply(frame);
        \\    }
        \\}
    );
    try harness.expect_messages(findings, &.{
        "while (true) breaks on no named limit; bound it with a constants.zig value (invariant 8)",
    });
}

test "unbounded-loop flags a length field compared to a literal" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try findings_of(arena_state.allocator(), "src/hpack/hpack.zig",
        \\pub fn decode(self: *Table, chunk: []const u8) void {
        \\    while (chunk.len != 0) {
        \\        chunk = self.entry(chunk);
        \\    }
        \\    while (0 < self.entries.count()) {
        \\        self.evict();
        \\    }
        \\}
    );
    try harness.expect_messages(findings, &.{
        "the condition reads chunk.len against a literal and the loop names no limit (invariant 8)",
        "the condition reads self.entries.count against a literal and the loop names no limit (invariant 8)",
    });
}

test "unbounded-loop leaves every other condition alone" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try findings_of(arena_state.allocator(), "src/wire/wire.zig",
        \\pub fn scan(iterator: anytype, count: u32, done: bool) void {
        \\    var index: u32 = 0;
        \\    while (index < count) : (index += 1) {}
        \\    while (iterator.next()) |item| _ = item;
        \\    while (!done) {}
        \\    while (false) {}
        \\    for (0..count) |i| _ = i;
        \\    while (index < buffer.len) : (index += 1) {}
        \\}
    );
    try harness.expect_messages(findings, &.{});
}

test "unbounded-loop accepts a constants.zig value whose name does not end in _max" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try findings_of(arena_state.allocator(), "src/quic/quic.zig",
        \\pub fn reassemble(self: *Connection, reader: *Reader) void {
        \\    while (true) {
        \\        if (self.depth == constants.reassembly_depth) break;
        \\        self.step();
        \\    }
        \\}
    );
    try harness.expect_messages(findings, &.{});
}

test "unbounded-loop accepts a _max name reached without the constants root" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try findings_of(arena_state.allocator(), "src/quic/quic.zig",
        \\pub fn drain(self: *Connection, reader: *Reader) void {
        \\    var read: u32 = 0;
        \\    while (reader.remaining() > 0) : (read = @min(read + 1, ack_ranges_max)) {
        \\        self.step();
        \\    }
        \\}
    );
    try harness.expect_messages(findings, &.{});
}

test "unbounded-loop reads src/ alone" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try testing.expect(config.scope.applies("src/quic/quic.zig"));
    try testing.expect(!config.scope.applies("tools/lint/main.zig"));
    try testing.expect(!config.scope.applies("build/modules.zig"));
    try harness.expect_messages(try findings_of(arena, "tools/lint/main.zig", failing_fixture), &.{});
}

test "unbounded-loop reads every length reader name on its list" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try findings_of(arena_state.allocator(), "src/h2/settings.zig",
        \\pub fn drain(self: *Connection, reader: *Reader, chunk: []const u8) void {
        \\    while (reader.remaining() > 0) self.step();
        \\    while (chunk.len != 0) self.step();
        \\    while (reader.size() > 0) self.step();
        \\    while (self.entries.count() > 0) self.step();
        \\    while (reader.bytes_remaining > 0) self.step();
        \\    while (reader.bytes_left() != 0) self.step();
        \\    while (reader.total() != 0) self.step();
        \\}
    );
    const suffix = " against a literal and the loop names no limit (invariant 8)";
    try harness.expect_messages(findings, &.{
        "the condition reads reader.remaining" ++ suffix,
        "the condition reads chunk.len" ++ suffix,
        "the condition reads reader.size" ++ suffix,
        "the condition reads self.entries.count" ++ suffix,
        "the condition reads reader.bytes_remaining" ++ suffix,
        "the condition reads reader.bytes_left" ++ suffix,
    });
}
