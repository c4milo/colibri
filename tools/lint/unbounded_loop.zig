//! unbounded-loop: every loop over peer-supplied counts is bounded by a named limit
//! (docs/invariants.md INV-8, CLAUDE.md non-negotiable 4). INV-8 names this file as its check and
//! `while (reader.remaining() > 0)` over a peer-controlled buffer as its violation.
//!
//! Over every `.zig` file under `src/`, the rule reports two shapes:
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

const std = @import("std");
const Ast = std.zig.Ast;
const Node = Ast.Node;
const ast = @import("ast.zig");
const paths = @import("paths.zig");
const report = @import("report.zig");

pub const name = "unbounded-loop";

/// The directory the rule reads.
const source_directory = "src";

/// The condition text of check 1.
const forever_condition = "true";

/// The condition of a loop that never runs. It is a literal, not a peer value, so check 2 skips
/// it the way it skips `true`.
const never_condition = "false";

/// A chain holding this segment names a limit from a module's `constants.zig`.
const bound_segment = "constants";

/// A chain whose last segment ends with this names a limit: `field_count_max`,
/// `streams_per_connection_max`.
const bound_name_suffix = "_max";

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

pub fn applies(path: []const u8) bool {
    if (!paths.has_extension(path, paths.zig_extension)) return false;
    return paths.is_under(path, source_directory);
}

pub fn check(context: *report.Context, file: report.File) !void {
    if (!applies(file.path)) return;
    const tree = file.tree orelse return;
    var visitor: Visitor = .{ .tree = tree, .findings = &context.findings, .path = file.path };
    for (tree.rootDecls()) |declaration| visitor.child(declaration);
    if (visitor.failure) |failure| return failure;
}

const Visitor = struct {
    tree: *const Ast,
    findings: *report.Findings,
    path: []const u8,
    depth: u32 = 0,
    failure: ?anyerror = null,

    pub fn child(self: *Visitor, node: Node.Index) void {
        self.depth += 1;
        defer self.depth -= 1;
        std.debug.assert(self.depth <= ast.max_tree_depth);
        self.visit(node) catch |failure| {
            self.failure = failure;
        };
    }

    fn visit(self: *Visitor, node: Node.Index) !void {
        if (ast.is_while(self.tree.nodeTag(node))) try self.visit_while(node);
        ast.for_each_child(self.tree, node, self);
    }

    fn visit_while(self: *Visitor, node: Node.Index) !void {
        const loop = self.tree.fullWhile(node).?;
        const scan = scan_loop(self.tree, loop);
        var buffer: [ast.max_chain_bytes]u8 = undefined;
        if (ast.chain_text(self.tree, loop.ast.cond_expr, &buffer)) |condition| {
            if (std.mem.eql(u8, condition, never_condition)) return;
            if (std.mem.eql(u8, condition, forever_condition)) return self.report_forever(node, scan);
            return;
        }
        if (scan.names_bound) return;
        var read_buffer: [ast.max_chain_bytes]u8 = undefined;
        const read = length_read_against_literal(self.tree, loop.ast.cond_expr, &read_buffer) orelse return;
        try self.add(
            node,
            "the condition reads {s} against a literal and the loop names no limit (invariant 8)",
            .{read},
        );
    }

    fn report_forever(self: *Visitor, node: Node.Index, scan: LoopScan) !void {
        if (!scan.has_break) {
            return self.add(node, "while (true) has no break; nothing ends the loop (invariant 8)", .{});
        }
        if (scan.names_bound) return;
        try self.add(
            node,
            "while (true) breaks on no named limit; bound it with a constants.zig value (invariant 8)",
            .{},
        );
    }

    fn add(self: *Visitor, node: Node.Index, comptime format: []const u8, arguments: anytype) !void {
        const location = ast.node_location(self.tree, node);
        try self.findings.add(name, self.path, location.line, location.column, format, arguments);
    }
};

/// What one loop's condition, continue expression and body hold: whether a `break` can end the
/// loop, and whether a named limit is mentioned anywhere in it.
const LoopScan = struct {
    tree: *const Ast,
    has_break: bool = false,
    names_bound: bool = false,
    depth: u32 = 0,

    pub fn child(self: *LoopScan, node: Node.Index) void {
        self.depth += 1;
        defer self.depth -= 1;
        std.debug.assert(self.depth <= ast.max_tree_depth);
        if (self.tree.nodeTag(node) == .@"break") self.has_break = true;
        var buffer: [ast.max_chain_bytes]u8 = undefined;
        if (ast.chain_text(self.tree, node, &buffer)) |chain| {
            // A chain holds no break and no further chain, so it is read whole and not descended
            // into.
            if (is_named_bound(chain)) self.names_bound = true;
            return;
        }
        ast.for_each_child(self.tree, node, self);
    }
};

fn scan_loop(tree: *const Ast, loop: Ast.full.While) LoopScan {
    var scan: LoopScan = .{ .tree = tree };
    scan.child(loop.ast.cond_expr);
    scan.child(loop.ast.then_expr);
    if (loop.ast.cont_expr.unwrap()) |continue_expression| scan.child(continue_expression);
    return scan;
}

/// True when the chain names a limit: a `constants.zig` value, or a name ending in `_max`.
fn is_named_bound(chain: []const u8) bool {
    if (ast.has_segment(chain, bound_segment)) return true;
    return std.mem.endsWith(u8, ast.last_segment(chain), bound_name_suffix);
}

fn is_comparison(tag: Node.Tag) bool {
    return switch (tag) {
        .less_than, .less_or_equal, .greater_than, .greater_or_equal, .equal_equal, .bang_equal => true,
        else => false,
    };
}

/// The length read of a comparison between a length and an integer literal, or null when the
/// condition is any other expression.
fn length_read_against_literal(
    tree: *const Ast,
    node: Node.Index,
    buffer: *[ast.max_chain_bytes]u8,
) ?[]const u8 {
    if (!is_comparison(tree.nodeTag(node))) return null;
    const left, const right = tree.nodeData(node).node_and_node;
    if (tree.nodeTag(right) == .number_literal) return length_read(tree, left, buffer);
    if (tree.nodeTag(left) == .number_literal) return length_read(tree, right, buffer);
    return null;
}

/// The chain of a length read: `reader.remaining` for the call `reader.remaining()`, `chunk.len`
/// for the field `chunk.len`. Null when the expression is anything else.
fn length_read(tree: *const Ast, node: Node.Index, buffer: *[ast.max_chain_bytes]u8) ?[]const u8 {
    const read = if (ast.is_call(tree.nodeTag(node))) ast.callee(tree, node) else node;
    const chain = ast.chain_text(tree, read, buffer) orelse return null;
    if (!is_length_reader(ast.last_segment(chain))) return null;
    return chain;
}

fn is_length_reader(segment: []const u8) bool {
    for (length_reader_names) |reader| {
        if (std.mem.eql(u8, segment, reader)) return true;
    }
    return false;
}

// Tests. Each fixture pins one shape from the header.

const testing = std.testing;
const harness = @import("harness.zig");

fn findings_of(
    arena: std.mem.Allocator,
    path: []const u8,
    source: [:0]const u8,
) ![]const report.Finding {
    return harness.run(arena, @This(), path, source);
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
    try testing.expect(applies("src/quic/quic.zig"));
    try testing.expect(!applies("tools/lint/main.zig"));
    try testing.expect(!applies("build/modules.zig"));
    try harness.expect_messages(try findings_of(arena, "tools/lint/main.zig", failing_fixture), &.{});
}
