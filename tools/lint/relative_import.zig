//! relative-import: a module reaches another module by the name build/modules.zig gives it, never
//! by a path (CLAUDE.md, Layout). A module can `@import` only what the build hands it, so the
//! dependency direction is enforced by the build and not by review — and an `@import` that climbs
//! out of its own directory reaches past the build and takes that away.
//!
//! Over every `.zig` file under `src/`, the rule flags an `@import` whose path holds `../`, and an
//! `@import` of an absolute path, which names a machine rather than a tree. A file reaching a
//! sibling or a subdirectory of its own module is untouched: `@import("frame_header.zig")` and
//! `@import("packet/header.zig")` stay inside the module whose root build/modules.zig named.
//!
//! The rule reads the literal string only. `@import(module_name)` with a computed name is
//! invisible to it, as is `@embedFile`, which the rule ignores on purpose: a corpus file lives
//! beside the module that reads it and is not a module edge.

const std = @import("std");
const Ast = std.zig.Ast;
const Node = Ast.Node;
const ast = @import("ast.zig");
const paths = @import("paths.zig");
const report = @import("report.zig");

pub const name = "relative-import";

/// The directory the rule reads.
const source_directory = "src";

/// The segment that climbs out of the importing file's directory.
const parent_segment = "../";

/// The first byte of an absolute path.
const absolute_root: u8 = '/';

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
        if (ast.imported_path(self.tree, node)) |imported| {
            if (leaves_the_module(imported)) {
                const location = ast.node_location(self.tree, node);
                try self.findings.add(
                    name,
                    self.path,
                    location.line,
                    location.column,
                    "@import(\"{s}\") reaches out of the module by path;" ++
                        " import the module name build/modules.zig declares",
                    .{imported},
                );
            }
        }
        ast.for_each_child(self.tree, node, self);
    }
};

/// True when the imported path climbs above the importing file's directory or names an absolute
/// location.
fn leaves_the_module(imported: []const u8) bool {
    if (imported.len == 0) return false;
    if (imported[0] == absolute_root) return true;
    return std.mem.indexOf(u8, imported, parent_segment) != null;
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
    \\const std = @import("std");
    \\const core = @import("core");
    \\const wire = @import("wire");
    \\const constants = @import("constants.zig");
    \\const header = @import("packet/packet_header.zig");
    \\const corpus = @embedFile("../golden/settings.bin");
;

const failing_fixture: [:0]const u8 =
    \\const core = @import("../core/core.zig");
    \\const wire = @import("../../src/wire/wire.zig");
    \\const pinned = @import("/Users/someone/colibri/src/core/core.zig");
;

test "relative-import passes module names, siblings and subdirectories" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try findings_of(arena_state.allocator(), "src/quic/quic.zig", passing_fixture);
    try harness.expect_messages(findings, &.{});
}

test "relative-import flags a parent path and an absolute path" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try findings_of(arena_state.allocator(), "src/quic/quic.zig", failing_fixture);
    try harness.expect_messages(findings, &.{
        "@import(\"../core/core.zig\") reaches out of the module by path;" ++
            " import the module name build/modules.zig declares",
        "@import(\"../../src/wire/wire.zig\") reaches out of the module by path;" ++
            " import the module name build/modules.zig declares",
        "@import(\"/Users/someone/colibri/src/core/core.zig\") reaches out of the module by path;" ++
            " import the module name build/modules.zig declares",
    });
    try testing.expectEqual(1, findings[0].line);
}

test "relative-import flags an @import nested inside an expression" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try findings_of(arena_state.allocator(), "src/h3/h3.zig",
        \\const Head = @import("../h2/frame.zig").Head;
        \\fn read() void {
        \\    const table = @import("../hpack/table.zig").Table;
        \\    _ = table;
        \\}
    );
    try harness.expect_messages(findings, &.{
        "@import(\"../h2/frame.zig\") reaches out of the module by path;" ++
            " import the module name build/modules.zig declares",
        "@import(\"../hpack/table.zig\") reaches out of the module by path;" ++
            " import the module name build/modules.zig declares",
    });
    try testing.expectEqual(3, findings[1].line);
}

test "relative-import does not read other builtins or a computed name" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try findings_of(arena_state.allocator(), "src/quic/quic.zig",
        \\const bytes = @embedFile("../fixture.bin");
        \\const module = @import(module_name);
        \\const number = @as(u32, 1);
    );
    try harness.expect_messages(findings, &.{});
}

test "relative-import reads src/ alone" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try testing.expect(applies("src/quic/packet/header.zig"));
    try testing.expect(!applies("tools/lint/main.zig"));
    try testing.expect(!applies("build/modules.zig"));
    try harness.expect_messages(try findings_of(arena, "tools/graph_gate.zig", failing_fixture), &.{});
}
