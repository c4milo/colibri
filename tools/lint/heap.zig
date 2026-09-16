//! heap: colibri allocates at init and never after (CLAUDE.md non-negotiable 4, invariant 1).
//! Storage is the caller's, sized once, and every later call writes into it.
//!
//! Over every `.zig` file under `src/`, the rule makes two checks:
//!   1. a chain that starts with `std.heap` at a dot boundary, such as `std.heap.page_allocator`
//!      or `std.heap.ArenaAllocator`. Naming `std.heap` at all means a file has an allocator of
//!      its own rather than one it received;
//!   2. a parameter whose type names `Allocator`, on a function whose name is not `init`. The
//!      type is matched by segment, so `std.mem.Allocator`, `mem.Allocator` and a bare
//!      `Allocator` all match, and so do the wrapped forms `?Allocator`, `*const Allocator` and
//!      `[]const Allocator`, because the whole type expression is searched.
//!
//! What check 2 cannot see: a parameter declared `anytype` carries no type expression, so an
//! allocator passed as `anytype` is invisible to this rule. It also reads the function's own
//! name only — a function named `init` may take an allocator, and one it calls may not, which is
//! exactly the direction invariant 1 wants.
//!
//! Every function in `src/` is read, a test helper included. A test that needs scratch memory
//! calls `std.testing.allocator` where it needs it rather than taking a parameter, so that the
//! signature of a function in `src/` never says an allocator reaches it.

const std = @import("std");
const Ast = std.zig.Ast;
const Node = Ast.Node;
const ast = @import("ast.zig");
const chain_scan = @import("chain_scan.zig");
const paths = @import("paths.zig");
const report = @import("report.zig");

pub const name = "heap";

/// The directory the rule reads. Developer tooling under `tools/` allocates freely; nothing under
/// `tools/` is linked into the library.
const source_directory = "src";

/// The one function name allowed an allocator parameter.
const allocating_function_name = "init";

/// A parameter type holding this segment is an allocator.
const allocator_type_segment = "Allocator";

/// The name a prototype with no name token is reported under: a function type in a field or a
/// vtable declaration, `fn (*anyopaque) void`.
const anonymous_function_name = "an anonymous function type";

const forbidden: chain_scan.Forbidden = .{
    .name = name,
    .prefixes = &.{"std.heap"},
    .reason = "colibri allocates at init and never after (invariant 1)",
};

pub fn applies(path: []const u8) bool {
    if (!paths.has_extension(path, paths.zig_extension)) return false;
    return paths.is_under(path, source_directory);
}

pub fn check(context: *report.Context, file: report.File) !void {
    if (!applies(file.path)) return;
    try chain_scan.scan(context, file, forbidden);
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
        // A `fn_decl` holds its prototype as a child, which this walk reaches on its own; reading
        // the prototype here as well would report every parameter twice.
        if (self.tree.nodeTag(node) != .fn_decl) try self.visit_prototype(node);
        ast.for_each_child(self.tree, node, self);
    }

    fn visit_prototype(self: *Visitor, node: Node.Index) !void {
        var buffer: [1]Node.Index = undefined;
        const prototype = self.tree.fullFnProto(&buffer, node) orelse return;
        const declared_name = self.name_of(prototype);
        if (std.mem.eql(u8, declared_name, allocating_function_name)) return;
        for (prototype.ast.params) |parameter| {
            if (!self.names_allocator(parameter)) continue;
            const location = ast.node_start_location(self.tree, parameter);
            try self.findings.add(
                name,
                self.path,
                location.line,
                location.column,
                "{s} takes an allocator parameter; only {s} may take one (invariant 1)",
                .{ declared_name, allocating_function_name },
            );
        }
    }

    fn name_of(self: *const Visitor, prototype: Ast.full.FnProto) []const u8 {
        const token = prototype.name_token orelse return anonymous_function_name;
        return self.tree.tokenSlice(token);
    }

    /// True when the parameter's type expression names `Allocator` anywhere inside it, so a
    /// pointer, an optional or a slice of one is found along with the plain type.
    fn names_allocator(self: *const Visitor, parameter: Node.Index) bool {
        var search: TypeSearch = .{ .tree = self.tree };
        search.child(parameter);
        return search.found;
    }
};

/// Walks one parameter's type expression and records whether it names `Allocator`.
const TypeSearch = struct {
    tree: *const Ast,
    found: bool = false,
    depth: u32 = 0,

    pub fn child(self: *TypeSearch, node: Node.Index) void {
        self.depth += 1;
        defer self.depth -= 1;
        std.debug.assert(self.depth <= ast.max_tree_depth);
        var buffer: [ast.max_chain_bytes]u8 = undefined;
        if (ast.chain_text(self.tree, node, &buffer)) |chain| {
            if (ast.has_segment(chain, allocator_type_segment)) self.found = true;
            return;
        }
        ast.for_each_child(self.tree, node, self);
    }
};

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
    \\
    \\pub const Connection = struct {
    \\    streams: []Stream,
    \\
    \\    pub fn init(allocator: std.mem.Allocator, count: u32) !Connection {
    \\        return .{ .streams = try allocator.alloc(Stream, count) };
    \\    }
    \\
    \\    pub fn read(self: *Connection, bytes: []const u8) !usize {
    \\        return self.streams[0].write(bytes);
    \\    }
    \\};
    \\
    \\const heap_bytes = core.constants.connection_heap_bytes;
;

const failing_fixture: [:0]const u8 =
    \\const std = @import("std");
    \\
    \\const arena_type = std.heap.ArenaAllocator;
    \\
    \\pub fn read(allocator: std.mem.Allocator, bytes: []const u8) !usize {
    \\    _ = allocator;
    \\    return bytes.len;
    \\}
;

test "heap passes a file that allocates only in init" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try findings_of(arena_state.allocator(), "src/quic/quic.zig", passing_fixture);
    try harness.expect_messages(findings, &.{});
}

test "heap flags std.heap and an allocator parameter outside init" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try findings_of(arena_state.allocator(), "src/quic/quic.zig", failing_fixture);
    try harness.expect_messages(findings, &.{
        "reference to std.heap.ArenaAllocator: colibri allocates at init and never after (invariant 1)",
        "read takes an allocator parameter; only init may take one (invariant 1)",
    });
    try testing.expectEqual(3, findings[0].line);
    try testing.expectEqual(5, findings[1].line);
}

test "heap finds an allocator wrapped in a pointer, an optional or a slice" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try findings_of(arena_state.allocator(), "src/core/core.zig",
        \\fn one(allocator: *const std.mem.Allocator) void {}
        \\fn two(allocator: ?Allocator) void {}
        \\fn three(allocators: []const mem.Allocator) void {}
    );
    try harness.expect_messages(findings, &.{
        "one takes an allocator parameter; only init may take one (invariant 1)",
        "two takes an allocator parameter; only init may take one (invariant 1)",
        "three takes an allocator parameter; only init may take one (invariant 1)",
    });
}

test "heap does not flag a parameter whose type merely resembles the word" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try findings_of(arena_state.allocator(), "src/core/core.zig",
        \\fn one(allocation: Allocations) void {}
        \\fn two(bytes: []u8, count: u32) void {}
        \\const heap_limit = constants.std_heap_bytes;
    );
    try harness.expect_messages(findings, &.{});
}

test "heap reports one finding per parameter and reads a nested function" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try findings_of(arena_state.allocator(), "src/core/core.zig",
        \\pub const Pool = struct {
        \\    pub fn grow(self: *Pool, allocator: Allocator, second: Allocator) void {}
        \\};
    );
    try harness.expect_messages(findings, &.{
        "grow takes an allocator parameter; only init may take one (invariant 1)",
        "grow takes an allocator parameter; only init may take one (invariant 1)",
    });
}

test "heap names an anonymous function type when a prototype has no name" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try findings_of(arena_state.allocator(), "src/tls/tls.zig",
        \\pub const Provider = struct {
        \\    start: *const fn (allocator: Allocator) void,
        \\};
    );
    try harness.expect_messages(findings, &.{
        "an anonymous function type takes an allocator parameter; only init may take one (invariant 1)",
    });
}

test "heap reads src/ alone" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try testing.expect(applies("src/quic/quic.zig"));
    try testing.expect(applies("./src/testing/endpoint.zig"));
    try testing.expect(!applies("tools/lint/main.zig"));
    try testing.expect(!applies("build/modules.zig"));
    try testing.expect(!applies("docs/design.md"));
    try harness.expect_messages(try findings_of(arena, "tools/lint/heap.zig", failing_fixture), &.{});
}
