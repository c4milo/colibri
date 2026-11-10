//! rotor-import: only the programs that run on Rotor get it, and only colibri's Rotor adapter
//! imports it (decision 159). Rotor is a lazy package, so a dependent of the protocol modules or
//! of the `.hosted` kind fetches no Rotor. The rule keeps it that way in two parts:
//!   1. The build. In `build.zig` and in each `.zig` file of `build/`, each
//!      `<receiver>.addImport("rotor", ...)` names a receiver of `rotor_receivers`: `colibri`,
//!      `testing`, `testing_client`, `testing_udp` and `example`, the module of each example. Each
//!      call `dependency("rotor", ...)` is a finding, because only `lazyDependency` keeps the
//!      package lazy. A module with no import cannot compile `@import("rotor")`, so for `server`,
//!      `client`, `http`, `h11`, `h2`, `h3`, `quic` and `tls` the build is the proof.
//!   2. The source. A `.zig` file under `src/` that holds `@import("rotor")` is under
//!      `src/testing/`, or is a file of `src/colibri/` whose name starts with `rotor_host`. The
//!      compiler cannot limit an import to some files of one module, so the rule does it. It keeps
//!      each Rotor type out of the driver of `colibri`.
//!
//! `zig build colibri-hosted-check` is the third part: it builds `colibri` with no Rotor
//! (build/colibri_hosted_check.zig).
//!
//! The rule reads the parsed tree. The build part reads each call by the last name of its callee
//! and of its receiver, as `module_graph.zig` reads the imports of `quic`. It does not follow a
//! value through a variable, so the build spells each `addImport("rotor", ...)` out.
//!
//! Decision 159 names pepegrillo's `forbidden_references` for the source part. That rule reads
//! chains such as `rotor.Loop`, and not the `@import` itself, so a file that imports Rotor under
//! another name would pass it. This rule reads `@import("rotor")` through pepegrillo's
//! `imported_path` instead.

const std = @import("std");
const Ast = std.zig.Ast;
const Node = Ast.Node;
const pepegrillo = @import("pepegrillo");
const ast = pepegrillo.lint.ast;
const paths = pepegrillo.lint.paths;
const report = pepegrillo.lint.report;

pub const name = "rotor-import";

/// The name of the package and of its module.
const rotor_name = "rotor";

/// The modules that take Rotor: the `.private` kind of `colibri`, the test-only endpoints of
/// `src/testing/` (decision 58) and the programs of `examples/` (decision 96).
const rotor_receivers = [_][]const u8{ "colibri", "testing", "testing_client", "testing_udp", "example" };

/// The method call that gives one module to another.
const add_import_method = "addImport";

/// The call that fetches a package whatever the build asks for.
const eager_method = "dependency";

/// The build script and the directory of its helpers.
const build_script = "build.zig";
const build_directory = "build";

/// Where the source part reads, and the two places that may import Rotor.
const source_directory = "src";
const testing_directory = "src/testing";
const adapter_directory = "src/colibri";
const adapter_prefix = "rotor_host";

const Part = enum { build, source };

pub fn check(context: *report.Context, file: *const report.File) !void {
    const part = part_of(file.path) orelse return;
    const tree = file.tree orelse return;
    var visitor: Visitor = .{ .tree = tree, .findings = &context.findings, .path = file.path, .part = part };
    for (tree.rootDecls()) |declaration| visitor.child(declaration);
    if (visitor.failure) |failure| return failure;
}

/// Which part reads `path`, or null when neither does.
fn part_of(path: []const u8) ?Part {
    if (!paths.has_extension(path, paths.zig_extension)) return null;
    if (std.mem.eql(u8, paths.basename(path), build_script)) return .build;
    if (std.mem.eql(u8, paths.parent_basename(path), build_directory)) return .build;
    if (!paths.is_under(path, source_directory)) return null;
    if (may_import_rotor(path)) return null;
    return .source;
}

/// A file of `src/testing/`, or of `src/colibri/` with a name that starts with `rotor_host`.
fn may_import_rotor(path: []const u8) bool {
    if (paths.is_under(path, testing_directory)) return true;
    if (!paths.is_under(path, adapter_directory)) return false;
    if (!std.mem.eql(u8, paths.parent_basename(path), paths.basename(adapter_directory))) return false;
    return std.mem.startsWith(u8, paths.basename(path), adapter_prefix);
}

const Visitor = struct {
    tree: *const Ast,
    findings: *report.Findings,
    path: []const u8,
    part: Part,
    depth: u32 = 0,
    failure: ?anyerror = null,

    pub fn child(self: *Visitor, node: Node.Index) void {
        self.depth += 1;
        defer self.depth -= 1;
        std.debug.assert(self.depth <= ast.tree_depth_max);
        const visited = switch (self.part) {
            .build => self.visit_build(node),
            .source => self.visit_source(node),
        };
        visited catch |failure| {
            self.failure = failure;
        };
        ast.for_each_child(self.tree, node, self);
    }

    /// Part 2: an `@import("rotor")` in a file that may not hold one.
    fn visit_source(self: *Visitor, node: Node.Index) !void {
        const imported = ast.imported_path(self.tree, node) orelse return;
        if (!std.mem.eql(u8, imported, rotor_name)) return;
        try self.add(
            node,
            "@import(\"rotor\") outside src/testing/ and src/colibri/rotor_host*.zig;" ++
                " only colibri's Rotor adapter imports Rotor (decision 159)",
            .{},
        );
    }

    /// Part 1: an `addImport("rotor", ...)` to a module that does not run on Rotor, or a
    /// `dependency("rotor", ...)`.
    fn visit_build(self: *Visitor, node: Node.Index) !void {
        if (!ast.is_call(self.tree.nodeTag(node))) return;
        var call_buffer: [1]Node.Index = undefined;
        const call = self.tree.fullCall(&call_buffer, node).?;
        if (!names_rotor(self.tree, call.ast.params)) return;
        var chain_buffer: [ast.chain_len_max]u8 = undefined;
        const chain = ast.chain_text(self.tree, call.ast.fn_expr, &chain_buffer) orelse return;
        const method = ast.last_segment(chain);
        if (std.mem.eql(u8, method, eager_method)) {
            return self.add(node, "dependency(\"rotor\", ...) fetches Rotor for each dependent;" ++
                " call lazyDependency (decision 159)", .{});
        }
        if (!std.mem.eql(u8, method, add_import_method)) return;
        const receiver = ast.last_segment(chain[0..chain.len -| (add_import_method.len + 1)]);
        if (is_receiver(receiver)) return;
        try self.add(node, "{s} takes Rotor; only colibri, testing, testing_client, testing_udp" ++
            " and example run on it (decision 159)", .{receiver});
    }

    fn add(self: *Visitor, node: Node.Index, comptime format: []const u8, arguments: anytype) !void {
        const location = ast.node_start_location(self.tree, node);
        try self.findings.add(self.path, location.line, location.column, name, format, arguments);
    }
};

/// Whether the first argument of a call is the string literal `"rotor"`.
fn names_rotor(tree: *const Ast, params: []const Node.Index) bool {
    if (params.len == 0) return false;
    const argument = params[0];
    if (tree.nodeTag(argument) != .string_literal) return false;
    const quoted = tree.tokenSlice(tree.nodeMainToken(argument));
    return std.mem.eql(u8, quoted[1 .. quoted.len - 1], rotor_name);
}

fn is_receiver(receiver: []const u8) bool {
    for (rotor_receivers) |allowed| {
        if (std.mem.eql(u8, receiver, allowed)) return true;
    }
    return false;
}

// Tests. Each fixture pins one shape from the header.

const testing = std.testing;
const harness = pepegrillo.lint.harness;

const import_message = "@import(\"rotor\") outside src/testing/ and src/colibri/rotor_host*.zig;" ++
    " only colibri's Rotor adapter imports Rotor (decision 159)";

fn findings_of(arena: std.mem.Allocator, path: []const u8, source: [:0]const u8) ![]const report.Finding {
    return harness.run(arena, @This(), path, source);
}

const build_fixture: [:0]const u8 =
    \\pub fn add(b: *std.Build) void {
    \\    const rotor = b.lazyDependency("rotor", .{}) orelse return;
    \\    colibri.addImport("rotor", rotor.module("rotor"));
    \\    graph.testing.addImport("rotor", rotor.module("rotor"));
    \\    graph.testing_client.addImport("rotor", rotor.module("rotor"));
    \\    testing_udp.addImport("rotor", rotor.module("rotor"));
    \\    example.addImport("rotor", rotor.module("rotor"));
    \\    quic.addImport("core", core);
    \\    const stdx = b.dependency("stdx", .{});
    \\    _ = stdx;
    \\}
;

const source_fixture: [:0]const u8 =
    \\const std = @import("std");
    \\const rotor = @import("rotor");
    \\const rotor_host = @import("rotor_host.zig");
;

test "rotor-import passes each module that runs on Rotor, and a lazy fetch" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try harness.expect_messages(try findings_of(arena, "build/modules.zig", build_fixture), &.{});
    try harness.expect_messages(try findings_of(arena, "build.zig", build_fixture), &.{});
}

test "rotor-import refuses Rotor given to another module, and an eager fetch" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try findings_of(arena_state.allocator(), "build/modules.zig",
        \\pub fn add(b: *std.Build) void {
        \\    const rotor = b.dependency("rotor", .{});
        \\    quic.addImport("rotor", rotor.module("rotor"));
        \\    graph.server.addImport("rotor", rotor.module("rotor"));
        \\}
    );
    try harness.expect_messages(findings, &.{
        "dependency(\"rotor\", ...) fetches Rotor for each dependent; call lazyDependency (decision 159)",
        "quic takes Rotor; only colibri, testing, testing_client, testing_udp and example run on it (decision 159)",
        "server takes Rotor; only colibri, testing, testing_client, testing_udp and example run on it (decision 159)",
    });
    try testing.expectEqual(2, findings[0].line);
    try testing.expectEqual(3, findings[1].line);
}

test "rotor-import refuses @import(\"rotor\") in the driver and in a protocol module" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    for ([_][]const u8{ "src/colibri/client.zig", "src/server/server.zig", "src/colibri/host_rotor.zig", "src/colibri/sub/rotor_host.zig" }) |path| {
        const findings = try findings_of(arena, path, source_fixture);
        try harness.expect_messages(findings, &.{import_message});
        try testing.expectEqual(2, findings[0].line);
    }
}

test "rotor-import passes the Rotor adapter, src/testing/, and each file outside src/" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    for ([_][]const u8{
        "src/colibri/rotor_host.zig",
        "src/colibri/rotor_host_udp.zig",
        "src/colibri/rotor_host_client_test.zig",
        "src/testing/udp.zig",
        "./src/testing/quic/endpoint.zig",
        "examples/link.zig",
        "tools/consumer/main.zig",
    }) |path| {
        try harness.expect_messages(try findings_of(arena, path, source_fixture), &.{});
    }
}

test "rotor-import reads no file of another kind, and no @import of another name" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try testing.expectEqual(null, part_of("src/colibri/client.md"));
    try testing.expectEqual(Part.source, part_of("src/colibri/client.zig").?);
    try testing.expectEqual(Part.build, part_of("build/examples.zig").?);
    try testing.expectEqual(Part.build, part_of("build.zig").?);
    try harness.expect_messages(try findings_of(arena, "src/colibri/client.zig",
        \\const rotor_host = @import("rotor_host.zig");
        \\const rotor = @import("rotor_core");
    ), &.{});
}
