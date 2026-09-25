//! module-graph: `quic` receives `core`, `wire`, `crypto` and `tls`, and nothing else
//! (docs/design.md §3, decision 5, invariant 26). QUIC is a transport with streams and no opinion
//! about payloads, and the way that is held is the build: `src/quic/` naming `http`, `h2`, `h3`,
//! `h11`, `hpack` or `qpack` does not compile, because build/modules.zig never gave `quic` those
//! modules.
//!
//! The rule reads two files and requires both to agree with `expected_quic_imports`:
//!   1. `build/modules.zig` — every `quic.addImport("<name>", ...)` call, which is what the
//!      compiler actually acts on;
//!   2. `tools/graph_check.zig` — the `quic_imports` list the check compiles its fixtures against,
//!      which must name what the build names. The check proves that a `quic`-shaped module cannot
//!      import HTTP. If its list drifts from the build's, it proves that about a module graph
//!      colibri does not have, and the proof stops covering the real one.
//!
//! The rule runs when the walk reaches `build/modules.zig`; `tools/graph_check.zig` is found beside
//! it, at the same prefix, and read as a second file. A run that never visits `build/modules.zig`
//! never runs this rule, so `zig build lint` passes it the `build` directory.
//!
//! The `addImport` calls are read from the parsed tree, by receiver name: a call is `quic`'s when
//! the receiver's last name is `quic`. The check's list is read from the tokens of its
//! `quic_imports` declaration, each `.name = "..."` field in it. Neither read follows a value
//! through a variable, so a list built by a loop or a name held in a `const` would be invisible;
//! both files spell their lists out, and the rule requires that they keep doing so.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Ast = std.zig.Ast;
const Node = Ast.Node;
const pepegrillo = @import("pepegrillo");
const ast = pepegrillo.lint.ast;
const paths = pepegrillo.lint.paths;
const report = pepegrillo.lint.report;

pub const name = "module-graph";

/// The file the rule runs on.
const build_modules_path = "build/modules.zig";

/// The file read beside it, at the same prefix.
const graph_check_path = "tools/graph_check.zig";

/// The module whose import list is pinned.
const module_name = "quic";

/// The method call that wires one module into another.
const add_import_method = "addImport";

/// The declaration in tools/graph_check.zig that holds the check's copy of the list.
const check_list_name = "quic_imports";

/// The field of a check entry that holds the module name.
const check_name_field = "name";

/// The import set docs/design.md §3 gives `quic`. Every other module in the graph is checked by
/// the compiler the moment a file names it; this one is checked here because its whole point is
/// what is *absent*, and absence compiles.
const expected_quic_imports = [_][]const u8{ "core", "wire", "crypto", "tls" };

/// Longest path the rule builds for the file it reads beside build/modules.zig.
const max_path_bytes: usize = 4096;

/// The line a finding about a whole file is reported on.
const file_line: usize = 1;

/// One module name as one of the two files spells it, with where it was written.
const Entry = struct {
    name: []const u8,
    line: usize,
    column: usize,
};

/// A parsed file the comparison reads.
const Source = struct {
    path: []const u8,
    tree: *const Ast,
};

pub fn applies(path: []const u8) bool {
    return paths.ends_with_path(path, build_modules_path);
}

pub fn check(context: *report.Context, file: report.File) !void {
    if (!applies(file.path)) return;
    const tree = file.tree orelse return;
    var path_buffer: [max_path_bytes]u8 = undefined;
    const check_path = try check_path_beside(&path_buffer, file.path);
    const check_source = context.read_file(check_path) orelse {
        return context.findings.add(
            name,
            check_path,
            file_line,
            1,
            "cannot read {s}; the check's {s} list is what proves the edge (invariant 26)",
            .{ check_path, check_list_name },
        );
    };
    var check_tree = try Ast.parse(context.arena, check_source, .zig);
    defer check_tree.deinit(context.arena);
    if (check_tree.errors.len != 0) {
        return context.findings.add(name, check_path, file_line, 1, "{s} does not parse", .{check_path});
    }
    try compare(
        context.arena,
        &context.findings,
        .{ .path = file.path, .tree = tree },
        .{ .path = check_path, .tree = &check_tree },
    );
}

/// `<prefix>build/modules.zig` becomes `<prefix>tools/graph_check.zig`, so the rule finds the check
/// whatever the walk's PATH argument was.
fn check_path_beside(buffer: []u8, modules_path: []const u8) ![]const u8 {
    const prefix = paths.without_suffix(modules_path, build_modules_path);
    return std.fmt.bufPrint(buffer, "{s}{s}", .{ prefix, graph_check_path });
}

/// Requires the build's list to be the expected one, and the tool's list to be the build's.
pub fn compare(
    arena: Allocator,
    findings: *report.Findings,
    build: Source,
    tool: Source,
) !void {
    const build_imports = try collect_add_imports(arena, build.tree);
    try report_unexpected(findings, build.path, build_imports, &expected_quic_imports);
    try report_absent(findings, build.path, build_imports, &expected_quic_imports);

    const tool_imports = try collect_tool_imports(arena, tool.tree) orelse {
        return findings.add(
            name,
            tool.path,
            file_line,
            1,
            "{s} declares no {s} list; the check cannot state the graph it proves (invariant 26)",
            .{ tool.path, check_list_name },
        );
    };
    const build_names = try names_of(arena, build_imports);
    try report_unexpected(findings, tool.path, tool_imports, build_names);
    try report_absent(findings, tool.path, tool_imports, build_names);
}

/// Every `quic.addImport("<name>", ...)` call of the build's module graph, in source order.
fn collect_add_imports(arena: Allocator, tree: *const Ast) ![]const Entry {
    var collector: ImportCollector = .{ .tree = tree, .arena = arena };
    for (tree.rootDecls()) |declaration| collector.child(declaration);
    if (collector.failure) |failure| return failure;
    return collector.entries.items;
}

const ImportCollector = struct {
    tree: *const Ast,
    arena: Allocator,
    entries: std.ArrayList(Entry) = .empty,
    depth: u32 = 0,
    failure: ?anyerror = null,

    pub fn child(self: *ImportCollector, node: Node.Index) void {
        self.depth += 1;
        defer self.depth -= 1;
        std.debug.assert(self.depth <= ast.max_tree_depth);
        self.visit(node) catch |failure| {
            self.failure = failure;
        };
        ast.for_each_child(self.tree, node, self);
    }

    fn visit(self: *ImportCollector, node: Node.Index) !void {
        if (!ast.is_call(self.tree.nodeTag(node))) return;
        var call_buffer: [1]Node.Index = undefined;
        const call = self.tree.fullCall(&call_buffer, node).?;
        var chain_buffer: [ast.max_chain_bytes]u8 = undefined;
        const chain = ast.chain_text(self.tree, call.ast.fn_expr, &chain_buffer) orelse return;
        if (!std.mem.eql(u8, ast.last_segment(chain), add_import_method)) return;
        const receiver = chain[0..chain.len -| (add_import_method.len + 1)];
        if (!std.mem.eql(u8, ast.last_segment(receiver), module_name)) return;
        if (call.ast.params.len == 0) return;
        const argument = call.ast.params[0];
        if (self.tree.nodeTag(argument) != .string_literal) return;
        const quoted = self.tree.tokenSlice(self.tree.nodeMainToken(argument));
        const location = ast.node_start_location(self.tree, argument);
        try self.entries.append(self.arena, .{
            .name = try self.arena.dupe(u8, quoted[1 .. quoted.len - 1]),
            .line = location.line,
            .column = location.column,
        });
    }
};

/// Every `.name = "<name>"` field of the check's `quic_imports` declaration, in source order, or
/// null when the declaration is absent.
fn collect_tool_imports(arena: Allocator, tree: *const Ast) !?[]const Entry {
    const declaration = find_declaration(tree, check_list_name) orelse return null;
    var entries: std.ArrayList(Entry) = .empty;
    const last = tree.lastToken(declaration);
    var token = tree.firstToken(declaration);
    // Four tokens spell one field: `.` `name` `=` `"core"`.
    while (token + 3 <= last) : (token += 1) {
        if (!is_name_field(tree, token)) continue;
        const quoted = tree.tokenSlice(token + 3);
        const location = ast.token_location(tree, token + 3);
        try entries.append(arena, .{
            .name = try arena.dupe(u8, quoted[1 .. quoted.len - 1]),
            .line = location.line,
            .column = location.column,
        });
    }
    return entries.items;
}

/// True when the four tokens starting at `token` spell `.name = "<something>"`.
fn is_name_field(tree: *const Ast, token: Ast.TokenIndex) bool {
    if (tree.tokenTag(token) != .period) return false;
    if (tree.tokenTag(token + 1) != .identifier) return false;
    if (!std.mem.eql(u8, tree.tokenSlice(token + 1), check_name_field)) return false;
    if (tree.tokenTag(token + 2) != .equal) return false;
    return tree.tokenTag(token + 3) == .string_literal;
}

/// The root declaration with this name, or null.
fn find_declaration(tree: *const Ast, wanted: []const u8) ?Node.Index {
    for (tree.rootDecls()) |declaration| {
        if (!is_variable_declaration(tree.nodeTag(declaration))) continue;
        // The main token of a variable declaration is its `const` or `var`; the name follows it.
        const name_token = tree.nodeMainToken(declaration) + 1;
        if (tree.tokenTag(name_token) != .identifier) continue;
        if (std.mem.eql(u8, tree.tokenSlice(name_token), wanted)) return declaration;
    }
    return null;
}

fn is_variable_declaration(tag: Node.Tag) bool {
    return switch (tag) {
        .simple_var_decl, .aligned_var_decl, .local_var_decl, .global_var_decl => true,
        else => false,
    };
}

fn names_of(arena: Allocator, entries: []const Entry) ![]const []const u8 {
    var list: std.ArrayList([]const u8) = .empty;
    for (entries) |entry| try list.append(arena, entry.name);
    return list.items;
}

/// Reports every entry whose name `wanted` does not hold.
fn report_unexpected(
    findings: *report.Findings,
    path: []const u8,
    entries: []const Entry,
    wanted: []const []const u8,
) !void {
    for (entries) |entry| {
        if (holds(wanted, entry.name)) continue;
        try findings.add(
            name,
            path,
            entry.line,
            entry.column,
            "{s} receives \"{s}\", which the graph does not give it (decision 5, invariant 26)",
            .{ module_name, entry.name },
        );
    }
}

/// Reports every name of `wanted` that no entry holds.
fn report_absent(
    findings: *report.Findings,
    path: []const u8,
    entries: []const Entry,
    wanted: []const []const u8,
) !void {
    for (wanted) |module| {
        if (holds_entry(entries, module)) continue;
        try findings.add(
            name,
            path,
            file_line,
            1,
            "{s} does not receive \"{s}\", which the graph gives it (design §3)",
            .{ module_name, module },
        );
    }
}

fn holds(names: []const []const u8, wanted: []const u8) bool {
    for (names) |candidate| {
        if (std.mem.eql(u8, candidate, wanted)) return true;
    }
    return false;
}

fn holds_entry(entries: []const Entry, wanted: []const u8) bool {
    for (entries) |entry| {
        if (std.mem.eql(u8, entry.name, wanted)) return true;
    }
    return false;
}

// Tests. Each fixture pins one shape from the header. The comparison is driven directly, with
// both files in memory, so the fixtures are string constants rather than files on disk.

const testing = std.testing;
const harness = pepegrillo.lint.harness;

const passing_build: [:0]const u8 =
    \\pub fn add(b: *std.Build) Modules {
    \\    const core = create(b, "src/core/core.zig");
    \\    const wire = create(b, "src/wire/wire.zig");
    \\    wire.addImport("core", core);
    \\    const quic = create(b, "src/quic/quic.zig");
    \\    quic.addImport("core", core);
    \\    quic.addImport("wire", wire);
    \\    quic.addImport("crypto", crypto);
    \\    quic.addImport("tls", tls);
    \\    const h3 = create(b, "src/h3/h3.zig");
    \\    h3.addImport("quic", quic);
    \\    h3.addImport("qpack", qpack);
    \\}
;

const passing_check: [:0]const u8 =
    \\const quic_imports = [_]Import{
    \\    .{ .name = "core", .root = "core/core.zig", .deps = &.{} },
    \\    .{ .name = "wire", .root = "wire/wire.zig", .deps = &.{"core"} },
    \\    .{ .name = "crypto", .root = "crypto/crypto.zig", .deps = &.{"core"} },
    \\    .{ .name = "tls", .root = "tls/tls.zig", .deps = &.{"core"} },
    \\};
    \\const forbidden = [_][]const u8{ "http", "h2", "h3", "hpack", "qpack" };
;

/// Runs the comparison over two in-memory sources and returns the findings sorted.
fn compare_sources(
    arena: Allocator,
    build_source: [:0]const u8,
    check_source: [:0]const u8,
) ![]const report.Finding {
    var build_tree = try Ast.parse(arena, build_source, .zig);
    try testing.expectEqual(0, build_tree.errors.len);
    var check_tree = try Ast.parse(arena, check_source, .zig);
    try testing.expectEqual(0, check_tree.errors.len);
    var findings: report.Findings = .{ .arena = arena };
    try compare(
        arena,
        &findings,
        .{ .path = build_modules_path, .tree = &build_tree },
        .{ .path = graph_check_path, .tree = &check_tree },
    );
    findings.sort();
    return findings.items.items;
}

test "module-graph passes when the build and the check both name the four modules" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try compare_sources(arena_state.allocator(), passing_build, passing_check);
    try harness.expect_messages(findings, &.{});
}

test "module-graph flags an HTTP module the build gives quic" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try compare_sources(arena_state.allocator(),
        \\pub fn add(b: *std.Build) Modules {
        \\    quic.addImport("core", core);
        \\    quic.addImport("wire", wire);
        \\    quic.addImport("crypto", crypto);
        \\    quic.addImport("tls", tls);
        \\    quic.addImport("http", http);
        \\}
    , passing_check);
    // The first is the build's own extra import; the second is the check's list not naming it,
    // which is the drift that would leave the check proving something about another graph.
    try harness.expect_messages(findings, &.{
        "quic receives \"http\", which the graph does not give it (decision 5, invariant 26)",
        "quic does not receive \"http\", which the graph gives it (design §3)",
    });
    try testing.expectEqualStrings(build_modules_path, findings[0].path);
    try testing.expectEqual(6, findings[0].line);
    try testing.expectEqualStrings(graph_check_path, findings[1].path);
}

test "module-graph flags a module the build no longer gives quic" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try compare_sources(arena_state.allocator(),
        \\pub fn add(b: *std.Build) Modules {
        \\    quic.addImport("core", core);
        \\    quic.addImport("wire", wire);
        \\    quic.addImport("crypto", crypto);
        \\}
    , passing_check);
    try harness.expect_messages(findings, &.{
        "quic does not receive \"tls\", which the graph gives it (design §3)",
        "quic receives \"tls\", which the graph does not give it (decision 5, invariant 26)",
    });
    try testing.expectEqualStrings(build_modules_path, findings[0].path);
    try testing.expectEqualStrings(graph_check_path, findings[1].path);
}

test "module-graph flags a check list that drifts from the build" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try compare_sources(arena_state.allocator(), passing_build,
        \\const quic_imports = [_]Import{
        \\    .{ .name = "core", .root = "core/core.zig", .deps = &.{} },
        \\    .{ .name = "wire", .root = "wire/wire.zig", .deps = &.{"core"} },
        \\    .{ .name = "crypto", .root = "crypto/crypto.zig", .deps = &.{"core"} },
        \\};
    );
    try harness.expect_messages(findings, &.{
        "quic does not receive \"tls\", which the graph gives it (design §3)",
    });
    try testing.expectEqualStrings(graph_check_path, findings[0].path);
}

test "module-graph flags a check with no quic_imports list at all" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try compare_sources(arena_state.allocator(), passing_build,
        \\const forbidden = [_][]const u8{ "http", "h2", "h3", "hpack", "qpack" };
    );
    try harness.expect_messages(findings, &.{
        "tools/graph_check.zig declares no quic_imports list;" ++
            " the check cannot state the graph it proves (invariant 26)",
    });
}

test "module-graph reads the addImport calls of quic and of no other module" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var tree = try Ast.parse(arena, passing_build, .zig);
    const entries = try collect_add_imports(arena, &tree);
    try testing.expectEqual(4, entries.len);
    try testing.expectEqualStrings("core", entries[0].name);
    try testing.expectEqualStrings("tls", entries[3].name);
    try testing.expectEqual(9, entries[3].line);
}

test "module-graph finds the check beside build/modules.zig, whatever the walk's prefix was" {
    var buffer: [max_path_bytes]u8 = undefined;
    try testing.expectEqualStrings(
        "tools/graph_check.zig",
        try check_path_beside(&buffer, "build/modules.zig"),
    );
    try testing.expectEqualStrings(
        "./tools/graph_check.zig",
        try check_path_beside(&buffer, "./build/modules.zig"),
    );
    try testing.expectEqualStrings(
        "/home/me/colibri/tools/graph_check.zig",
        try check_path_beside(&buffer, "/home/me/colibri/build/modules.zig"),
    );
}

test "module-graph runs on build/modules.zig and on nothing else" {
    try testing.expect(applies("build/modules.zig"));
    try testing.expect(applies("./build/modules.zig"));
    try testing.expect(!applies("build/other.zig"));
    try testing.expect(!applies("src/quic/quic.zig"));
    try testing.expect(!applies("tools/graph_check.zig"));
}
