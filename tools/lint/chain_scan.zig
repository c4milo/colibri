//! The walk the three forbidden-reference rules share. `heap`, `io` and `determinism` each name a
//! list of dotted prefixes that no file under their directories may reach, and each of the three
//! finds them the same way: parse the file, walk every node, and report every identifier or
//! field-access chain that starts with one of the prefixes at a dot boundary.
//!
//! The dot boundary is what separates `std.heap.page_allocator` from a local named `std_heap_bytes`
//! and `std.posix.socket` from a field named `std_posix_mode`. A chain is reported once, as a
//! whole, at its first token, and is never descended into: its segments are not separate
//! references.
//!
//! What this walk reads is the text of the source, not its types. An alias re-exported by another
//! module (`const posix = other.posix;` in one file, `posix.socket` in a second) reaches the
//! forbidden declaration under a name this walk does not know. The module graph of
//! build/modules.zig is what stops that, because a module can import only what the build gives
//! it; this walk is what stops a file reaching `std` directly.

const std = @import("std");
const Ast = std.zig.Ast;
const Node = Ast.Node;
const ast = @import("ast.zig");
const report = @import("report.zig");

/// One rule's forbidden list, with the sentence a finding cites.
pub const Forbidden = struct {
    /// The rule name a finding is reported under.
    name: []const u8,
    /// A chain that starts with one of these at a dot boundary is a finding.
    prefixes: []const []const u8,
    /// Why the reference is forbidden, printed after the chain.
    reason: []const u8,
};

/// Reports every forbidden chain in `file`. A file that is not Zig, or that did not parse, is
/// left alone; the caller has already decided the path is this rule's concern.
pub fn scan(context: *report.Context, file: report.File, forbidden: Forbidden) !void {
    const tree = file.tree orelse return;
    var visitor: Visitor = .{
        .tree = tree,
        .findings = &context.findings,
        .path = file.path,
        .forbidden = forbidden,
    };
    for (tree.rootDecls()) |declaration| visitor.child(declaration);
    if (visitor.failure) |failure| return failure;
}

const Visitor = struct {
    tree: *const Ast,
    findings: *report.Findings,
    path: []const u8,
    forbidden: Forbidden,
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
        var buffer: [ast.max_chain_bytes]u8 = undefined;
        if (ast.chain_text(self.tree, node, &buffer)) |chain| {
            if (ast.has_any_prefix_at_dot(chain, self.forbidden.prefixes)) {
                const location = ast.node_start_location(self.tree, node);
                try self.findings.add(
                    self.forbidden.name,
                    self.path,
                    location.line,
                    location.column,
                    "reference to {s}: {s}",
                    .{ chain, self.forbidden.reason },
                );
            }
            return;
        }
        ast.for_each_child(self.tree, node, self);
    }
};

// Tests. The three rules that use this walk carry the fixtures for their own lists; these pin the
// walk itself.

const testing = std.testing;
const harness = @import("harness.zig");

const probe: Forbidden = .{
    .name = "probe",
    .prefixes = &.{ "std.posix", "std.fs" },
    .reason = "the reason",
};

const Probe = struct {
    pub const name = probe.name;
    pub fn check(context: *report.Context, file: report.File) !void {
        try scan(context, file, probe);
    }
};

test "scan reports a forbidden chain once, as a whole, at its first token" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try harness.run(arena_state.allocator(), Probe, "src/quic/quic.zig",
        \\const socket = std.posix.socket;
        \\const opened = std.fs.cwd().openFile;
    );
    try harness.expect_messages(findings, &.{
        "reference to std.posix.socket: the reason",
        "reference to std.fs.cwd: the reason",
    });
    try testing.expectEqual(1, findings[0].line);
    try testing.expectEqual(16, findings[0].column);
    try testing.expectEqual(2, findings[1].line);
}

test "scan holds to the dot boundary and to whole chains" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try harness.run(arena_state.allocator(), Probe, "src/quic/quic.zig",
        \\const bytes = constants.std_posix_bytes;
        \\const other = std.posixish.socket;
        \\const mine = self.std.posix;
    );
    try harness.expect_messages(findings, &.{});
}

test "scan reaches a chain nested inside an expression" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try harness.run(arena_state.allocator(), Probe, "src/quic/quic.zig",
        \\fn open(name: []const u8) !void {
        \\    if (name.len == 0) return;
        \\    const file = try std.fs.cwd().openFile(name, .{});
        \\    _ = file;
        \\}
    );
    try harness.expect_messages(findings, &.{"reference to std.fs.cwd: the reason"});
    try testing.expectEqual(3, findings[0].line);
}
