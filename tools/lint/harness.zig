//! Test support for the rules: runs one rule over one in-memory file and returns its findings
//! sorted. Only tests reference this file, so nothing in it is compiled into the tool.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Ast = std.zig.Ast;
const testing = std.testing;
const paths = @import("paths.zig");
const report = @import("report.zig");

/// Runs `rule.check` over `source` presented at `path`. A `.zig` path is parsed first, and a
/// parse error fails the test, since a fixture that does not parse pins nothing.
pub fn run(
    arena: Allocator,
    comptime rule: type,
    path: []const u8,
    source: [:0]const u8,
) ![]const report.Finding {
    var context: report.Context = .{
        .arena = arena,
        .io = testing.io,
        .findings = .{ .arena = arena },
    };
    var tree: Ast = undefined;
    var tree_pointer: ?*const Ast = null;
    if (paths.has_extension(path, paths.zig_extension)) {
        tree = try Ast.parse(arena, source, .zig);
        try testing.expectEqual(0, tree.errors.len);
        tree_pointer = &tree;
    }
    try rule.check(&context, .{ .path = path, .source = source, .tree = tree_pointer });
    context.findings.sort();
    return context.findings.items.items;
}

/// Checks the messages of `findings`, in sorted order, against `expected`.
pub fn expect_messages(findings: []const report.Finding, expected: []const []const u8) !void {
    if (expected.len != findings.len) {
        std.debug.print("findings reported:\n", .{});
        for (findings) |finding| {
            std.debug.print("  {s}:{d}: [{s}] {s}\n", .{
                finding.path, finding.line, finding.rule, finding.message,
            });
        }
    }
    try testing.expectEqual(expected.len, findings.len);
    for (findings, expected) |finding, message| {
        try testing.expectEqualStrings(message, finding.message);
    }
}
