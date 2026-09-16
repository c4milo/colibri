//! What one lint run accumulates and what it hands each rule.
//!
//! A rule receives a `Context` and a `File` and calls `context.findings.add` once per finding.
//! `main.zig` sorts the findings by path, line, column and rule name, so the report reads the
//! same whatever order the directory walk visited the files in, and prints one line per finding:
//!
//!     path:line: [rule-name] message
//!
//! The column is recorded and not printed. It orders two findings that fall on one line, so the
//! report is stable when a rule reports twice about the same line.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Io = std.Io;
const Ast = std.zig.Ast;

/// Findings recorded per run. One more is reported as an error, never dropped silently.
pub const max_findings: usize = 1024 * 1024;

/// A file at or over this size is reported as unreadable rather than linted.
pub const max_file_bytes: usize = 4 * 1024 * 1024;

pub const Finding = struct {
    path: []const u8,
    /// 1-based line.
    line: usize,
    /// 1-based column. Orders findings that share a line; never printed.
    column: usize,
    rule: []const u8,
    message: []const u8,
};

/// One file as the rules see it. `tree` is set when the path ends in `.zig` and the parse
/// succeeded; a text rule ignores it and a Zig rule returns when it is null.
pub const File = struct {
    path: []const u8,
    source: [:0]const u8,
    tree: ?*const Ast,
};

pub const Findings = struct {
    arena: Allocator,
    items: std.ArrayList(Finding) = .empty,

    /// Records one finding. `path` is copied, so a caller may hand over a path buffer it is
    /// about to overwrite.
    pub fn add(
        self: *Findings,
        rule: []const u8,
        path: []const u8,
        line: usize,
        column: usize,
        comptime format: []const u8,
        arguments: anytype,
    ) !void {
        if (self.items.items.len >= max_findings) return error.TooManyFindings;
        try self.items.append(self.arena, .{
            .path = try self.arena.dupe(u8, path),
            .line = line,
            .column = column,
            .rule = rule,
            .message = try std.fmt.allocPrint(self.arena, format, arguments),
        });
    }

    pub fn count(self: *const Findings) usize {
        return self.items.items.len;
    }

    pub fn sort(self: *Findings) void {
        std.mem.sort(Finding, self.items.items, {}, before);
    }

    /// Writes every finding as one `path:line: [rule] message` line.
    pub fn write(self: *const Findings, out: *Io.Writer) !void {
        for (self.items.items) |finding| {
            try out.print("{s}:{d}: [{s}] {s}\n", .{
                finding.path, finding.line, finding.rule, finding.message,
            });
        }
    }
};

fn before(_: void, left: Finding, right: Finding) bool {
    switch (std.mem.order(u8, left.path, right.path)) {
        .lt => return true,
        .gt => return false,
        .eq => {},
    }
    if (left.line != right.line) return left.line < right.line;
    if (left.column != right.column) return left.column < right.column;
    return std.mem.order(u8, left.rule, right.rule) == .lt;
}

/// The run-wide state a rule may touch: the arena for scratch memory that lives until the report
/// is printed, the I/O interface for the one rule that reads a second file, and the findings.
pub const Context = struct {
    arena: Allocator,
    io: Io,
    findings: Findings,

    /// Reads a whole file relative to the working directory into the arena with a trailing zero.
    /// Returns null when the file cannot be read for any reason: a missing file is the ordinary
    /// case, and the caller decides what a missing file means.
    pub fn read_file(self: *Context, path: []const u8) ?[:0]u8 {
        return Io.Dir.cwd().readFileAllocOptions(
            self.io,
            path,
            self.arena,
            .limited(max_file_bytes),
            .of(u8),
            0,
        ) catch null;
    }
};

// Tests.

const testing = std.testing;

test "findings sort by path, then line, then column, then rule" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var findings: Findings = .{ .arena = arena_state.allocator() };
    try findings.add("b-rule", "b.zig", 1, 1, "", .{});
    try findings.add("a-rule", "a.zig", 9, 1, "", .{});
    try findings.add("a-rule", "a.zig", 2, 5, "", .{});
    try findings.add("a-rule", "a.zig", 2, 3, "", .{});
    try findings.add("z-rule", "a.zig", 2, 3, "", .{});
    findings.sort();
    const items = findings.items.items;
    try testing.expectEqualStrings("a.zig", items[0].path);
    try testing.expectEqual(2, items[0].line);
    try testing.expectEqual(3, items[0].column);
    try testing.expectEqualStrings("a-rule", items[0].rule);
    try testing.expectEqualStrings("z-rule", items[1].rule);
    try testing.expectEqual(5, items[2].column);
    try testing.expectEqual(9, items[3].line);
    try testing.expectEqualStrings("b.zig", items[4].path);
}

test "write prints path:line: [rule] message" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var findings: Findings = .{ .arena = arena };
    try findings.add("heap", "src/core/core.zig", 3, 7, "reference to {s}", .{"std.heap"});
    var writer: Io.Writer.Allocating = .init(arena);
    defer writer.deinit();
    try findings.write(&writer.writer);
    try testing.expectEqualStrings(
        "src/core/core.zig:3: [heap] reference to std.heap\n",
        writer.written(),
    );
}

test "add copies the path" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var findings: Findings = .{ .arena = arena_state.allocator() };
    var path_buffer: [8]u8 = "a.zig\x00\x00\x00".*;
    try findings.add("heap", path_buffer[0..5], 1, 1, "", .{});
    path_buffer[0] = 'z';
    try testing.expectEqualStrings("a.zig", findings.items.items[0].path);
    try testing.expectEqual(1, findings.count());
}
