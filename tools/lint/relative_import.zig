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
//!
//! The rule is pepegrillo's `relative_import` (decision 36). This file holds colibri's configuration of it
//! and the fixtures that pin that configuration.

const std = @import("std");
const pepegrillo = @import("pepegrillo");
const lint = pepegrillo.lint;
const relative_import = lint.rules.relative_import;

/// The configuration. It reads `src/` and flags a path holding `../` or starting with `/`.
pub const config: relative_import.Config = .{
    .scope = .{ .extensions = &.{lint.paths.zig_extension}, .include_directories = &.{"src"} },
    .mode = .parent_or_absolute,
    .message = "@import(\"{[path]s}\") reaches out of the module by path;" ++
        " import the module name build/modules.zig declares",
};

const Rule = relative_import.Rule(config);
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
    try testing.expect(config.scope.applies("src/quic/packet/header.zig"));
    try testing.expect(!config.scope.applies("tools/lint/main.zig"));
    try testing.expect(!config.scope.applies("build/modules.zig"));
    try harness.expect_messages(try findings_of(arena, "tools/graph_gate.zig", failing_fixture), &.{});
}

test "relative-import reads the path as written, not where it resolves" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    // Both paths resolve inside `src/quic/`. The rule flags them all the same, because it reads a
    // `../` segment and does not resolve it.
    const findings = try findings_of(arena_state.allocator(), "src/quic/packet/packet_header.zig",
        \\const constants = @import("../constants.zig");
        \\const frame = @import("stream/../frame.zig");
    );
    try harness.expect_messages(findings, &.{
        "@import(\"../constants.zig\") reaches out of the module by path;" ++
            " import the module name build/modules.zig declares",
        "@import(\"stream/../frame.zig\") reaches out of the module by path;" ++
            " import the module name build/modules.zig declares",
    });
}
