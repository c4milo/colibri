//! type-function-suffix: a public type function is named for the thing it returns.
//!
//! Zig's std names a function that returns a type for the thing that type is: `std.ArrayList(T)`
//! and `std.StaticBitSet(size)`, never `ArrayListOf(T)`. The owner ruled on 2026-11-07 that
//! colibri's public API follows TigerStyle first and then std's idioms (decision 158), and
//! decision 156 ruling 1 renamed `ClientOf` and `ServerOf` to `Client` and `Server` for this
//! reason.
//!
//! The rule is pepegrillo's `type_function_suffix` (decision 36). It reads every Zig file of the
//! library and of `src/testing/`, the examples and the tools, so a test-only type function
//! follows the same rule. This file holds colibri's configuration of it and the fixtures that pin
//! that configuration.

const std = @import("std");
const pepegrillo = @import("pepegrillo");
const lint = pepegrillo.lint;
const type_function_suffix = lint.rules.type_function_suffix;

pub const config: type_function_suffix.Config = .{
    .scope = .{
        .extensions = &.{lint.paths.zig_extension},
        .include_directories = &.{ "src", "examples", "tools" },
    },
};

const Rule = type_function_suffix.Rule(config);
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

test "type-function-suffix refuses a public type function named with Of" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try findings_of(arena_state.allocator(), "src/colibri/client.zig",
        \\pub fn ClientOf(comptime capacity: Capacity) type {
        \\    return struct { held: [capacity.count]u8 };
        \\}
    );
    try testing.expectEqual(1, findings.len);
    try testing.expectEqualStrings(name, findings[0].rule);
}

test "type-function-suffix passes a type function named for its thing, and a file outside its scope" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const named = try findings_of(arena_state.allocator(), "src/colibri/client.zig",
        \\pub fn Client(comptime capacity: Capacity) type {
        \\    return struct { held: [capacity.count]u8 };
        \\}
    );
    try testing.expectEqual(0, named.len);
    const outside = try findings_of(arena_state.allocator(), "build/modules.zig",
        \\pub fn ModuleOf(comptime name: []const u8) type {
        \\    return struct { name: []const u8 = name };
        \\}
    );
    try testing.expectEqual(0, outside.len);
}
