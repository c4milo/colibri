//! slow-std: no file names a declaration of Zig's standard library that a measurement found slow,
//! where a faster replacement exists.
//!
//! In Zig 0.16, `std.mem.copyForwards` and `std.mem.copyBackwards` copy one octet a step. Design §8
//! step 55 found such a copy in `keep_unread` taking 43% of a stream route's instructions, and
//! replaced every call of the tree with `@memmove`. The owner then asked pepegrillo for a rule
//! that keeps such calls out, and pepegrillo's measurement gives its entries.
//!
//! The rule is pepegrillo's `slow_std` (decision 36), with its default entries. It reads every Zig
//! file that the other rules read: the library, `src/testing/`, the examples, the benchmarks, the
//! tools and the build. This file holds colibri's configuration of it and the fixtures that pin
//! that configuration.

const std = @import("std");
const pepegrillo = @import("pepegrillo");
const lint = pepegrillo.lint;
const slow_std = lint.rules.slow_std;

pub const config: slow_std.Config = .{
    .scope = .{
        .extensions = &.{lint.paths.zig_extension},
        .include_directories = &.{ "src", "examples", "bench", "tools", "build" },
    },
};

const Rule = slow_std.Rule(config);
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

test "slow-std refuses std.mem.copyForwards and std.mem.copyBackwards, through an alias too" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try findings_of(arena_state.allocator(), "src/server/router/router_body.zig",
        \\const std = @import("std");
        \\const mem = std.mem;
        \\pub fn keep(held: []u8, start: usize) void {
        \\    std.mem.copyForwards(u8, held, held[start..]);
        \\    mem.copyBackwards(u8, held[start..], held);
        \\}
    );
    try testing.expectEqual(2, findings.len);
    try testing.expectEqualStrings(name, findings[0].rule);
    try testing.expectEqual(4, findings[0].line);
    try testing.expectEqual(5, findings[1].line);
}

test "slow-std reads the tests, the benchmarks and the build, and passes @memmove" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const copy =
        \\const std = @import("std");
        \\pub fn shift(page: []u8) void {
        \\    std.mem.copyForwards(u8, page[0..1], page[1..2]);
        \\}
    ;
    for ([_][]const u8{ "src/testing/server_session.zig", "bench/memory.zig", "build/lint.zig" }) |path| {
        try testing.expectEqual(1, (try findings_of(arena_state.allocator(), path, copy)).len);
    }
    const moved = try findings_of(arena_state.allocator(), "src/core/reader.zig",
        \\pub fn shift(page: []u8) void {
        \\    @memmove(page[0..1], page[1..2]);
        \\}
    );
    try testing.expectEqual(0, moved.len);
}
