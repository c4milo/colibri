//! static-alignment: a container-level `var` states its own alignment.
//!
//! Zig 0.16's x86_64 backend, which builds Debug on x86_64 Linux, can place a global without the
//! alignment its type gets from an aligned field. It placed `udp_run.memory`, a `udp.Memory`
//! whose loop memory is declared `align(64)`, 16 octets past a multiple of 64. Rotor's io_uring
//! loop then panicked on its first table, and every server check in CI failed with it. LLVM, which
//! builds aarch64, places it right, so macOS never showed it. A global declared
//! `var memory: Memory align(@alignOf(Memory))` is placed right by every backend.
//!
//! The rule is pepegrillo's `static_alignment` (decision 36). It reads every Zig file colibri
//! builds and runs: the library and `src/testing/` under `src/`, `examples/`, and the tools. This
//! file holds colibri's configuration of it and the fixtures that pin that configuration.

const std = @import("std");
const pepegrillo = @import("pepegrillo");
const lint = pepegrillo.lint;
const static_alignment = lint.rules.static_alignment;

pub const config: static_alignment.Config = .{
    .scope = .{
        .extensions = &.{lint.paths.zig_extension},
        .include_directories = &.{ "src", "examples", "tools" },
    },
};

const Rule = static_alignment.Rule(config);
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

test "static-alignment asks the endpoint's memory for its alignment" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try findings_of(arena_state.allocator(), "src/testing/quic/udp/udp_run.zig",
        \\var memory: udp.Memory = undefined;
        \\var workers: [4]Worker = undefined;
    );
    try harness.expect_messages(findings, &.{
        "var memory declares no alignment: write align(@alignOf(udp.Memory))",
        "var workers declares no alignment: write align(@alignOf(Worker))",
    });
}

test "static-alignment passes a stated alignment, a primitive, and a file outside its scope" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const stated = try findings_of(arena_state.allocator(), "examples/h2_exchange.zig",
        \\var link: Link align(@alignOf(Link)) = undefined;
        \\var octets: [64]u8 = undefined;
    );
    try testing.expectEqual(0, stated.len);
    const outside = try findings_of(arena_state.allocator(), "build/modules.zig",
        \\var memory: Memory = undefined;
    );
    try testing.expectEqual(0, outside.len);
}
