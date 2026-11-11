//! kept-options-pointer: an `init` copies what it keeps of a `*const` parameter.
//!
//! TigerStyle passes an argument over 16 bytes as `*const`. Zig's std copies an options struct,
//! such as `std.Thread.SpawnConfig`, and keeps no pointer to it. The owner ruled on 2026-11-07
//! that a type copies what it keeps from its options, and keeps no pointer to the caller's
//! options after `init` returns (decision 158 ruling 2). An `init` that stores the pointer makes
//! the caller keep the options alive for the life of the value.
//!
//! The rule is pepegrillo's `kept_options_pointer` (decision 36). It reads every Zig file of the
//! library and of `src/testing/`, the examples and the tools, except the files below. This file
//! holds colibri's configuration of it and the fixtures that pin that configuration.
//!
//! The excluded files hold types that no root exports (design §8 step 21d took `Connection` and
//! `QuicConnection` out of the client's and the server's lists). Each one keeps a pointer to the
//! configuration that its engine or its pool copied at its own `init` (`&engine.config`,
//! `&pool.config`), which lives as long as it does. No pointer to the program's options stays, so
//! decision 158 ruling 2 holds, and a copy in each connection would cost memory for each slot. The
//! two simulator files keep a pointer to a plan that their test owns.

const std = @import("std");
const pepegrillo = @import("pepegrillo");
const lint = pepegrillo.lint;
const kept_options_pointer = lint.rules.kept_options_pointer;

pub const config: kept_options_pointer.Config = .{
    .scope = .{
        .extensions = &.{lint.paths.zig_extension},
        .include_directories = &.{ "src", "examples", "tools" },
        .exclude_paths = &.{
            "src/client/connection/connection.zig",
            "src/client/quic/quic_connection.zig",
            "src/server/connection/connection.zig",
            "src/server/engine/engine_connections.zig",
            "src/sim/h3_endpoint.zig",
            "src/sim/h3_trace_endpoint.zig",
        },
    },
};

const Rule = kept_options_pointer.Rule(config);
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

test "kept-options-pointer refuses an init that keeps its config pointer" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try findings_of(arena_state.allocator(), "src/colibri/client.zig",
        \\pub const Connection = struct {
        \\    config: *const Config,
        \\    pub fn init(connection: *Connection, config: *const Config) void {
        \\        connection.* = .{ .config = config };
        \\    }
        \\};
    );
    try testing.expectEqual(1, findings.len);
    try testing.expectEqualStrings(name, findings[0].rule);
}

test "kept-options-pointer passes an init that copies its config, and a file outside its scope" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const copied = try findings_of(arena_state.allocator(), "src/colibri/client.zig",
        \\pub const Connection = struct {
        \\    config: Config,
        \\    pub fn init(connection: *Connection, config: *const Config) void {
        \\        connection.* = .{ .config = config.* };
        \\    }
        \\};
    );
    try testing.expectEqual(0, copied.len);
    const outside = try findings_of(arena_state.allocator(), "build/modules.zig",
        \\pub const Module = struct {
        \\    config: *const Config,
        \\    pub fn init(module: *Module, config: *const Config) void {
        \\        module.* = .{ .config = config };
        \\    }
        \\};
    );
    try testing.expectEqual(0, outside.len);
}

test "kept-options-pointer reads no connection that keeps its engine's own configuration" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const internal = try findings_of(arena_state.allocator(), "src/server/connection/connection.zig",
        \\pub const Connection = struct {
        \\    config: *const Config,
        \\    pub fn init(connection: *Connection, config: *const Config) void {
        \\        connection.* = .{ .config = config };
        \\    }
        \\};
    );
    try testing.expectEqual(0, internal.len);
}
