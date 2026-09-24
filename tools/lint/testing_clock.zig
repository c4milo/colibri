//! testing-clock: `src/testing/` names no clock. Its endpoints take each instant from Rotor's
//! loop, which reads the monotonic clock once per tick (decision 63), so a file there that names
//! `std.time` has taken a second clock.
//!
//! Randomness is not this rule's. The endpoints are real network peers: their connection IDs,
//! keys and PATH_CHALLENGE data must be unpredictable, so they may draw it. `determinism.zig`
//! holds the rest of `src/` to both.
//!
//! The rule is pepegrillo's `forbidden_references` (decision 36), as `determinism` is.
const std = @import("std");
const pepegrillo = @import("pepegrillo");
const lint = pepegrillo.lint;
const forbidden_references = lint.rules.forbidden_references;

const forbidden_prefixes = [_][]const u8{"std.time"};

pub const config: forbidden_references.Config = .{
    .name = "testing-clock",
    .scope = .{ .extensions = &.{lint.paths.zig_extension}, .include_directories = &.{"src/testing"} },
    .prefixes = &forbidden_prefixes,
    .reason = "src/testing takes each instant from Rotor's loop (decision 63)",
};

const Rule = forbidden_references.Rule(config);
pub const name = Rule.name;
pub const check = Rule.check;

// Tests.

const testing = std.testing;
const harness = lint.harness;

const reason = "src/testing takes each instant from Rotor's loop (decision 63)";

const fixture: [:0]const u8 =
    \\const std = @import("std");
    \\
    \\pub fn draw(connection_id: []u8) void {
    \\    std.crypto.random.bytes(connection_id);
    \\    const started_ns = std.time.nanoTimestamp();
    \\    _ = started_ns;
    \\}
;

test "testing-clock flags a clock in src/testing/ and lets it draw randomness" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try harness.run(arena_state.allocator(), Rule, "src/testing/endpoint.zig", fixture);
    try harness.expect_messages(findings, &.{"reference to std.time.nanoTimestamp: " ++ reason});
    try testing.expectEqual(5, findings[0].line);
}

test "testing-clock reads src/testing/ alone" {
    try testing.expect(config.scope.applies("src/testing/quic/udp/udp_run.zig"));
    try testing.expect(!config.scope.applies("src/quic/recovery.zig"));
    try testing.expect(!config.scope.applies("tools/lint/main.zig"));
}
