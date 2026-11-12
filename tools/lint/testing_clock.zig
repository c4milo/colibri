//! testing-clock: `src/testing/` names no clock. Its endpoints take each instant from Rotor's
//! loop, which reads the monotonic clock once per tick (decision 63), so a file there that names
//! `std.time` has taken a second clock. Zig 0.16 also reads the clock through `std.Io`, so the
//! rule refuses `std.Io.Clock` and `std.Io.Timestamp` too, and the same names under `Io.`, the
//! spelling behind `const Io = std.Io;` (https://github.com/c4milo/colibri/pull/17).
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

const forbidden_prefixes = [_][]const u8{ "std.time", "std.Io.Clock", "std.Io.Timestamp", "Io.Clock", "Io.Timestamp" };

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
    \\
    \\pub fn elapsed(io: std.Io, started: Io.Timestamp) u64 {
    \\    const now = std.Io.Timestamp.now(io, .awake);
    \\    const deadline = std.Io.Clock.Timestamp.fromNow(io, .awake, .zero);
    \\    _ = deadline;
    \\    return started.durationTo(now).nanoseconds;
    \\}
;

test "testing-clock flags a clock in src/testing/ and lets it draw randomness" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try harness.run(arena_state.allocator(), Rule, "src/testing/endpoint.zig", fixture);
    try harness.expect_messages(findings, &.{
        "reference to std.time.nanoTimestamp: " ++ reason,
        "reference to Io.Timestamp: " ++ reason,
        "reference to std.Io.Timestamp.now: " ++ reason,
        "reference to std.Io.Clock.Timestamp.fromNow: " ++ reason,
    });
    try testing.expectEqual(5, findings[0].line);
    try testing.expectEqual(9, findings[1].line);
}

test "testing-clock reads src/testing/ alone" {
    try testing.expect(config.scope.applies("src/testing/quic/udp/udp_run.zig"));
    try testing.expect(!config.scope.applies("src/quic/recovery.zig"));
    try testing.expect(!config.scope.applies("tools/lint/main.zig"));
}
