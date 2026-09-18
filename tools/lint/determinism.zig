//! determinism: time is a value the caller passes and randomness is the caller's (CLAUDE.md
//! non-negotiables 3 and 5, invariants 4 and 5). One seed replays byte-identically across hosts
//! and build modes, which holds only while a connection's output is a pure function of its
//! configuration, the bytes it was fed, and the instants it was given.
//!
//! Over every `.zig` file under `src/`, the rule flags a chain that starts with `std.time`,
//! `std.Random` or `std.crypto.random` at a dot boundary. RFC 9002's pseudocode reads `now()` at
//! nine sites and all nine become parameters on five entry points (design §8 step 10), so a file
//! that names a clock has taken one of them back.
//!
//! `std.time` is flagged whole, its unit constants included: `std.time.ns_per_ms` reads no clock,
//! but a duration colibri uses is a named limit in a module's `constants.zig` and never an
//! expression written inline (CLAUDE.md non-negotiable 4), so the constants file is where the
//! multiplier belongs.
//!
//! What the rule cannot see: a clock reached through a parameter or a vtable, `provider.now()`.
//! That is the shape colibri wants — the caller supplies the instant — and the rule cannot tell
//! it from a caller-supplied value that happens to be named `now`. It reads what a file under
//! `src/` names in `std`, which is where a clock would have to come from.
//!
//! The rule is pepegrillo's `forbidden_references` (decision 36). This file holds colibri's configuration of it
//! and the fixtures that pin that configuration.

const std = @import("std");
const pepegrillo = @import("pepegrillo");
const lint = pepegrillo.lint;
const forbidden_references = lint.rules.forbidden_references;

/// A chain that starts with one of these at a dot boundary is a finding: the clock, the general
/// pseudo-random generator, and the system entropy source.
const forbidden_prefixes = [_][]const u8{ "std.time", "std.Random", "std.crypto.random" };

/// The configuration. It reads `src/`, `src/testing/` included.
pub const config: forbidden_references.Config = .{
    .name = "determinism",
    .scope = .{ .extensions = &.{lint.paths.zig_extension}, .include_directories = &.{"src"} },
    .prefixes = &forbidden_prefixes,
    .reason = "time is a caller-supplied parameter and randomness is the caller's" ++
        " (invariants 4 and 5)",
};

const Rule = forbidden_references.Rule(config);
pub const name = Rule.name;
pub const check = Rule.check;

// Tests. Each fixture pins one shape from the header.

const testing = std.testing;
const harness = lint.harness;

const reason = "time is a caller-supplied parameter and randomness is the caller's" ++
    " (invariants 4 and 5)";

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
    \\
    \\/// RFC 9002 §5.3: the probe timeout is armed from the instant the caller hands in.
    \\pub fn on_packet_sent(self: *Recovery, now_ns: u64, packet: Packet) void {
    \\    self.last_sent_ns = now_ns;
    \\    self.timeout_ns = now_ns + self.probe_timeout_ns;
    \\    self.largest_sent = packet.number;
    \\}
    \\
    \\/// The connection id the caller drew; colibri never draws one.
    \\pub fn set_connection_id(self: *Recovery, id: []const u8) void {
    \\    self.connection_id = id;
    \\}
;

const failing_fixture: [:0]const u8 =
    \\const std = @import("std");
    \\
    \\pub fn on_packet_sent(self: *Recovery, packet: Packet) void {
    \\    self.last_sent_ns = std.time.nanoTimestamp();
    \\    self.timeout_ns = self.last_sent_ns + 3 * std.time.ns_per_ms;
    \\    self.connection_id = std.crypto.random.int(u64);
    \\    var generator = std.Random.DefaultPrng.init(0);
    \\    self.jitter = generator.random().int(u8);
    \\    _ = packet;
    \\}
;

test "determinism passes a file that takes the instant as a parameter" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try findings_of(arena_state.allocator(), "src/quic/recovery.zig", passing_fixture);
    try harness.expect_messages(findings, &.{});
}

test "determinism flags the clock, the unit constants, the PRNG and the entropy source" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try findings_of(arena_state.allocator(), "src/quic/recovery.zig", failing_fixture);
    try harness.expect_messages(findings, &.{
        "reference to std.time.nanoTimestamp: " ++ reason,
        "reference to std.time.ns_per_ms: " ++ reason,
        "reference to std.crypto.random.int: " ++ reason,
        "reference to std.Random.DefaultPrng.init: " ++ reason,
    });
    try testing.expectEqual(4, findings[0].line);
    try testing.expectEqual(7, findings[3].line);
}

test "determinism does not flag a name that merely resembles one on the list" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try findings_of(arena_state.allocator(), "src/quic/recovery.zig",
        \\const timeout_ns = constants.probe_timeout_ns;
        \\const hash = std.crypto.hash.sha2.Sha256;
        \\const elapsed = now_ns - self.last_sent_ns;
        \\const times = self.retry_times;
    );
    try harness.expect_messages(findings, &.{});
}

test "determinism reads src/ alone, src/testing/ included" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try testing.expect(config.scope.applies("src/quic/recovery.zig"));
    try testing.expect(config.scope.applies("src/testing/endpoint.zig"));
    try testing.expect(!config.scope.applies("tools/lint/main.zig"));
    try testing.expect(!config.scope.applies("docs/design.md"));
    try harness.expect_messages(try findings_of(arena, "tools/graph_check.zig", failing_fixture), &.{});
    const in_testing = try findings_of(arena, "src/testing/endpoint.zig", failing_fixture);
    try testing.expectEqual(4, in_testing.len);
}
