//! determinism: time is a value the caller passes and randomness is the caller's (CLAUDE.md
//! non-negotiables 3 and 5, invariants 4 and 5). One seed replays byte-identically across hosts
//! and build modes, which holds only while a connection's output is a pure function of its
//! configuration, the bytes it was fed, and the instants it was given.
//!
//! Over every `.zig` file under `src/` but `src/testing/`, the rule flags a chain that starts with
//! `std.time`, `std.Random` or `std.crypto.random` at a dot boundary. `src/testing/` holds real
//! network endpoints, whose connection IDs, keys and PATH_CHALLENGE data must be unpredictable,
//! so they may draw randomness; `testing_clock.zig` holds them to decision 63's clock rule alone. RFC 9002's pseudocode reads `now()` at
//! nine sites and all nine become parameters on five entry points (design §8 step 10), so a file
//! that names a clock has taken one of them back.
//!
//! Zig 0.16 reads the clock and the entropy source through `std.Io`, so the rule also flags a
//! chain that starts with `std.Io.Clock` or `std.Io.Timestamp.now`, or with the same names under
//! `Io.`, the spelling behind `const Io = std.Io;`. It flags a call of a `std.Io` timestamp or
//! timeout method that reads the clock, such as `started.untilNow(io)`, a call of
//! `randomSecure`, and a call of `random` on a receiver whose name contains `io`, such as
//! `io.random(&buffer)`. Those method names are camelCase and colibri's are snake_case, so none
//! collides. The `io` rule refuses `std.Io` outside `src/testing/` already; this rule reads
//! `src/testing/` too.
//!
//! `std.time` is flagged whole, its unit constants included: `std.time.ns_per_ms` reads no clock,
//! but a duration colibri uses is a named limit in a module's `constants.zig` and never an
//! expression written inline (CLAUDE.md non-negotiable 4), so the constants file is where the
//! multiplier belongs.
//!
//! What the rule cannot see: a clock reached through a parameter or a vtable, `provider.now()`,
//! and a `std.Io.Clock` value passed in and read as `clock.now(io)`. A decl literal such as
//! `.fromNow(io, duration)` names no receiver, so it is invisible too. A parameter is the shape
//! colibri wants — the caller supplies the instant — and the rule cannot tell it from a
//! caller-supplied value that happens to be named `now`. It reads what a file under `src/` names
//! in `std`, which is where a clock would have to come from.
//!
//! The rule is pepegrillo's `forbidden_references` (decision 36). This file holds colibri's configuration of it
//! and the fixtures that pin that configuration.

const std = @import("std");
const pepegrillo = @import("pepegrillo");
const lint = pepegrillo.lint;
const forbidden_references = lint.rules.forbidden_references;

/// A chain that starts with one of these at a dot boundary is a finding: the clock, the general
/// pseudo-random generator, the system entropy source, and the `std.Io` clock and timestamp read.
const forbidden_prefixes = [_][]const u8{
    "std.time",
    "std.Random",
    "std.crypto.random",
    "std.Io.Clock",
    "Io.Clock",
    "std.Io.Timestamp.now",
    "Io.Timestamp.now",
};

/// A call whose callee ends with one of these is a finding: the `std.Io` timestamp and timeout
/// methods that read the clock, and the secure entropy source.
const forbidden_callee_names = [_][]const u8{
    "fromNow",
    "untilNow",
    "durationFromNow",
    "toClock",
    "toDeadline",
    "toTimestamp",
    "toDurationFromNow",
    "randomSecure",
};

/// The configuration. It reads `src/`, and not `src/testing/`.
pub const config: forbidden_references.Config = .{
    .name = "determinism",
    .scope = .{
        .extensions = &.{lint.paths.zig_extension},
        .include_directories = &.{"src"},
        .exclude_directories = &.{"src/testing"},
    },
    .prefixes = &forbidden_prefixes,
    .callee_names = &forbidden_callee_names,
    // `io.random(&buffer)` fills a buffer from the host's generator; the receiver's name tells it
    // from a seeded generator's `random()`, which the AST cannot tell by type.
    .method_calls = .{ .methods_on_named_receivers = &.{"random"}, .receiver_words = &.{"io"} },
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

test "determinism flags the std.Io clock, its timestamp reads and the host generator" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try findings_of(arena_state.allocator(), "src/quic/recovery.zig",
        \\const a = std.Io.Clock.awake.now(io);
        \\const b = Io.Clock.real;
        \\const c = std.Io.Timestamp.now(io, .real);
        \\const d = Io.Timestamp.now(io, .awake);
        \\const e = started.untilNow(io);
        \\const f = deadline.durationFromNow(io);
        \\const g = Timestamp.fromNow(io, duration);
        \\const h = started.toClock(io, .real);
        \\const i = timeout.toDeadline(io);
        \\const j = timeout.toTimestamp(io);
        \\const k = timeout.toDurationFromNow(io);
        \\fn seed(self: *Connection, bytes: []u8) !void {
        \\    try io.randomSecure(bytes);
        \\    self.io.random(bytes);
        \\}
    );
    try harness.expect_messages(findings, &.{
        "reference to std.Io.Clock.awake.now: " ++ reason,
        "reference to Io.Clock.real: " ++ reason,
        "reference to std.Io.Timestamp.now: " ++ reason,
        "reference to Io.Timestamp.now: " ++ reason,
        "reference to started.untilNow: " ++ reason,
        "reference to deadline.durationFromNow: " ++ reason,
        "reference to Timestamp.fromNow: " ++ reason,
        "reference to started.toClock: " ++ reason,
        "reference to timeout.toDeadline: " ++ reason,
        "reference to timeout.toTimestamp: " ++ reason,
        "reference to timeout.toDurationFromNow: " ++ reason,
        "reference to io.randomSecure: " ++ reason,
        "reference to random: " ++ reason,
    });
}

test "determinism does not flag the simulator clock, a seeded generator, or std.Io values" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try findings_of(arena_state.allocator(), "src/sim/pipe.zig",
        \\const Clock = @import("clock.zig").Clock;
        \\const now_ns = pipe.clock.now();
        \\const byte = generator.random().int(u8);
        \\const elapsed = std.Io.Timestamp.durationTo(started, finished);
        \\const later = std.Io.Timestamp.addDuration(started, window);
    );
    try harness.expect_messages(findings, &.{});
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

test "determinism reads src/ alone, and not src/testing/" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try testing.expect(config.scope.applies("src/quic/recovery.zig"));
    try testing.expect(config.scope.applies("src/sim/network.zig"));
    try testing.expect(!config.scope.applies("src/testing/endpoint.zig"));
    try testing.expect(!config.scope.applies("tools/lint/main.zig"));
    try testing.expect(!config.scope.applies("docs/design.md"));
    try harness.expect_messages(try findings_of(arena, "tools/graph_check.zig", failing_fixture), &.{});
    try harness.expect_messages(try findings_of(arena, "src/testing/endpoint.zig", failing_fixture), &.{});
}
