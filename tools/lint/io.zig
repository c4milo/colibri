//! io: colibri owns no I/O (CLAUDE.md non-negotiable 1, invariant 2). No socket, no file
//! descriptor, no poll, no thread. Frames and heads are written into storage the caller owns and
//! parsed out of bytes the caller has already read, so every function that would block returns
//! what it wants instead.
//!
//! Over every `.zig` file under `src/` but not under `src/testing/`, the rule flags a chain that
//! starts with one of `forbidden_prefixes` at a dot boundary: `std.posix`, `std.fs`, `std.net`,
//! `std.Thread`, `std.Io` and `std.process`. `src/testing/` holds the test-only entry points of
//! design §9 and is the one directory permitted to touch a socket (CLAUDE.md, Layout), so it is
//! exempt.
//!
//! The rule reads what a file names, not what it reaches. A module that received another module
//! from build/modules.zig can call through it, and this rule cannot see where that call ends up.
//! The module graph is what bounds that; this rule is what stops a file under `src/` reaching the
//! host through `std` directly.

const std = @import("std");
const chain_scan = @import("chain_scan.zig");
const paths = @import("paths.zig");
const report = @import("report.zig");

pub const name = "io";

/// The directory the rule reads.
const source_directory = "src";

/// The one directory under `src/` permitted to touch a socket: the test-only entry points of
/// docs/design.md §9, which are excluded from the packaged library.
const exempt_directory = "src/testing";

/// A chain that starts with one of these at a dot boundary is a finding. Each names a way to
/// reach the host: the syscall surface, the filesystem, the network, threads, the `std.Io`
/// interface every blocking call now takes, and the process table.
const forbidden_prefixes = [_][]const u8{
    "std.posix",
    "std.fs",
    "std.net",
    "std.Thread",
    "std.Io",
    "std.process",
};

const forbidden: chain_scan.Forbidden = .{
    .name = name,
    .prefixes = &forbidden_prefixes,
    .reason = "colibri owns no I/O (invariant 2)",
};

pub fn applies(path: []const u8) bool {
    if (!paths.has_extension(path, paths.zig_extension)) return false;
    if (paths.is_under(path, exempt_directory)) return false;
    return paths.is_under(path, source_directory);
}

pub fn check(context: *report.Context, file: report.File) !void {
    if (!applies(file.path)) return;
    try chain_scan.scan(context, file, forbidden);
}

// Tests. Each fixture pins one shape from the header.

const testing = std.testing;
const harness = @import("harness.zig");

fn findings_of(
    arena: std.mem.Allocator,
    path: []const u8,
    source: [:0]const u8,
) ![]const report.Finding {
    return harness.run(arena, @This(), path, source);
}

const passing_fixture: [:0]const u8 =
    \\const std = @import("std");
    \\const core = @import("core");
    \\
    \\/// Parses one frame head out of bytes the caller has already read.
    \\pub fn parse_head(bytes: []const u8) !Head {
    \\    if (bytes.len < head_len) return error.ShortBuffer;
    \\    return .{ .length = std.mem.readInt(u24, bytes[0..3], .big) };
    \\}
    \\
    \\/// Writes one frame head into storage the caller owns.
    \\pub fn write_head(head: Head, into: []u8) !usize {
    \\    if (into.len < head_len) return error.ShortBuffer;
    \\    std.mem.writeInt(u24, into[0..3], head.length, .big);
    \\    return head_len;
    \\}
;

const failing_fixture: [:0]const u8 =
    \\const std = @import("std");
    \\
    \\pub fn serve(port: u16) !void {
    \\    const address = try std.net.Address.parseIp("127.0.0.1", port);
    \\    const socket = try std.posix.socket(2, 1, 0);
    \\    const thread = try std.Thread.spawn(.{}, run, .{socket});
    \\    thread.join();
    \\    _ = address;
    \\}
;

test "io passes a file that parses bytes the caller read" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try findings_of(arena_state.allocator(), "src/h2/frame.zig", passing_fixture);
    try harness.expect_messages(findings, &.{});
}

test "io flags the network, the syscall surface and threads" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try findings_of(arena_state.allocator(), "src/h2/frame.zig", failing_fixture);
    try harness.expect_messages(findings, &.{
        "reference to std.net.Address.parseIp: colibri owns no I/O (invariant 2)",
        "reference to std.posix.socket: colibri owns no I/O (invariant 2)",
        "reference to std.Thread.spawn: colibri owns no I/O (invariant 2)",
    });
    try testing.expectEqual(4, findings[0].line);
}

test "io flags every prefix on its list, in a parameter type as well as a body" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try findings_of(arena_state.allocator(), "src/quic/quic.zig",
        \\fn send(socket: std.posix.socket_t, file: std.fs.File, count: u32) void {}
        \\const reader = std.Io.Reader;
        \\const argv = std.process.args;
        \\const listener = std.net.Server;
        \\const worker = std.Thread;
    );
    try harness.expect_messages(findings, &.{
        "reference to std.posix.socket_t: colibri owns no I/O (invariant 2)",
        "reference to std.fs.File: colibri owns no I/O (invariant 2)",
        "reference to std.Io.Reader: colibri owns no I/O (invariant 2)",
        "reference to std.process.args: colibri owns no I/O (invariant 2)",
        "reference to std.net.Server: colibri owns no I/O (invariant 2)",
        "reference to std.Thread: colibri owns no I/O (invariant 2)",
    });
}

test "io does not flag a name that merely starts with the same letters" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try findings_of(arena_state.allocator(), "src/quic/quic.zig",
        \\const bytes = constants.std_posix_bytes;
        \\const written = std.fmt.bufPrint(&buffer, "{d}", .{1});
        \\const order = std.mem.readInt(u32, bytes[0..4], .big);
    );
    try harness.expect_messages(findings, &.{});
}

test "io exempts src/testing/ and reads nothing outside src/" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try testing.expect(applies("src/quic/quic.zig"));
    try testing.expect(!applies("src/testing/endpoint.zig"));
    try testing.expect(!applies("./src/testing/deep/endpoint.zig"));
    try testing.expect(!applies("tools/lint/main.zig"));
    try harness.expect_messages(try findings_of(arena, "src/testing/endpoint.zig", failing_fixture), &.{});
    try harness.expect_messages(try findings_of(arena, "tools/graph_gate.zig", failing_fixture), &.{});
}
