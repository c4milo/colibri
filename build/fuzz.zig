//! The test runner of `-Dfuzz` (decision 144, https://github.com/c4milo/colibri/issues/53).
//!
//! Zig 0.16.0's own test runner does not compile with `-ffuzz`: one line passes a
//! `std.builtin.StackTrace` where `std.debug.writeStackTrace` takes a `std.debug.StackTrace`.
//! This file reads that runner from the Zig in use, replaces the one line, and gives the result to
//! each unit test. It holds no copy of the runner. When the line is gone, as in Zig 0.17.0, the
//! build stops and says to remove `-Dfuzz`.
const std = @import("std");

/// The runner's path inside Zig's library directory.
const runner_path = "compiler/test_runner.zig";

/// More octets than Zig 0.16.0's runner holds, which is about 24,000.
const runner_len_max = 1 << 20;

/// The line that fails to compile, at test_runner.zig:566 of Zig 0.16.0.
const broken_line = "std.debug.writeStackTrace(trace, stderr) catch break :p;";

/// The same call, with the error return trace given as the type `writeStackTrace` takes.
const fixed_line = "std.debug.writeStackTrace(&.{ .return_addresses = " ++
    "trace.instruction_addresses[0..@min(trace.index, trace.instruction_addresses.len)], " ++
    ".skipped = .none }, stderr) catch break :p;";

/// Gives the runner for `b.addTest`. It runs in server mode, which reports each fuzz test to the
/// build runner, as Zig's default runner does.
pub fn test_runner(b: *std.Build) std.Build.Step.Compile.TestRunner {
    const library = b.graph.zig_lib_directory.handle;
    const source = library.readFileAlloc(b.graph.io, runner_path, b.allocator, .limited(runner_len_max)) catch |err|
        std.debug.panic("-Dfuzz: cannot read {s} from Zig's library: {t}", .{ runner_path, err });
    if (std.mem.count(u8, source, broken_line) != 1)
        std.debug.panic("-Dfuzz: Zig's test runner no longer holds the line it fixes; remove -Dfuzz (decision 144)", .{});
    const patched = std.mem.replaceOwned(u8, b.allocator, source, broken_line, fixed_line) catch @panic("out of memory");
    const files = b.addWriteFiles();
    return .{ .path = files.add("test_runner.zig", patched), .mode = .server };
}
