//! global-state: the library holds no `var` that every thread shares.
//!
//! The caller owns every struct and buffer (CLAUDE.md non-negotiable 4, decision 35), and one
//! program may run a colibri connection on each of its threads. A container-level `var` is one
//! copy for the whole process, which two such threads race on. The rule refuses it unless it is
//! `threadlocal`, or the state is handed in.
//!
//! The rule is pepegrillo's `global_state` (decision 36). It reads the library modules under
//! `src/` and leaves out what never runs on a caller's threads:
//!   1. `src/testing/`, whose servers share an array indexed by worker on purpose. Made
//!      `threadlocal`, the array would be copied into every thread, and glibc places a thread's
//!      static TLS on that thread's stack;
//!   2. `src/sim/` and `src/golden/`, which run on one thread;
//!   3. the test files, which run on the test runner's one thread: `*_test.zig`, the fixtures
//!      several files' tests share in `*_test_support.zig`, and `*_fuzz.zig`.
//!
//! A test fixture declared in a library file is still read, because the rule cannot tell it from
//! the file's other declarations. One that a single file uses is `threadlocal`, which costs a test
//! binary nothing. One that several files share cannot be: their tests name it through a `const`
//! holding its address, which a `threadlocal` does not have at compile time. So it lives in a
//! `*_test_support.zig` file beside them.
//!
//! This file holds colibri's configuration of the rule and the fixtures that pin it.

const std = @import("std");
const pepegrillo = @import("pepegrillo");
const lint = pepegrillo.lint;
const global_state = lint.rules.global_state;

pub const config: global_state.Config = .{
    .scope = .{
        .extensions = &.{lint.paths.zig_extension},
        .include_directories = &.{"src"},
        .exclude_directories = &.{ "src/testing", "src/sim", "src/golden" },
        .exclude_basename_suffixes = &.{"_fuzz.zig"},
        .exclude_stem_segment = "_test",
    },
};

const Rule = global_state.Rule(config);
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

test "global-state refuses a shared var in a library module, and passes a threadlocal one" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const findings = try findings_of(arena_state.allocator(), "src/quic/stream/stream_provider.zig",
        \\var none_context: u8 = 0;
        \\threadlocal var test_section: FieldSection = undefined;
    );
    try harness.expect_messages(findings, &.{
        "var none_context is state every thread shares: make it threadlocal, or hand it in",
    });
}

test "global-state leaves out the endpoints, the simulator, the corpus and the test files" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const source = "var workers: [4]Worker = undefined;";
    for ([_][]const u8{
        "src/testing/server.zig",
        "src/sim/run_main.zig",
        "src/golden/corpus.zig",
        "src/qpack/decoder_test.zig",
        "src/h2/connection/connection_test_support.zig",
        "src/h3/frame_fuzz.zig",
    }) |path| {
        const findings = try findings_of(arena_state.allocator(), path, source);
        try testing.expectEqual(0, findings.len);
    }
}
