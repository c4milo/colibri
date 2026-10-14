//! `zig build test` runs each top-level step whose name ends in `-check`, such as `routes-check`
//! and `routes-hidden-check`. CI runs `zig build test` through `tools/ci.sh`, so a check that
//! `test` does not run is a check that CI does not run.
//!
//! `require` reads the step graph after build.zig has made it. A `-check` step runs in `test`
//! when `test` depends on it, or on each step that it depends on. `golden-check` is of the second
//! kind: it depends on the run of the golden module's tests alone. When a check does not run,
//! `zig build test` fails and names it. Other steps, such as `zig build lint`, still run.
const std = @import("std");

/// The end of the name of each top-level step that `zig build test` runs.
const check_suffix = "-check";

/// Makes `zig build test` fail for each top-level `-check` step that it does not run. Call it
/// after every step is made.
pub fn require(b: *std.Build, test_step: *std.Build.Step) void {
    for (b.top_level_steps.keys(), b.top_level_steps.values()) |name, top_level| {
        if (!std.mem.endsWith(u8, name, check_suffix)) continue;
        if (runs(test_step, &top_level.step)) continue;
        const fail = b.addFail(b.fmt("zig build test does not run zig build {s}", .{name}));
        test_step.dependOn(&fail.step);
    }
}

/// Whether `test_step` runs `step`: it depends on `step`, or on each step that `step` depends on.
/// A step with no dependencies does no work, so `test_step` runs it.
fn runs(test_step: *const std.Build.Step, step: *const std.Build.Step) bool {
    if (depends_on(test_step, step)) return true;
    for (step.dependencies.items) |dependency| {
        if (!depends_on(test_step, dependency)) return false;
    }
    return true;
}

/// Whether `dependency` is one of the steps that `step` depends on directly.
fn depends_on(step: *const std.Build.Step, dependency: *const std.Build.Step) bool {
    for (step.dependencies.items) |item| {
        if (item == dependency) return true;
    }
    return false;
}
