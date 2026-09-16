//! Cognitive complexity linter for Zig source, and the check behind the CLAUDE.md rule that a
//! function stays at cognitive complexity 15 or less.
//!
//! Run:  zig build lint, which passes `--max 15` and build.zig, build, src and tools.
//!
//! The scorer is pepegrillo's (decision 36): SonarSource Cognitive Complexity mapped onto Zig, with
//! every function and every `test` block scored, one line per declaration over the threshold,
//!
//!     path:line: name scored SCORE (max N)
//!
//! and a summary line when nothing is over it. The threshold and the paths come from build.zig, so
//! this entry point configures nothing.

const std = @import("std");
const pepegrillo = @import("pepegrillo");

pub fn main(init: std.process.Init) !void {
    return pepegrillo.complexity.main(init);
}
