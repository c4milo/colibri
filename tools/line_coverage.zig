//! The line coverage of the library modules, through pepegrillo's `coverage` tool. It runs the
//! test binary of each module under kcov 43, and prints the share of each module's lines that the
//! tests run, with a total. build/line_coverage.zig gives it the binaries.
//!
//! The directories are those of the modules the package exports (decision 86). The simulator,
//! `src/golden/`, `src/testing/`, `tools/` and `examples/` are not the library, so no line of them
//! counts. Zig compiles only the functions that code references, so a function that no test
//! references has no line to count: the share is of the lines that the tests compile.
//!
//! Run: `tools/line_coverage_check.sh`, which runs `zig build line-coverage` on Linux.

const std = @import("std");
const pepegrillo = @import("pepegrillo");

pub fn main(init: std.process.Init) !void {
    return pepegrillo.coverage.main(init, .{
        .directories = &.{
            "src/core",  "src/wire",   "src/http",   "src/tls_provider", "src/crypto",  "src/qlog",
            "src/hpack", "src/qpack",  "src/quic",   "src/h2",           "src/h3",      "src/h11",
            "src/tls",   "src/dnssec", "src/server", "src/client",       "src/colibri",
        },
    });
}
