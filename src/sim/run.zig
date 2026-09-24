//! The simulator's driver: the checks of design §8 and the command line `zig build sim` runs.
//!
//! This file is a module of its own, `sim_run`, not part of `sim`. A check drives a protocol module
//! through the harness, and `sim` must import none, so the one module that imports both is this
//! one and build/modules.zig enforces the direction. Every file it reaches imports `sim` by its
//! module name, never by path, so no file of `sim` is compiled into this module a second time.
//!
//! The check of step 2 is `chunk_check.zig`, the check of step 4 is `connection_check.zig`, and
//! the check of step 11 is `qpack_check.zig`. Each one's test runs in `zig build test`, silently,
//! and `zig build sim -- --<check>-seed <hex>` or `--<check>-check [seeds]` runs it by hand
//! (`run_main.zig`).
const std = @import("std");

pub const chunk_stream = @import("chunk_stream.zig");
pub const chunk_check = @import("chunk_check.zig");
pub const connection_invariants = @import("connection_invariants.zig");
pub const connection_stream = @import("connection_stream.zig");
pub const connection_check = @import("connection_check.zig");
pub const tls_check = @import("tls_check.zig");
pub const cost_check = @import("cost_check.zig");
pub const qpack_plan = @import("qpack_plan.zig");
pub const qpack_check = @import("qpack_check.zig");
const run_main = @import("run_main.zig");

pub const main = run_main.main;

test {
    std.testing.refAllDecls(@This());
    _ = chunk_stream;
    _ = chunk_check;
    _ = connection_invariants;
    _ = connection_stream;
    _ = connection_check;
    _ = tls_check;
    _ = cost_check;
    _ = qpack_plan;
    _ = qpack_check;
    _ = run_main;
}
