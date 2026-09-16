//! The simulator's driver: the gates of design §8 and the command line `zig build sim` runs.
//!
//! This file is a module of its own, `sim_run`, not part of `sim`. A gate drives a protocol module
//! through the harness, and `sim` must import none, so the one module that imports both is this
//! one and build/modules.zig enforces the direction. Every file it reaches imports `sim` by its
//! module name, never by path, so no file of `sim` is compiled into this module a second time.
//!
//! The gate of step 2 is `chunk_gate.zig`. Its test runs in `zig build test`, silently, and
//! `zig build sim -- --chunk-seed <hex>` or `--chunk-gate [seeds]` runs it by hand (`run_main.zig`).
const std = @import("std");

pub const chunk_stream = @import("chunk_stream.zig");
pub const chunk_gate = @import("chunk_gate.zig");
const run_main = @import("run_main.zig");

pub const main = run_main.main;

test {
    std.testing.refAllDecls(@This());
    _ = chunk_stream;
    _ = chunk_gate;
    _ = run_main;
}
