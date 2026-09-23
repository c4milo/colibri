//! The driver of the simulator's QUIC checks. It is a module of its own, `sim_run_quic`, apart
//! from `sim_run`, for one reason: build/modules.zig gives it `sim` and `quic` and no HTTP module.
//! Decision 5 has QUIC know nothing about HTTP, and the check that proves it is that the QUIC
//! harness builds and runs with no HTTP module in the graph (design §3, §8 step 8). `sim_run`
//! drives `h2`, so a QUIC check placed there would prove nothing of the kind.
//!
//! The check of step 7 is `packet_check.zig` and the check of step 8 is `network_check.zig`.
//! Both run in `zig build test`, and `zig build test-sim-run-quic` runs them alone.
const std = @import("std");

pub const packet_check = @import("packet_check.zig");
pub const network_check = @import("network_check.zig");
pub const recovery_check = @import("recovery_check.zig");
pub const recovery_check_run = @import("recovery_check_run.zig");
pub const quic_connection_check = @import("quic_connection_check.zig");

test {
    std.testing.refAllDecls(@This());
    _ = packet_check;
    _ = network_check;
    _ = recovery_check;
    _ = recovery_check_run;
    _ = quic_connection_check;
}
