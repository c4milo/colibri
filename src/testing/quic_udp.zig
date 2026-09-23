//! The root of `zig build quic-udp` and of the `testing_udp` module: design §9's UDP QUIC
//! endpoint, which runs as the hq-interop server or client over one Rotor socket (decision 58),
//! with chapulin's QUIC mode behind colibri's two vtables (decision 10). Part of design §8 step
//! 9e, piece 11. It is the one module that imports Rotor, through `udp.zig`.
const std = @import("std");

pub const udp = @import("udp.zig");
pub const chapulin_quic_c = @import("quic/chapulin_quic_c.zig");
pub const chapulin_quic = @import("quic/chapulin_quic.zig");
pub const chapulin_quic_suite = @import("quic/chapulin_quic_suite.zig");
pub const hq = @import("quic/hq/hq.zig");
pub const hq_file = @import("quic/hq/hq_file.zig");
pub const hq_server = @import("quic/hq/hq_server.zig");
pub const hq_client = @import("quic/hq/hq_client.zig");
pub const udp_peer = @import("quic/udp/udp_peer.zig");
pub const udp_arguments = @import("quic/udp/udp_arguments.zig");
pub const udp_identity = @import("quic/udp/udp_identity.zig");
pub const udp_run = @import("quic/udp/udp_run.zig");

comptime {
    // The chapulin object imports `ch_assert_fail` and `ch_keylog`, which these two files export.
    // Zig analyses a file only when something references it, so these keep the exports in a build
    // with no tests.
    _ = chapulin_quic_c;
    _ = chapulin_quic;
}

pub const main = udp_run.main;

test {
    std.testing.refAllDecls(@This());
    _ = udp;
    _ = hq;
    _ = hq_server;
    _ = hq_client;
    _ = udp_peer;
    _ = udp_arguments;
    _ = udp_identity;
}
