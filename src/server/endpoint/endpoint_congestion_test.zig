//! The congestion controller a server's QUIC connections run (decision 136, design §8 step 29c).
const std = @import("std");
const support = @import("../quic/quic_test_support.zig");

const testing = std.testing;
const endpoint_support = support.endpoint_support;

test "decision 136: a server runs CUBIC on each QUIC connection by default" {
    try support.start_endpoint(null);
    try support.connect();
    try testing.expectEqual(.cubic, std.meta.activeTag(support.served.transport.recovery.congestion.state));
}

test "decision 136: a server whose configuration names BBRv3 runs it on each QUIC connection" {
    try support.start_endpoint(null);
    endpoint_support.endpoint_config.congestion_controller = .bbr;
    defer endpoint_support.endpoint_config.congestion_controller = .cubic;
    try endpoint_support.restart();
    try support.connect();
    const state = support.served.transport.recovery.congestion.state;
    try testing.expectEqual(.bbr, std.meta.activeTag(state));
    // Decision 136: its probe waits come from the program's source, not a fixed value.
    try testing.expect(state.bbr.bandwidth_probe_waits != 0);
}
