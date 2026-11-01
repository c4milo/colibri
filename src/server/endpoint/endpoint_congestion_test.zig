//! The congestion controller a server's QUIC connections run (decisions 136 and 143, design §8
//! step 29c).
const std = @import("std");
const support = @import("../quic/quic_test_support.zig");

const testing = std.testing;
const endpoint_support = support.endpoint_support;

test "decision 143: a server runs BBRv3 on each QUIC connection by default" {
    try support.start_endpoint(null);
    try support.connect();
    const state = support.served.transport.recovery.congestion.state;
    try testing.expectEqual(.bbr, std.meta.activeTag(state));
    // Decision 136: its probe waits come from the program's source, not a fixed value.
    try testing.expect(state.bbr.bandwidth_probe_waits != 0);
}

test "decision 143: a server's QUIC connection runs BBRv3 when its own configuration names none" {
    // The connection started with its configuration's defaults, not through an endpoint.
    try support.start();
    try support.connect();
    const state = support.connection.transport.recovery.congestion.state;
    try testing.expectEqual(.bbr, std.meta.activeTag(state));
    try testing.expect(state.bbr.bandwidth_probe_waits != 0);
}

test "decision 136: a server whose configuration names CUBIC runs it on each QUIC connection" {
    try support.start_endpoint(null);
    endpoint_support.endpoint_config.congestion_controller = .cubic;
    defer endpoint_support.endpoint_config.congestion_controller = .bbr;
    try endpoint_support.restart();
    try support.connect();
    try testing.expectEqual(.cubic, std.meta.activeTag(support.served.transport.recovery.congestion.state));
}
