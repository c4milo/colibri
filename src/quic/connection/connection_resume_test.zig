//! The tests of what a connection observes for Careful Resume (`connection_resume.zig`, RFC 9959
//! §3.1 and §4.1), and of the option that starts a connection from a saved set (§3.2).
const std = @import("std");
const constants = @import("../constants.zig");
const transport_parameters = @import("../transport_parameters.zig");
const connection_module = @import("connection.zig");
const connection_resume = @import("connection_resume.zig");
const recovery_resume = @import("../recovery/recovery_resume.zig");
const recovery_congestion = @import("../recovery/recovery_congestion.zig");

const Connection = connection_module.Connection;
const testing = std.testing;

var connection: Connection align(@alignOf(Connection)) = undefined;

const start_ns: u64 = 1_000_000;
const observed_at_ns: u64 = 9_000_000_000;
const rtt_ns: u64 = 50_000_000;
const id_len: usize = 4;
const local_octet: u8 = 0xc1;
const peer_octet: u8 = 0x51;
const id: [id_len]u8 = @splat(local_octet);
const peer: [id_len]u8 = @splat(peer_octet);
/// RFC 9000 §4.1 needs a data limit above zero; no stream opens here.
const max_data: u64 = 1_000;
/// The second sample's round trip, a multiple of the first, which moves the smoothed estimate.
const longer_rtt_factor: u64 = 3;
const initial_window = recovery_congestion.initial_window(constants.protocol.datagram_len_min);
const floor = initial_window * constants.policy.resume_observed_windows_min;

fn open(controller: recovery_congestion.Controller, resumed_from: ?recovery_resume.ResumeState) void {
    connection.init(.{
        .role = .server,
        .local_parameters = parameters(),
        .now_ns = start_ns,
        .identity = .{ .local_initial_source = &id, .original_destination = &peer },
        .congestion_controller = controller,
        .resumed_from = resumed_from,
    });
}

/// RFC 9000 §4.1 needs a data limit above zero; no stream opens here.
fn parameters() transport_parameters.Parameters {
    var held = transport_parameters.Parameters.initial();
    held.initial_max_data = max_data;
    return held;
}

/// Two round trip samples: `rtt_ns`, the minimum RFC 9959 §3.1's saved_rtt reads, and a longer
/// one that moves the smoothed estimate away from it.
fn sample() void {
    connection.recovery.rtt.update(.{ .rtt_ns = rtt_ns, .ack_delay_ns = 0, .handshake_confirmed = true, .taken_at_ns = start_ns });
    connection.recovery.rtt.update(.{ .rtt_ns = longer_rtt_factor * rtt_ns, .ack_delay_ns = 0, .handshake_confirmed = true, .taken_at_ns = start_ns + 1 });
    std.debug.assert(connection.recovery.rtt.smoothed_ns != rtt_ns);
}

test "RFC 9959 §3.1: a connection with no round trip sample observes nothing" {
    open(.cubic, null);
    connection.recovery.congestion.window = 2 * floor;
    try testing.expectEqual(null, connection_resume.observe(&connection, observed_at_ns));
}

test "RFC 9959 §3.1: a window in congestion avoidance is saved, with the minimum round trip" {
    inline for (.{ .cubic, .newreno }) |controller| {
        open(controller, null);
        sample();
        connection.recovery.congestion.window = 2 * floor;
        connection.recovery.congestion.slow_start_threshold = floor;
        const state = connection_resume.observe(&connection, observed_at_ns).?;
        try testing.expectEqual(2 * floor, state.window_len);
        try testing.expectEqual(rtt_ns, state.rtt_ns);
        try testing.expectEqual(observed_at_ns, state.saved_at_ns);
        try testing.expectEqual(recovery_resume.state_version, state.version);
    }
}

test "RFC 9959 §4.1: a window in slow start is saved at half" {
    open(.cubic, null);
    sample();
    connection.recovery.congestion.window = 4 * floor;
    try testing.expectEqual(2 * floor, connection_resume.observe(&connection, observed_at_ns).?.window_len);
}

test "RFC 9959 §3.1: below four initial windows nothing is saved" {
    open(.cubic, null);
    sample();
    connection.recovery.congestion.window = floor - 1;
    connection.recovery.congestion.slow_start_threshold = 1;
    try testing.expectEqual(null, connection_resume.observe(&connection, observed_at_ns));
    connection.recovery.congestion.window = floor;
    try testing.expectEqual(floor, connection_resume.observe(&connection, observed_at_ns).?.window_len);
}

test "RFC 9959 §4.1: BBRv3 saves its model's BDP, BBR.bw over BBR.min_rtt" {
    open(.bbr, null);
    sample();
    const bbr = &connection.recovery.congestion.state.bbr;
    // 20 Mbit/s over 50 ms is 125,000 octets.
    bbr.bw = 2_500_000;
    bbr.model.min_rtt_ns = rtt_ns;
    try testing.expectEqual(125_000, connection_resume.observe(&connection, observed_at_ns).?.window_len);
}

test "RFC 9959 §3.2: a connection given a usable set starts in the Reconnaissance Phase" {
    const saved: recovery_resume.ResumeState = .{ .window_len = 2 * floor, .rtt_ns = rtt_ns, .saved_at_ns = start_ns };
    open(.cubic, saved);
    try testing.expectEqual(.reconnaissance, connection.recovery.careful_resume.phase);
    // RFC 9959 §3.2: Careful Resume does not modify the CWND before the path is confirmed.
    try testing.expectEqual(initial_window, connection.recovery.congestion.window);
    // RFC 9959 §3.2: a new path (RFC 9000 §9.4) stops Careful Resume.
    connection.recovery.on_path_changed();
    try testing.expectEqual(.off, connection.recovery.careful_resume.phase);
    open(.cubic, null);
    try testing.expectEqual(.off, connection.recovery.careful_resume.phase);
}
