//! The tests of the probe packets RFC 9002 §6.2.4 owes when a PTO fires: ack-eliciting, carrying
//! a PING when nothing else would elicit an acknowledgment, and counted off per packet at the
//! level they were owed at.
//!
//! The fixture is `packet_build_test.zig`'s, which builds through a connection pair and reads the
//! frames back.
const std = @import("std");
const core = @import("core");
const constants = @import("../../constants.zig");
const frames = @import("../connection_frames.zig");
const keys = @import("../connection_keys.zig");
const send = @import("../connection_send.zig");
const connection_module = @import("../connection.zig");
const fixture = @import("packet_build_test.zig");

const connection_recovery = @import("../connection_recovery.zig");
const testing = std.testing;
const Connection = connection_module.Connection;
const test_now_ns: u64 = 1_000_000;
const challenge_octet: u8 = 0x3d;
const challenge_data: [constants.path_challenge_len]u8 = @splat(challenge_octet);

/// The fixture's pair with 1-RTT keys, the handshake complete and nothing owed.
fn open_application() void {
    fixture.open_connection();
    for ([_]*Connection{ &fixture.test_connection, &fixture.peer_connection }) |connection| {
        keys.on_keys_installed(connection, .application, .read);
        keys.on_keys_installed(connection, .application, .write);
        connection.handshake_complete = true;
    }
    fixture.fake = .{};
}

/// Reads a built packet back at the peer and returns what its frames amounted to.
fn read_back(built: anytype) !frames.Report {
    const opened = try fixture.walk_back(built);
    return frames.process(&fixture.peer_connection, opened, test_now_ns, &recovery_scratch);
}

/// Where an ACK frame's packets go while RFC 9002 takes them (decision 59). Test-only.
var recovery_scratch: connection_recovery.Scratch = undefined;

test "RFC 9002 §6.2.4: a probe with nothing to send is a PING, and each owed probe is one packet" {
    open_application();
    // Nothing is owed, so nothing is built.
    try testing.expectEqual(null, try fixture.build_at(.application));
    send.owe_probes(&fixture.test_connection, .application, constants.probe_packets);
    for (0..constants.probe_packets) |_| {
        const built = (try fixture.build_at(.application)).?;
        // "All probe packets sent on a PTO MUST be ack-eliciting."
        try testing.expect(built.ack_eliciting);
        try testing.expect(built.in_flight);
        const report = try read_back(built);
        try testing.expectEqual(1, report.frames);
        try testing.expect(report.ack_eliciting);
    }
    try testing.expectEqual(null, try fixture.build_at(.application));
}

test "RFC 9002 §6.2.4: a probe carries what else is owed, and a PING only when that elicits nothing" {
    open_application();
    send.owe_probes(&fixture.test_connection, .application, 1);
    // A frame that elicits an acknowledgment is the probe; no PING is added beside it.
    fixture.test_connection.path.owe_challenge(challenge_data);
    const built = (try fixture.build_at(.application)).?;
    try testing.expectEqual(1, (try read_back(built)).frames);
    try testing.expectEqual(0, fixture.test_connection.probes_owed[@intFromEnum(core.Level.application)]);

    // A pending ACK elicits nothing, so a probe beside it carries a PING, and the ACK is not taken
    // back as one standing alone would be (RFC 9000 §13.2.1).
    _ = fixture.peer_connection.space_at(.application).next_number() catch unreachable;
    _ = fixture.test_connection.space_at(.application).receive(0, test_now_ns, true, .not_ect);
    send.owe_probes(&fixture.test_connection, .application, 1);
    const with_ack = (try fixture.build_at(.application)).?;
    try testing.expect(with_ack.ack_eliciting);
    try testing.expectEqual(2, (try read_back(with_ack)).frames);
}

test "RFC 9002 §6.2.4: a probe owed at one level is sent at that level alone" {
    open_application();
    send.owe_probes(&fixture.test_connection, .initial, 1);
    try testing.expectEqual(null, try fixture.build_at(.application));
    const built = (try fixture.build_at(.initial)).?;
    try testing.expect(built.ack_eliciting);
    try testing.expectEqual(core.Level.initial, built.level);
    // Owing fewer than already owed leaves the larger count.
    send.owe_probes(&fixture.test_connection, .application, constants.probe_packets);
    send.owe_probes(&fixture.test_connection, .application, 1);
    try testing.expectEqual(constants.probe_packets, fixture.test_connection.probes_owed[@intFromEnum(core.Level.application)]);
}
