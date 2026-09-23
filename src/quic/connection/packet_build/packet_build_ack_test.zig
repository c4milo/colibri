//! The tests of what a packet carries when its space owes an acknowledgment (RFC 9000 §13.2.1):
//! one that must go out at once, and one that may wait for max_ack_delay.
//!
//! The fixture is `packet_build_test.zig`'s, because these build through the same connection pair
//! and read the frames back with the same walk; split off that file for length.
const std = @import("std");
const core = @import("core");
const constants = @import("../../constants.zig");
const frames = @import("../connection_frames.zig");
const keys = @import("../connection_keys.zig");
const connection_module = @import("../connection.zig");
const fixture = @import("packet_build_test.zig");

const testing = std.testing;
const Connection = connection_module.Connection;
const test_now_ns: u64 = 1_000_000;

test "RFC 9000 §13.2.1: an acknowledgment goes out and elicits nothing" {
    fixture.open_connection();
    // One ack-eliciting Initial arrived, which §13.2.1 says must be acknowledged immediately.
    _ = fixture.test_connection.space_at(.initial).receive(0, test_now_ns, true, .not_ect);
    try testing.expect(fixture.test_connection.space_at(.initial).owes_ack(test_now_ns, fixture.test_connection.max_ack_delay_ns()));
    const built = (try fixture.build_at(.initial)).?;
    // Table 3 marks ACK with N, so a packet of only ACK frames is not ack-eliciting, and
    // RFC 9002 §2 keeps it out of the bytes in flight.
    try testing.expect(!built.ack_eliciting);
    try testing.expect(!built.in_flight);

    // It reads back as an ACK naming the packet that arrived. The peer must have sent that
    // packet for §13.1 to admit the acknowledgment, so its space is advanced first.
    _ = try fixture.peer_connection.space_at(.initial).next_number();
    const opened = try fixture.walk_back(built);
    const report = try frames.process(&fixture.peer_connection, opened, test_now_ns);
    try testing.expectEqual(1, report.frames);
    try testing.expect(!report.ack_eliciting);
    try testing.expectEqual(0, fixture.peer_connection.space_at(.initial).largest_acknowledged.?);
}

test "RFC 9000 §13.2.1: an ACK goes out once max_ack_delay has passed" {
    fixture.open_connection();
    for ([_]*Connection{ &fixture.test_connection, &fixture.peer_connection }) |connection| {
        keys.on_keys_installed(connection, .application, .read);
        keys.on_keys_installed(connection, .application, .write);
        connection.handshake_complete = true;
    }
    // The peer has sent one packet, so an ACK naming number 0 is not §13.1's acknowledgment of a
    // packet that was never sent when it reads the frame back.
    _ = fixture.peer_connection.space_at(.application).next_number() catch unreachable;
    // One in-order ack-eliciting 1-RTT packet, which §13.2.2's count of two does not cover.
    _ = fixture.test_connection.space_at(.application).receive(0, test_now_ns, true, .not_ect);
    fixture.fake = .{};

    // Before the delay runs out nothing is owed, so there is nothing to build.
    const deadline_ns = test_now_ns + fixture.test_connection.max_ack_delay_ns();
    try testing.expectEqual(null, try fixture.build_at_instant(.application, deadline_ns - 1));

    // "ack-eliciting packets MUST be acknowledged at least once within the maximum delay an
    // endpoint communicated using the max_ack_delay transport parameter."
    const built = (try fixture.build_at_instant(.application, deadline_ns)).?;
    const opened = try fixture.walk_back(built);
    const report = try frames.process(&fixture.peer_connection, opened, test_now_ns);
    try testing.expectEqual(1, report.frames);
    // Table 3 marks ACK N, so the packet that carries one elicits nothing itself.
    try testing.expect(!report.ack_eliciting);
}

/// A PATH_CHALLENGE's data, which gives a packet a frame of its own. Test-only.
const challenge_octet: u8 = 0x5c;
const challenge_data: [constants.path_challenge_len]u8 = @splat(challenge_octet);

test "RFC 9000 §13.2.1: an ACK not yet owed goes out with other frames, and only then" {
    fixture.open_connection();
    for ([_]*Connection{ &fixture.test_connection, &fixture.peer_connection }) |connection| {
        keys.on_keys_installed(connection, .application, .read);
        keys.on_keys_installed(connection, .application, .write);
        connection.handshake_complete = true;
    }
    _ = fixture.peer_connection.space_at(.application).next_number() catch unreachable;
    const space = fixture.test_connection.space_at(.application);
    _ = space.receive(0, test_now_ns, true, .not_ect);
    try testing.expect(!space.owes_ack(test_now_ns, fixture.test_connection.max_ack_delay_ns()));
    fixture.fake = .{};

    // "An endpoint SHOULD send an ACK frame with other frames when there are new ack-eliciting
    // packets to acknowledge": a packet going out anyway carries it, before its deadline.
    fixture.test_connection.path.owe_challenge(challenge_data);
    const built = (try fixture.build_at_instant(.application, test_now_ns)).?;
    try testing.expect(!space.has_new_ack_eliciting());
    const opened = try fixture.walk_back(built);
    const report = try frames.process(&fixture.peer_connection, opened, test_now_ns);
    try testing.expectEqual(2, report.frames);
    try testing.expectEqual(0, fixture.peer_connection.space_at(.application).largest_acknowledged.?);

    // With nothing new to acknowledge, the next packet's other frame goes alone.
    fixture.test_connection.path.owe_challenge(challenge_data);
    const next = (try fixture.build_at_instant(.application, test_now_ns)).?;
    const next_opened = try fixture.walk_back(next);
    try testing.expectEqual(1, (try frames.process(&fixture.peer_connection, next_opened, test_now_ns)).frames);
}

test "RFC 9000 §13.2.2: an ACK taken back leaves the count, so the second packet still earns one" {
    fixture.open_connection();
    keys.on_keys_installed(&fixture.test_connection, .application, .read);
    keys.on_keys_installed(&fixture.test_connection, .application, .write);
    fixture.test_connection.handshake_complete = true;
    fixture.fake = .{};
    const space = fixture.test_connection.space_at(.application);
    _ = space.receive(0, test_now_ns, true, .not_ect);
    // The ACK is pending and would stand alone, so it is taken back.
    try testing.expectEqual(null, try fixture.build_at_instant(.application, test_now_ns));
    // §13.2.2: a receiver sends one "after receiving at least two ack-eliciting packets".
    _ = space.receive(1, test_now_ns, true, .not_ect);
    try testing.expect(space.owes_ack(test_now_ns, fixture.test_connection.max_ack_delay_ns()));
}
