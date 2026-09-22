//! The tests of what a packet carries when its space owes an acknowledgment (RFC 9000 §13.2.1):
//! one that must go out at once, and one that may wait for max_ack_delay.
//!
//! The fixture is `packet_build_test.zig`'s, because these build through the same connection pair
//! and read the frames back with the same walk; split off that file for length.
const std = @import("std");
const core = @import("core");
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
