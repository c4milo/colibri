//! The tests of what `connection_send.zig` does for RFC 9002 (decision 59): which packets it
//! records, what §7's congestion window lets through, and the Initial records RFC 9001 §4.9.1
//! discards. Split off `connection_send_test.zig` for length.
const std = @import("std");
const core = @import("core");
const constants = @import("../constants.zig");
const error_code = @import("../error_code.zig");
const transport_parameters = @import("../transport_parameters.zig");
const StreamProvider = @import("../stream/stream_provider.zig").StreamProvider;
const connection_module = @import("connection.zig");
const keys = @import("connection_keys.zig");
const close_module = @import("connection_close.zig");
const id_frames = @import("connection_id_frames.zig");
const send = @import("connection_send.zig");
const build_test = @import("packet_build/packet_build_test.zig");

const Level = core.Level;
const Connection = connection_module.Connection;
const Parameters = transport_parameters.Parameters;
const testing = std.testing;

var endpoint: Connection = undefined;
/// Larger than §14.1's smallest allowed maximum, so a peer that accepts more lets the window be
/// what bounds a packet. Test-only.
const datagram_buffer_len: usize = 3000;
var scratch: send.Scratch(datagram_buffer_len) = .{};
var datagram: [datagram_buffer_len]u8 = undefined;
var suite_holder: build_test.RoundTrip = undefined;
var provider_holder: build_test.Fake = undefined;

const test_now_ns: u64 = 1_000_000;
const test_max_data: u64 = 1_048_576;
const id_len: usize = 4;
const local_octet: u8 = 0xc1;
const peer_octet: u8 = 0x51;
const local_id: [id_len]u8 = @splat(local_octet);
const peer_id: [id_len]u8 = @splat(peer_octet);
/// Handshake octets the provider owes: a few, and more than any datagram here holds. Test-only.
const flight_octet: u8 = 0x6d;
const flight_len: usize = 40;
const flight: [flight_len]u8 = @splat(flight_octet);
const long_flight: [datagram_buffer_len]u8 = @splat(flight_octet);
/// A window above one datagram and below the datagram the peer accepts. Test-only.
const partial_window_len: u64 = 1500;
const issued_octet: u8 = 0x6a;
const issued_id: [id_len]u8 = @splat(issued_octet);
const token_octet: u8 = 0x9d;
const token: [constants.stateless_reset_token_len]u8 = @splat(token_octet);

fn parameters() Parameters {
    var held = Parameters.initial();
    held.initial_max_data = test_max_data;
    return held;
}

/// An endpoint holding keys at every level, which a server may use once it has received enough
/// to leave RFC 9000 §8.1's limit out of these tests.
fn open(role: connection_module.Role) void {
    open_at(role, &.{ .initial, .handshake, .application });
}

/// `open`, with keys at `levels` alone.
fn open_at(role: connection_module.Role, levels: []const Level) void {
    suite_holder.init();
    provider_holder = .{};
    endpoint.init(.{
        .role = role,
        .local_parameters = parameters(),
        .now_ns = test_now_ns,
        .identity = .{ .local_initial_source = &local_id, .original_destination = &peer_id },
    });
    for (levels) |level| {
        keys.on_keys_installed(&endpoint, level, .read);
        keys.on_keys_installed(&endpoint, level, .write);
    }
    if (role == .server) endpoint.path.on_datagram_received(datagram_buffer_len);
}

fn send_now() !?send.Sent {
    return send.send(
        &endpoint,
        suite_holder.suite(),
        provider_holder.provider(),
        StreamProvider.none(),
        &scratch,
        &datagram,
        test_now_ns,
    );
}

/// Leaves `len` octets of congestion window above what is in flight.
fn leave_window(len: u64) void {
    endpoint.recovery.congestion.window = endpoint.recovery.in_flight_len() + len;
}

/// One ack-eliciting packet arrives at `level`. RFC 9000 §13.2.1 has an Initial or Handshake
/// one acknowledged at once, and lets a 1-RTT one wait for max_ack_delay.
fn receive_eliciting(level: Level) void {
    _ = endpoint.space_at(level).receive(0, test_now_ns, true, .not_ect);
}

test "RFC 9002 A.5, decision 59: a packet in flight is recorded with what it carried" {
    open(.server);
    provider_holder = .{ .owed = &flight, .owed_level = .handshake };
    const sent = try send_now() orelse return error.NothingSent;
    const table = endpoint.recovery.table_of(.handshake);
    try testing.expectEqual(1, table.count());
    const record = table.oldest().?;
    try testing.expectEqual(sent.packets[0].packet_number, record.number);
    try testing.expectEqual(test_now_ns, record.sent_at_ns);
    try testing.expectEqual(sent.len, record.sent_len);
    try testing.expect(record.ack_eliciting and record.in_flight);
    try testing.expectEqual(.crypto, record.carries);
    try testing.expectEqual(flight_len, record.data_len);
    try testing.expectEqual(sent.len, endpoint.recovery.in_flight_len());
    // RFC 9002 §7.8: the window had room, so it was not what bounded sending.
    try testing.expect(!endpoint.window_limited);
}

test "RFC 9002 A.1: a packet of ACK frames alone is not recorded" {
    open(.server);
    receive_eliciting(.handshake);
    const sent = try send_now() orelse return error.NothingSent;
    try testing.expect(!sent.packets[0].ack_eliciting);
    try testing.expectEqual(0, endpoint.recovery.table_of(.handshake).count());
}

test "RFC 9002 §7: a window that cannot hold the datagram holds back what is in flight, not an ACK" {
    open(.server);
    provider_holder = .{ .owed = &flight, .owed_level = .handshake };
    receive_eliciting(.handshake);
    leave_window(constants.datagram_len_min - 1);
    const held_back = try send_now() orelse return error.NothingSent;
    try testing.expect(!held_back.packets[0].ack_eliciting);
    try testing.expectEqual(flight_len, provider_holder.owed.len);
    try testing.expect(endpoint.window_limited);
    // A whole datagram's worth of window lets the octets go.
    leave_window(constants.datagram_len_min);
    const sent = try send_now() orelse return error.NothingSent;
    try testing.expect(sent.packets[0].ack_eliciting);
    try testing.expectEqual(0, provider_holder.owed.len);
    try testing.expect(!endpoint.window_limited);
}

test "RFC 9002 §7: no packet takes more than the window leaves, nor does the next one" {
    open(.server);
    var peer = parameters();
    peer.max_udp_payload_size = datagram_buffer_len;
    endpoint.apply_peer_parameters(peer);
    // Handshake octets to fill the window, and a 1-RTT frame to go after them.
    provider_holder = .{ .owed = &long_flight, .owed_level = .handshake };
    _ = try id_frames.issue(&endpoint, &issued_id, &token);
    leave_window(partial_window_len);
    const sent = try send_now() orelse return error.NothingSent;
    try testing.expect(sent.len <= partial_window_len);
    try testing.expectEqual(sent.len, endpoint.recovery.in_flight_len());
    // The Handshake packet took the window, so the NEW_CONNECTION_ID waits.
    try testing.expect(endpoint.local_ids.active_ids()[1].new_frame.owed);
}

test "RFC 9000 §13.2.1: a window that holds everything back sends no ACK that could wait" {
    open(.server);
    receive_eliciting(.application);
    _ = try id_frames.issue(&endpoint, &issued_id, &token);
    leave_window(0);
    // A lone ACK is not owed yet, and nothing it could go out with may.
    try testing.expectEqual(null, try send_now());
    try testing.expect(endpoint.space_at(.application).has_new_ack_eliciting());
}

test "RFC 9002 §7: a probe goes whatever the window says" {
    open(.server);
    leave_window(0);
    send.owe_probes(&endpoint, .handshake, 1);
    const sent = try send_now() orelse return error.NothingSent;
    try testing.expect(sent.packets[0].ack_eliciting);
    try testing.expectEqual(1, endpoint.recovery.table_of(.handshake).count());
}

test "RFC 9000 §14.1: a client the window holds back sends no Initial, not even an ACK" {
    open(.client);
    receive_eliciting(.initial);
    leave_window(0);
    try testing.expectEqual(null, try send_now());
    // With a datagram's worth of window the ACK goes, padded to 1,200 octets and so in flight
    // (RFC 9002 §2), which is why it is recorded although it elicits nothing.
    leave_window(constants.datagram_len_min);
    const sent = try send_now() orelse return error.NothingSent;
    try testing.expectEqual(constants.datagram_len_min, sent.len);
    try testing.expectEqual(sent.len, endpoint.recovery.in_flight_len());
}

test "RFC 9000 §10.2.1: a CONNECTION_CLOSE goes whatever the window says, and is not recorded" {
    // RFC 9000 §10.2.3: a client closes in an Initial while that is all it can send.
    open_at(.client, &.{.initial});
    leave_window(0);
    close_module.owe(&endpoint, close_module.transport(error_code.internal_error, null));
    const sent = try send_now() orelse return error.NothingSent;
    try testing.expectEqual(Level.initial, sent.packets[0].level);
    // RFC 9000 §14.1 pads a client's Initial, so the datagram is in flight, and still nothing is recorded.
    try testing.expect(sent.packets[sent.count - 1].in_flight);
    try testing.expectEqual(0, endpoint.recovery.in_flight_len());
}

test "constants.sent_packets_max: a space whose table is full sends nothing, not even an ACK" {
    open(.server);
    for (0..constants.sent_packets_max) |number| {
        try endpoint.recovery.on_packet_sent(.handshake, .{
            .number = number,
            .sent_at_ns = test_now_ns,
            .sent_len = 1,
            .ack_eliciting = false,
            .in_flight = false,
        }, test_now_ns);
    }
    provider_holder = .{ .owed = &flight, .owed_level = .handshake };
    receive_eliciting(.handshake);
    try testing.expectEqual(null, try send_now());
    // Another space's table is its own (RFC 9000 §12.3).
    receive_eliciting(.initial);
    const sent = try send_now() orelse return error.NothingSent;
    try testing.expectEqual(Level.initial, sent.packets[0].level);
    try testing.expectEqual(1, sent.count);
}

test "RFC 9001 §4.9.1: a client's first Handshake packet discards the Initial keys and records" {
    open(.client);
    // A probe owed at Initial puts an Initial packet in flight ahead of the Handshake one.
    send.owe_probes(&endpoint, .initial, 1);
    provider_holder = .{ .owed = &flight, .owed_level = .handshake };
    const sent = try send_now() orelse return error.NothingSent;
    try testing.expectEqual(2, sent.count);
    try testing.expectEqual(Level.initial, sent.packets[0].level);
    // "a client MUST discard Initial keys when it first sends a Handshake packet"
    try testing.expectEqual(keys.State.discarded, endpoint.keys.at(.initial, .write));
    // RFC 9002 §6.4: the Initial packet leaves flight with its keys, and the Handshake one stays.
    try testing.expectEqual(0, endpoint.recovery.table_of(.initial).count());
    try testing.expectEqual(sent.packets[1].len, endpoint.recovery.in_flight_len());
}
