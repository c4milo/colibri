//! The tests of decision 65 in `connection_recovery.zig`: a server whose client shows it lacks the
//! server's Initial CRYPTO octets sends them again before the PTO, a limited number of times
//! (RFC 9002 §6.2.3). Split from `connection_recovery_test.zig`, which a hand-written file of 500
//! lines could not also hold.
const std = @import("std");
const constants = @import("../constants.zig");
const transport_parameters = @import("../transport_parameters.zig");
const recovery_sent = @import("../recovery/recovery_sent.zig");
const space_module = @import("../space/space.zig");
const connection_module = @import("connection.zig");
const keys = @import("connection_keys.zig");
const recovery = @import("connection_recovery.zig");

const Connection = connection_module.Connection;
const testing = std.testing;

var endpoint: Connection = undefined;
var scratch: recovery.Scratch = undefined;

const test_now_ns: u64 = 1_000_000;
const test_max_data: u64 = 1_048_576;
const id_len: usize = 4;
const local_octet: u8 = 0xc1;
const peer_octet: u8 = 0x51;
const local_id: [id_len]u8 = @splat(local_octet);
const peer_id: [id_len]u8 = @splat(peer_octet);
/// The server's ServerHello, as the octets its Initial CRYPTO flow carried. Test-only.
const flight_len: usize = 90;
/// The client's ClientHello, which the server has read before it sends anything. Test-only.
const client_hello_len: usize = 40;
const client_hello_octet: u8 = 0x16;
const client_hello: [client_hello_len]u8 = @splat(client_hello_octet);

fn parameters() transport_parameters.Parameters {
    var held = transport_parameters.Parameters.initial();
    held.initial_max_data = test_max_data;
    return held;
}

/// An endpoint of `role` that has read the ClientHello and sent `flight_len` Initial CRYPTO
/// octets in one packet still in flight.
fn open_with_flight(role: connection_module.Role) !void {
    endpoint.init(.{
        .role = role,
        .local_parameters = parameters(),
        .now_ns = test_now_ns,
        .identity = .{ .local_initial_source = &local_id, .original_destination = &peer_id },
    });
    keys.on_keys_installed(&endpoint, .initial, .read);
    keys.on_keys_installed(&endpoint, .initial, .write);
    const stream = endpoint.crypto_at(.initial);
    try stream.receive(0, &client_hello);
    _ = stream.send_room();
    stream.produced(flight_len);
    stream.framed(flight_len);
    try record_sent(.crypto);
}

/// Records one ack-eliciting Initial packet in flight that carried `carries`.
fn record_sent(carries: recovery_sent.Carries) !void {
    const number = try endpoint.space_at(.initial).next_number();
    try endpoint.recovery.on_packet_sent(.initial, .{
        .number = number,
        .sent_at_ns = test_now_ns,
        .sent_len = constants.datagram_len_min,
        .ack_eliciting = true,
        .in_flight = true,
        .carries = carries,
        .data_offset = 0,
        .data_len = flight_len,
    }, test_now_ns);
}

/// The server has processed an ack-eliciting Initial packet whose CRYPTO octets, if any, it
/// already held: a repeated ClientHello, or a client's padded PING.
fn take_repeat() !void {
    const received_len = endpoint.crypto_at(.initial).received_len();
    try recovery.on_initial_processed(&endpoint, true, received_len, &scratch);
}

fn initial_in_flight() usize {
    return endpoint.recovery.table_of(space_module.Kind.initial).count();
}

test "decision 65: a repeat from the client sends the server's Initial CRYPTO octets again" {
    try open_with_flight(.server);
    const window = endpoint.recovery.congestion.window;
    try take_repeat();
    // RFC 9002 §6.2.3: "send a packet containing unacknowledged CRYPTO data earlier than the PTO
    // expiry". The packet is declared lost, so its octets wait to be framed again.
    try testing.expectEqual(0, initial_in_flight());
    try testing.expectEqual(flight_len, endpoint.crypto_at(.initial).unsent().len);
    try testing.expectEqual(1, endpoint.early_crypto_resends);
    // Declared lost to move the octets, as decision 64 does, and not for congestion.
    try testing.expectEqual(window, endpoint.recovery.congestion.window);
}

test "decision 65: new CRYPTO octets, or a packet the peer need not acknowledge, show nothing" {
    try open_with_flight(.server);
    // The client's flight was still arriving: the octets moved `received_len`.
    const before = endpoint.crypto_at(.initial).received_len() - client_hello.len;
    try recovery.on_initial_processed(&endpoint, true, before, &scratch);
    try testing.expectEqual(1, initial_in_flight());
    // An ACK alone asks for no answer (RFC 9002 §2).
    try recovery.on_initial_processed(&endpoint, false, endpoint.crypto_at(.initial).received_len(), &scratch);
    try testing.expectEqual(1, initial_in_flight());
    try testing.expectEqual(0, endpoint.early_crypto_resends);
}

test "decision 65: a client sends nothing early" {
    try open_with_flight(.client);
    try take_repeat();
    try testing.expectEqual(1, initial_in_flight());
    try testing.expectEqual(0, endpoint.crypto_at(.initial).unsent().len);
}

test "decision 65: with no CRYPTO octets in flight nothing is sent and the limit is not spent" {
    try open_with_flight(.server);
    endpoint.recovery.discard_space(.initial);
    // A PING in flight, which carries nothing to send again.
    try record_sent(.none);
    try take_repeat();
    try testing.expectEqual(1, initial_in_flight());
    try testing.expectEqual(0, endpoint.early_crypto_resends);
}

test "decision 65: RFC 9002 §6.2.3's limited number of times per connection" {
    try open_with_flight(.server);
    for (0..constants.early_crypto_resends_max) |_| {
        try take_repeat();
        try testing.expectEqual(0, initial_in_flight());
        // The octets go out again in a new packet, which is in flight in turn.
        endpoint.crypto_at(.initial).framed(flight_len);
        try record_sent(.crypto);
    }
    try take_repeat();
    try testing.expectEqual(1, initial_in_flight());
    try testing.expectEqual(constants.early_crypto_resends_max, endpoint.early_crypto_resends);
}
