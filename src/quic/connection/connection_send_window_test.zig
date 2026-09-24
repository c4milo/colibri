//! The tests of what `connection_send.zig` does for RFC 9002 (decision 59): which packets it
//! records, what §7's congestion window lets through, the Initial records RFC 9001 §4.9.1
//! discards, and when RFC 9000 §10.1's idle timer restarts. Split off `connection_send_test.zig`
//! for length.
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
const timer = @import("connection_timer.zig");
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
    return send_at(test_now_ns);
}

fn send_at(now_ns: u64) !?send.Sent {
    return send.send(
        &endpoint,
        suite_holder.suite(),
        provider_holder.provider(),
        StreamProvider.none(),
        &scratch,
        &datagram,
        now_ns,
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

test "RFC 9000 §10.1: the first ack-eliciting packet since a receive restarts the idle timer" {
    open(.server);
    const first_ns = test_now_ns + 1;
    const second_ns = test_now_ns + 2;
    // An ACK alone elicits nothing and restarts nothing.
    receive_eliciting(.handshake);
    _ = try send_at(first_ns) orelse return error.NothingSent;
    try testing.expectEqual(test_now_ns, endpoint.termination.idle_since_ns);
    provider_holder = .{ .owed = &long_flight, .owed_level = .handshake };
    _ = try send_at(first_ns) orelse return error.NothingSent;
    try testing.expectEqual(first_ns, endpoint.termination.idle_since_ns);
    // "if no other ack-eliciting packets have been sent since last receiving and processing a
    // packet": a second one restarts nothing.
    _ = try send_at(second_ns) orelse return error.NothingSent;
    try testing.expectEqual(first_ns, endpoint.termination.idle_since_ns);
}

test "RFC 9002 §7.3.2: entering recovery lets one datagram past the window, and only one" {
    // A window with room leaves the allowance for when it has none.
    open(.server);
    provider_holder = .{ .owed = &flight, .owed_level = .handshake };
    endpoint.recovery.congestion.past_window_allowed = true;
    _ = try send_now() orelse return error.NothingSent;
    try testing.expect(endpoint.recovery.congestion.past_window_allowed);

    open(.server);
    provider_holder = .{ .owed = &long_flight, .owed_level = .handshake };
    leave_window(0);
    endpoint.recovery.congestion.past_window_allowed = true;
    // "If the congestion window is reduced immediately, a single packet can be sent prior to
    // reduction", which is how the octets of the lost packet go again at once.
    const sent = try send_now() orelse return error.NothingSent;
    try testing.expect(sent.packets[0].ack_eliciting);
    try testing.expectEqual(sent.len, endpoint.recovery.in_flight_len());
    try testing.expect(!endpoint.recovery.congestion.past_window_allowed);
    // The window binds again.
    try testing.expectEqual(null, try send_now());
}

/// The server of the next test: a Handshake flight owed, and a 1-RTT PING owed behind it.
fn owe_flight_and_ping() void {
    open_at(.server, &.{ .handshake, .application });
    provider_holder = .{ .owed = long_flight[0..leading_flight_len], .owed_level = .handshake };
    send.owe_probes(&endpoint, .application, 1);
}

/// Octets of the Handshake flight ahead of the PING, enough that the datagram passes the header
/// `send` needs room for before it plans anything. Test-only.
const leading_flight_len: usize = 1000;
/// Room after the Handshake packet for a 1-RTT PING before its number is widened, and not after:
/// a short header of byte 0, a four-octet connection ID and a one-octet number, one octet of
/// payload and the tag make 23, and RFC 9001 §5.4.2's widening makes 25. Test-only.
const unwidened_ping_room: u64 = 24;

test "RFC 9001 §5.4.2: no packet is planned in room its widened number would overrun" {
    owe_flight_and_ping();
    const leading_len = (try send_now() orelse return error.NothingSent).packets[0].len;
    // The same datagram again, with an allowance that leaves the PING 24 octets (RFC 9000 §8.1).
    owe_flight_and_ping();
    const allowance = leading_len + unwidened_ping_room;
    const received = allowance / constants.anti_amplification_factor + 1;
    endpoint.path.received = received;
    endpoint.path.sent = received * constants.anti_amplification_factor - allowance;
    const sent = try send_now() orelse return error.NothingSent;
    try testing.expectEqual(1, sent.count);
    try testing.expectEqual(leading_len, sent.len);
}

/// What a server received before a datagram that coalesces a widened packet with a full one.
/// Test-only.
const coalesced_allowance_received: u64 = 200;

test "RFC 9000 §8.1: a widened packet's octets count against what the rest of the datagram takes" {
    open(.server);
    endpoint.path.received = coalesced_allowance_received;
    // A lone PING at the Handshake level, widened, then 1-RTT octets that fill whatever is left.
    send.owe_probes(&endpoint, .handshake, 1);
    provider_holder = .{ .owed = &long_flight, .owed_level = .application };
    const sent = try send_now() orelse return error.NothingSent;
    try testing.expectEqual(2, sent.count);
    try testing.expectEqual(coalesced_allowance_received * constants.anti_amplification_factor, sent.len);
}

/// A round trip the pacing cases give the path, so the pacer earns at a rate rather than a whole
/// burst at once (RFC 9002 §7.7 spreads the window over the smoothed round trip). Test-only.
const paced_round_trip_ns: u64 = 100_000_000;
/// The window the pacing cases leave: ten datagrams of `datagram_len_min`, so the congestion
/// controller never holds the flight back. Test-only.
const paced_window_len: u64 = 12_000;

/// An endpoint whose pacer has just spent its credit, with window to spare.
fn open_paced() void {
    open(.server);
    endpoint.recovery.rtt.update(.{ .rtt_ns = paced_round_trip_ns, .ack_delay_ns = 0, .handshake_confirmed = false, .taken_at_ns = test_now_ns });
    leave_window(paced_window_len);
    endpoint.recovery.pacer.refill(test_now_ns, endpoint.recovery.rate());
    endpoint.recovery.pacer.on_sent(endpoint.recovery.pacer.credit_len);
}

test "RFC 9002 §7.7: the pacer holds back what the window allows, and names when to send" {
    open_paced();
    provider_holder = .{ .owed = &flight, .owed_level = .handshake };
    try testing.expectEqual(null, try send_now());
    try testing.expect(endpoint.pacing_limited);
    // RFC 9002 §7.8: a sender the pacer holds is using its window, so growth is not held back.
    try testing.expect(endpoint.window_limited);
    const deadline = timer.next(&endpoint).?;
    try testing.expectEqual(timer.Kind.pacing, deadline.kind);
    try testing.expect(deadline.at_ns > test_now_ns);
    // RFC 9000 §10.2.2: a draining connection sends nothing, so the pacer names no instant. The
    // draining period ends after the pacer's instant, so its end is not what the timer names.
    endpoint.termination.state = .draining;
    endpoint.termination.closing_since_ns = deadline.at_ns;
    endpoint.termination.closing_period_ns = paced_round_trip_ns;
    try testing.expect(timer.next(&endpoint).?.kind != .pacing);
    endpoint.termination.state = .active;
    // One nanosecond early the pacer still refuses, and at the instant it lets the flight out.
    try testing.expectEqual(null, try send_at(deadline.at_ns - 1));
    const sent = try send_at(deadline.at_ns) orelse return error.NothingSent;
    try testing.expect(sent.packets[0].ack_eliciting);
    try testing.expect(!endpoint.pacing_limited);
}

test "RFC 9002 §7.7: an ACK alone is not paced" {
    open_paced();
    receive_eliciting(.handshake);
    const sent = try send_now() orelse return error.NothingSent;
    try testing.expect(!sent.packets[0].ack_eliciting);
}
