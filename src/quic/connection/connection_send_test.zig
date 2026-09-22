//! The tests of `connection_send.zig`: RFC 9000 §12.2's coalescing, §14.1's expansion under
//! decision 54, and §8's anti-amplification limit.
//!
//! Every datagram is walked back by `connection_receive.zig`, so the coalescing is checked by the
//! code that has to take it apart rather than against an expected byte string.
const std = @import("std");
const core = @import("core");
const crypto = @import("crypto");
const tls = @import("tls");
const constants = @import("../constants.zig");
const transport_parameters = @import("../transport_parameters.zig");
const connection_module = @import("connection.zig");
const keys = @import("connection_keys.zig");
const receive = @import("connection_receive.zig");
const frames = @import("connection_frames.zig");
const send = @import("connection_send.zig");
const connection_crypto = @import("connection_crypto.zig");
const recovery_sent = @import("../recovery/recovery_sent.zig");
const build_test = @import("packet_build/packet_build_test.zig");

const testing = std.testing;
const Level = core.Level;
const Connection = connection_module.Connection;
const Parameters = transport_parameters.Parameters;
const Record = recovery_sent.Record;

var client: Connection = undefined;
var server: Connection = undefined;
/// As large as the datagram buffer, so what bounds a datagram in these tests is the rule under
/// test and never the scratch. A caller that places a smaller one gets smaller packets, which
/// `packet_build_test.zig` pins.
var scratch: send.Scratch(datagram_buffer_len) = .{};
/// Larger than §14.1's smallest allowed maximum, so a peer that accepts more can be believed.
const datagram_buffer_len: usize = 2000;
var datagram: [datagram_buffer_len]u8 = undefined;
/// Longer than any datagram these tests build, so the provider always has more to give.
const long_flight_len: usize = datagram_buffer_len;
const long_flight: [long_flight_len]u8 = @splat(flight_octet);
var suite_holder: build_test.RoundTrip = undefined;
var provider_holder: build_test.Fake = undefined;

const test_now_ns: u64 = 1_000_000;
const test_max_data: u64 = 1_048_576;
const local_octet: u8 = 0xc1;
const peer_octet: u8 = 0x51;
const id_len: usize = 4;
const local_id: [id_len]u8 = @splat(local_octet);
const peer_id: [id_len]u8 = @splat(peer_octet);

const flight_octet: u8 = 0x6d;
const flight_len: usize = 40;
const flight: [flight_len]u8 = @splat(flight_octet);

fn parameters() Parameters {
    var held = Parameters.initial();
    held.initial_max_data = test_max_data;
    return held;
}

fn open_pair() void {
    suite_holder.init();
    provider_holder = .{};
    open_one(&client, .client);
    open_one(&server, .server);
}

fn open_one(connection: *Connection, role: connection_module.Role) void {
    connection.init(.{
        .role = role,
        .local_parameters = parameters(),
        .now_ns = test_now_ns,
        .identity = .{ .local_initial_source = &local_id, .original_destination = &peer_id },
    });
    for ([_]Level{ .initial, .handshake }) |level| {
        keys.on_keys_installed(connection, level, .read);
        keys.on_keys_installed(connection, level, .write);
    }
}

fn send_from(connection: *Connection) !?send.Sent {
    return send.send(
        connection,
        suite_holder.suite(),
        provider_holder.provider(),
        &scratch,
        &datagram,
        test_now_ns,
    );
}

/// Walks a datagram back as the other endpoint, and returns how many packets it held.
fn walk_back(reader: *Connection, sent: send.Sent) !usize {
    var walk: receive.Walk = undefined;
    walk.init(.{ .octets = datagram[0..sent.len], .now_ns = test_now_ns, .ecn = .not_ect });
    var seen: usize = 0;
    // Bounded by what one datagram can hold (RFC 9000 §12.2).
    while (seen < constants.coalesced_packets_max) {
        const outcome = try receive.next(&walk, reader, suite_holder.suite()) orelse break;
        switch (outcome) {
            .opened => |opened| {
                seen += 1;
                _ = try frames.process(reader, opened, test_now_ns);
            },
            // RFC 9000 §19.1: the PADDING that expands a datagram is a frame like any other, and
            // a packet carrying only it is still a packet the walk takes.
            .discarded => break,
        }
    }
    return seen;
}

test "RFC 9000 §12.2: two levels are coalesced into one datagram, in increasing order" {
    open_pair();
    // The client owes a flight at both handshake levels, which is the case §12.2 exists for.
    _ = client.space_at(.initial).receive(0, test_now_ns, true, .not_ect);
    provider_holder = .{ .owed = &flight, .owed_level = .initial };
    const first = (try send_from(&client)).?;
    try testing.expectEqual(1, first.count);
    try testing.expectEqual(Level.initial, first.written()[0].level);

    // Both endpoints must have sent what the other acknowledges, so the server's space is moved
    // along before it reads.
    _ = try server.space_at(.initial).next_number();
    try testing.expectEqual(1, try walk_back(&server, first));
}

test "RFC 9000 §14.1, decision 54: a client's Initial datagram reaches 1,200 octets" {
    open_pair();
    provider_holder = .{ .owed = &flight, .owed_level = .initial };
    const sent = (try send_from(&client)).?;
    // "A client MUST expand the payload of all UDP datagrams carrying Initial packets to at
    // least the smallest allowed maximum datagram size of 1200 bytes."
    try testing.expectEqual(constants.datagram_len_min, sent.len);
    // Decision 54 puts the expansion on the last packet, and RFC 9002 §2 counts a packet
    // carrying PADDING as in flight.
    try testing.expect(sent.written()[sent.count - 1].in_flight);

    // And it still comes apart: the PADDING is frames inside the packet, not octets after it.
    _ = try server.space_at(.initial).next_number();
    try testing.expectEqual(1, try walk_back(&server, sent));
}

test "RFC 9000 §14.1: a server expands only its ack-eliciting Initial datagrams" {
    open_pair();
    // An Initial carrying nothing but an acknowledgment. §14.1 asks a server to expand "all UDP
    // datagrams carrying ack-eliciting Initial packets", and this is not one.
    server.path.on_datagram_received(constants.datagram_len_min);
    _ = server.space_at(.initial).receive(0, test_now_ns, true, .not_ect);
    const sent = (try send_from(&server)).?;
    try testing.expect(!sent.written()[0].ack_eliciting);
    try testing.expect(sent.len < constants.datagram_len_min);

    // With a flight to carry it is ack-eliciting, and then §14.1 does ask for the expansion.
    open_pair();
    server.path.on_datagram_received(constants.datagram_len_min);
    provider_holder = .{ .owed = &flight, .owed_level = .initial };
    const expanded = (try send_from(&server)).?;
    try testing.expect(expanded.written()[0].ack_eliciting);
    try testing.expectEqual(constants.datagram_len_min, expanded.len);
}

test "RFC 9000 §8, invariant 18: a server sends no more than three times what it received" {
    open_pair();
    // Nothing has arrived, so three times nothing is nothing and the server may not answer.
    provider_holder = .{ .owed = &flight, .owed_level = .initial };
    try testing.expectEqual(0, server.path.send_allowance());
    // §8's limit bounds the datagram like the caller's buffer and the peer's maximum do. A
    // server that has received nothing is the ordinary state of every server at the start of a
    // connection, so there is nothing here to assert about: it simply has nothing to send.
    try testing.expectEqual(null, try send_from(&server));

    // One datagram in gives it room for three out, and what it sends counts against that.
    server.path.on_datagram_received(constants.datagram_len_min);
    const before = server.path.send_allowance();
    const sent = (try send_from(&server)).?;
    try testing.expectEqual(before - sent.len, server.path.send_allowance());

    // A client is exempt (§21.1.1.1), so its allowance never moves off unlimited.
    try testing.expectEqual(std.math.maxInt(u64), client.path.send_allowance());
}

test "RFC 9000 §12.2: a connection with nothing to send assembles no datagram" {
    open_pair();
    // No flight owed and no acknowledgment owed, which is what an idle connection looks like.
    try testing.expectEqual(null, try send_from(&client));
}

test "RFC 9001 §4.9.1: a level discarded contributes no packet to the datagram" {
    open_pair();
    provider_holder = .{ .owed = &flight, .owed_level = .initial };
    client.keys.mark_discarded(.initial);
    // §4.9.1: "Endpoints MUST NOT send Initial packets after this point", so the flight owed
    // there goes nowhere and the datagram is empty.
    try testing.expectEqual(null, try send_from(&client));
}

test "RFC 9000 §18.2: the peer's max_udp_payload_size bounds the datagram" {
    open_pair();
    // Before the handshake carries it, §14.1's smallest allowed maximum is all colibri assumes,
    // even though the caller's buffer holds more.
    provider_holder = .{ .owed = &long_flight, .owed_level = .initial };
    const before = (try send_from(&client)).?;
    try testing.expectEqual(constants.datagram_len_min, before.len);

    // §18.2: "The value of the maximum UDP payload size ... values below 1200 are invalid", so a
    // peer can only ever raise this. One that accepts more is believed.
    open_pair();
    var peer = parameters();
    const larger: u64 = 1500;
    peer.max_udp_payload_size = larger;
    client.apply_peer_parameters(peer);
    provider_holder = .{ .owed = &long_flight, .owed_level = .initial };
    const after = (try send_from(&client)).?;
    try testing.expectEqual(larger, after.len);
}

/// The unpredictable octets RFC 9000 §8.2.1 asks for, as a fixed value: §5.1 wants them drawn by
/// the caller and invariant 5 forbids colibri a random number, so a test states them.
const challenge_octet: u8 = 0x9c;
const challenge_data: [constants.path_challenge_len]u8 = @splat(challenge_octet);

/// Gives `connection` the application level, which RFC 9000 §12.5's Table 3 confines the path
/// frames to.
fn open_application(connection: *Connection) void {
    keys.on_keys_installed(connection, .application, .read);
    keys.on_keys_installed(connection, .application, .write);
    connection.handshake_complete = true;
}

test "RFC 9000 §8.2.1: a PATH_CHALLENGE goes out in an expanded datagram and is recorded" {
    open_pair();
    open_application(&client);
    client.path.owe_challenge(challenge_data);

    const sent = (try send_from(&client)).?;
    // "An endpoint MUST expand datagrams that contain a PATH_CHALLENGE frame to at least the
    // smallest allowed maximum datagram size of 1200 bytes."
    try testing.expectEqual(constants.datagram_len_min, sent.len);
    // §8.2.1 asks once: the frame is not owed again until the caller asks again.
    try testing.expectEqual(null, client.path.challenge_owed);
    // §8.2.1's attempt is outstanding now, which §8.2.4's timer is armed against. The client's
    // path already reads as validated (§21.1.1.1 exempts it), so what shows is the attempt.
    try testing.expect(client.path.challenge_deadline_ns() != null);
    // RFC 9000 §12.4's Table 3 marks PADDING, ACK and CONNECTION_CLOSE with N and nothing else,
    // so a PATH_CHALLENGE elicits an acknowledgment and RFC 9002 §2 counts the packet in flight.
    try testing.expect(sent.packets[0].ack_eliciting);
    try testing.expect(sent.packets[0].in_flight);

    // The datagram reached 1,200 octets, so §8.2.3's response will validate the path MTU too.
    open_application(&server);
    _ = try walk_back(&server, sent);
    try testing.expectEqualSlices(u8, &challenge_data, &server.path.response_owed.?);
    try testing.expect(client.path.on_response(challenge_data));
    try testing.expect(!client.path.owes_mtu_validation());
}

test "RFC 9000 §8.2.2: a PATH_RESPONSE goes out in an expanded datagram" {
    open_pair();
    open_application(&client);
    // "On receiving a PATH_CHALLENGE frame, an endpoint MUST respond by echoing the data
    // contained in the PATH_CHALLENGE frame in a PATH_RESPONSE frame."
    client.path.take_challenge(challenge_data);

    const sent = (try send_from(&client)).?;
    // §8.2.2: "An endpoint MUST expand datagrams that contain a PATH_RESPONSE frame to at least
    // the smallest allowed maximum datagram size of 1200 bytes."
    try testing.expectEqual(constants.datagram_len_min, sent.len);
    // §8.2.2: "An endpoint MUST NOT send more than one PATH_RESPONSE frame in response to one
    // PATH_CHALLENGE frame", so nothing is owed afterwards and nothing more goes out.
    try testing.expectEqual(null, client.path.response_owed);
    try testing.expectEqual(null, try send_from(&client));
}

test "RFC 9000 §8.2.1: a datagram the anti-amplification limit bounds is not expanded" {
    open_pair();
    open_application(&server);
    // §8.1's limit is the server's: it may send three times what it received, which here is less
    // than §14.1's 1,200 octets.
    server.path.init(.unvalidated);
    server.path.on_datagram_received(small_receipt_len);
    server.path.take_challenge(challenge_data);
    server.path.owe_challenge(challenge_data);

    const sent = (try send_from(&server)).?;
    // §8.2.1: the expansion applies "unless the anti-amplification limit for the path does not
    // permit sending a datagram of this size", which is what stopped it here.
    try testing.expect(sent.len < constants.datagram_len_min);
    // §8.2.3: "the path is validated but not the path MTU. ... the endpoint MUST initiate another
    // path validation with an expanded datagram."
    try testing.expect(server.path.on_response(challenge_data));
    try testing.expect(server.path.owes_mtu_validation());
}

/// A round trip well under RFC 9002's kInitialRtt of 333 milliseconds, so the current Probe
/// Timeout is the smaller of the two §8.2.4 compares.
const short_sample_milliseconds: u64 = 10;
const short_sample_ns: u64 = short_sample_milliseconds * constants.nanoseconds_per_millisecond;

/// Three times this is under §14.1's smallest allowed maximum datagram, so §8's limit bites.
const small_receipt_len: u64 = 200;

test "RFC 9000 §12.5: neither path frame goes out below the application level" {
    open_pair();
    // The application level is not open, so Table 3 permits neither frame anywhere available.
    client.path.take_challenge(challenge_data);
    client.path.owe_challenge(challenge_data);
    try testing.expectEqual(null, try send_from(&client));
    try testing.expectEqualSlices(u8, &challenge_data, &client.path.response_owed.?);
    try testing.expectEqualSlices(u8, &challenge_data, &client.path.challenge_owed.?);
}

test "RFC 9000 §8.2.4: the timer is three times the larger of the two Probe Timeouts" {
    open_pair();
    open_application(&client);
    // A round trip shorter than kInitialRtt, so the current Probe Timeout is the smaller of the
    // two and §8.2.4's "larger" is what picks the other: "the new path could have a longer
    // round-trip time than the original".
    client.recovery.rtt.update(.{
        .rtt_ns = short_sample_ns,
        .ack_delay_ns = 0,
        .handshake_confirmed = true,
        .taken_at_ns = test_now_ns,
    });
    try testing.expect(client.recovery.rtt.probe_timeout_ns(true) < client.recovery.rtt.new_path_probe_timeout_ns());
    client.path.owe_challenge(challenge_data);
    _ = (try send_from(&client)).?;

    // "A value of three times the larger of the current PTO or the PTO for the new path (using
    // kInitialRtt ...) is RECOMMENDED."
    const rtt = &client.recovery.rtt;
    const larger_ns = @max(rtt.probe_timeout_ns(true), rtt.new_path_probe_timeout_ns());
    try testing.expectEqual(
        test_now_ns + constants.path_probe_timeouts * larger_ns,
        client.path.challenge_deadline_ns().?,
    );
}

/// The record the caller keeps for a packet the send path reported (RFC 9002 Appendix A.1.1),
/// built from what `Sent` said about it.
fn record_of(sent: send.Sent, at: usize) Record {
    const packet = sent.packets[at];
    return .{
        .number = packet.packet_number,
        .sent_at_ns = test_now_ns,
        .sent_len = @intCast(sent.len),
        .ack_eliciting = packet.ack_eliciting,
        .in_flight = packet.in_flight,
        .crypto_offset = packet.crypto_offset,
        .crypto_len = packet.crypto_len,
    };
}

test "RFC 9000 §13.3: CRYPTO octets from a lost packet are sent again under a new number" {
    open_pair();
    provider_holder = .{ .owed = &flight, .owed_level = .initial };
    const first = (try send_from(&client)).?;
    try testing.expectEqual(0, first.packets[0].packet_number);
    try testing.expectEqual(0, first.packets[0].crypto_offset);
    try testing.expectEqual(flight_len, first.packets[0].crypto_len);
    // The provider gave its octets up, so there is nothing new to send until something is lost.
    try testing.expectEqual(null, try send_from(&client));

    // RFC 9002's loss detection declared that packet lost, and the record is the caller's.
    const lost = [_]Record{record_of(first, 0)};
    const report = connection_crypto.on_packets_lost(&client, .initial, &lost);
    try testing.expectEqual(1, report.packets);
    try testing.expect(!report.forgotten);

    // §13.3: "the information that might be carried in frames is sent again in new frames as
    // needed", and invariant 17 gives that new packet a number of its own.
    const again = (try send_from(&client)).?;
    try testing.expect(again.packets[0].packet_number > first.packets[0].packet_number);
    // §19.6: the Offset is where the octets sit in the flow, so the repeat starts where they did.
    try testing.expectEqual(0, again.packets[0].crypto_offset);
    try testing.expectEqual(flight_len, again.packets[0].crypto_len);

    // The peer reads the flight off the second datagram, having never seen the first.
    _ = try walk_back(&server, again);
    try testing.expectEqualSlices(u8, &flight, server.crypto_at(.initial).readable());
}

test "RFC 9000 §13.3: a lost packet that carried no CRYPTO asks for nothing" {
    open_pair();
    provider_holder = .{ .owed = &flight, .owed_level = .initial };
    const first = (try send_from(&client)).?;

    // "PING and PADDING frames contain no information, so lost PING or PADDING frames do not
    // require repair", and neither does a packet that carried only an acknowledgment.
    var quiet = record_of(first, 0);
    quiet.crypto_offset = 0;
    quiet.crypto_len = 0;
    const report = connection_crypto.on_packets_lost(&client, .initial, &.{quiet});
    try testing.expectEqual(0, report.packets);
    try testing.expectEqual(null, try send_from(&client));
}

test "RFC 9000 §13.3: octets the window forgot cannot be sent again" {
    open_pair();
    provider_holder = .{ .owed = &flight, .owed_level = .initial };
    const first = (try send_from(&client)).?;
    // A flight longer than the send window forgets what it has already framed, which `send_base`
    // above the lost offset is. §13.3 has no answer for that.
    client.crypto_at(.initial).send_base = 1;

    const report = connection_crypto.on_packets_lost(&client, .initial, &.{record_of(first, 0)});
    try testing.expectEqual(1, report.packets);
    try testing.expect(report.forgotten);
}

test "RFC 9000 §13.3: the lowest lost offset is where the flow is sent again from" {
    open_pair();
    // A flight no single packet holds, so two of them carry it and each has its own offset.
    provider_holder = .{ .owed = &long_flight, .owed_level = .initial };
    const first = (try send_from(&client)).?;
    const second = (try send_from(&client)).?;
    try testing.expectEqual(0, first.packets[0].crypto_offset);
    try testing.expect(second.packets[0].crypto_offset > 0);

    // Both declared lost, the higher offset last, which is the order an ACK's ranges walk in.
    const lost = [_]Record{ record_of(first, 0), record_of(second, 0) };
    const report = connection_crypto.on_packets_lost(&client, .initial, &lost);
    try testing.expectEqual(2, report.packets);

    // §13.3 sends the information again, and the lowest lost offset is where that starts:
    // rewinding to the last record's offset instead would leave the first packet's octets unsent.
    const again = (try send_from(&client)).?;
    try testing.expectEqual(0, again.packets[0].crypto_offset);
}
