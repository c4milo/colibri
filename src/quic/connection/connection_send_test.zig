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
const build_test = @import("packet_build_test.zig");

const testing = std.testing;
const Level = core.Level;
const Connection = connection_module.Connection;
const Parameters = transport_parameters.Parameters;

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
        const outcome = receive.next(&walk, reader, suite_holder.suite()) orelse break;
        switch (outcome) {
            .opened => |opened| {
                seen += 1;
                _ = try frames.process(reader, opened.level, opened.payload, test_now_ns, null);
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
