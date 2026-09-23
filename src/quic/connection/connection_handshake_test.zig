//! The tests of `connection_handshake.zig`: completion and confirmation (RFC 9001 §4.1.1,
//! §4.1.2), the HANDSHAKE_DONE frame a server sends (RFC 9000 §19.20) and sends again until it is
//! acknowledged (§13.3), and the Handshake keys each endpoint discards once confirmed (RFC 9001
//! §4.9.2).
const std = @import("std");
const core = @import("core");
const constants = @import("../constants.zig");
const transport_parameters = @import("../transport_parameters.zig");
const recovery_sent = @import("../recovery/recovery_sent.zig");
const StreamProvider = @import("../stream/stream_provider.zig").StreamProvider;
const connection_module = @import("connection.zig");
const keys = @import("connection_keys.zig");
const receive = @import("connection_receive.zig");
const frames = @import("connection_frames.zig");
const send = @import("connection_send.zig");
const handshake = @import("connection_handshake.zig");
const build_test = @import("packet_build/packet_build_test.zig");

const Level = core.Level;
const Connection = connection_module.Connection;
const Parameters = transport_parameters.Parameters;
const Record = recovery_sent.Record;
const testing = std.testing;

var client: Connection = undefined;
var server: Connection = undefined;
var scratch: send.DefaultScratch = .{};
var datagram: [constants.datagram_len_min]u8 = undefined;
var suite_holder: build_test.RoundTrip = undefined;
var provider_holder: build_test.Fake = undefined;

const test_now_ns: u64 = 1_000_000;
const id_len: usize = 4;
const local_octet: u8 = 0xc1;
const peer_octet: u8 = 0x51;
const local_id: [id_len]u8 = @splat(local_octet);
const peer_id: [id_len]u8 = @splat(peer_octet);
const test_max_data: u64 = 1_048_576;

fn parameters() Parameters {
    var held = Parameters.initial();
    held.initial_max_data = test_max_data;
    return held;
}

/// Two endpoints with every level's keys, each holding the other's parameters unless the test
/// says otherwise, and a provider that has not finished the handshake.
fn open_pair() void {
    suite_holder.init();
    provider_holder = .{};
    open_one(&client, .client);
    open_one(&server, .server);
    client.apply_peer_parameters(parameters());
    server.apply_peer_parameters(parameters());
}

fn open_one(connection: *Connection, role: connection_module.Role) void {
    connection.init(.{
        .role = role,
        .local_parameters = parameters(),
        .now_ns = test_now_ns,
        .identity = .{ .local_initial_source = &local_id, .original_destination = &peer_id },
    });
    for ([_]Level{ .initial, .handshake, .application }) |level| {
        keys.on_keys_installed(connection, level, .read);
        keys.on_keys_installed(connection, level, .write);
    }
    // RFC 9000 §8.1: a server sends only after it has received, and a client's first datagram
    // is at least 1,200 octets (§14.1).
    if (role == .server) connection.path.on_datagram_received(constants.datagram_len_min);
}

fn complete(connection: *Connection) !bool {
    return handshake.complete(connection, provider_holder.provider(), suite_holder.suite());
}

fn send_from(connection: *Connection) !?send.Sent {
    return send.send(connection, suite_holder.suite(), provider_holder.provider(), StreamProvider.none(), &scratch, &datagram, test_now_ns);
}

/// The record the caller keeps for the one packet `sent` reported (RFC 9002 Appendix A.1.1).
fn record_of(sent: send.Sent) Record {
    const packet = sent.packets[0];
    return .{
        .number = packet.packet_number,
        .sent_at_ns = test_now_ns,
        .sent_len = @intCast(sent.len),
        .ack_eliciting = packet.ack_eliciting,
        .in_flight = packet.in_flight,
    };
}

/// Opens the one packet of `sent` at the client and reads its frames.
fn client_reads(sent: send.Sent) !frames.Report {
    var walk: receive.Walk = undefined;
    walk.init(.{ .octets = datagram[0..sent.len], .now_ns = test_now_ns, .ecn = .not_ect });
    const opened = (try receive.next(&walk, &client, suite_holder.suite())).?.opened;
    return frames.process(&client, opened, test_now_ns);
}

test "RFC 9001 §4.1.2: a server's handshake is confirmed when it completes, and owes HANDSHAKE_DONE" {
    open_pair();
    // §4.1.1: complete means the provider said so, and it has not.
    try testing.expect(!try complete(&server));
    try testing.expect(!server.handshake_complete);
    provider_holder.done = true;
    try testing.expect(try complete(&server));
    try testing.expect(server.handshake_complete);
    try testing.expect(server.handshake_confirmed);
    try testing.expect(server.handshake_done.owed);
    // §4.9.2: "An endpoint MUST discard its Handshake keys when the TLS handshake is confirmed".
    try testing.expectEqual(keys.State.discarded, server.keys.at(.handshake, .write));
    try testing.expectEqual(1, suite_holder.discards[@intFromEnum(Level.handshake)]);
    // Completing happens once.
    try testing.expect(!try complete(&server));
}

test "RFC 9001 §4.1.2: a client's handshake completes without being confirmed" {
    open_pair();
    provider_holder.done = true;
    try testing.expect(try complete(&client));
    try testing.expect(client.handshake_complete);
    // "At the client, the handshake is considered confirmed when a HANDSHAKE_DONE frame is
    // received", and RFC 9000 §19.20 lets only a server send one.
    try testing.expect(!client.handshake_confirmed);
    try testing.expect(!client.handshake_done.owed);
    try testing.expectEqual(keys.State.available, client.keys.at(.handshake, .write));
    try testing.expectEqual(0, suite_holder.discards[@intFromEnum(Level.handshake)]);
}

test "RFC 9001 §8.2: a handshake that completes without the peer's parameters is refused" {
    suite_holder.init();
    provider_holder = .{ .done = true };
    open_one(&server, .server);
    try testing.expectError(error.ParametersMissing, complete(&server));
    try testing.expect(!server.handshake_complete);
    try testing.expect(!server.handshake_done.owed);
}

test "RFC 9000 §19.20: the server sends HANDSHAKE_DONE in a 1-RTT packet, and the client confirms" {
    open_pair();
    provider_holder.done = true;
    _ = try complete(&server);
    // RFC 9001 §5.7: a client reads no 1-RTT packet before its own handshake completes.
    _ = try complete(&client);
    const sent = (try send_from(&server)).?;
    try testing.expectEqual(1, sent.count);
    // RFC 9000 §12.4, Table 3: HANDSHAKE_DONE travels in 1-RTT packets alone.
    try testing.expectEqual(Level.application, sent.packets[0].level);
    try testing.expect(sent.packets[0].ack_eliciting);
    try testing.expect(!server.handshake_done.owed);
    try testing.expectEqual(sent.packets[0].packet_number, server.handshake_done.sent_in.?);
    // Nothing else is owed, so nothing more goes out.
    try testing.expectEqual(null, try send_from(&server));

    const report = try client_reads(sent);
    try testing.expect(report.handshake_done);
    try testing.expect(client.handshake_confirmed);
    // The caller discards the client's Handshake keys once the report says so (§4.9.2).
    keys.on_handshake_confirmed(&client, suite_holder.suite());
    try testing.expectEqual(keys.State.discarded, client.keys.at(.handshake, .write));
}

test "RFC 9000 §13.3: HANDSHAKE_DONE is sent again when lost, until a packet carrying it is acknowledged" {
    open_pair();
    provider_holder.done = true;
    _ = try complete(&server);
    _ = try complete(&client);
    const first = (try send_from(&server)).?;
    // A record of another space with the same number is another packet (RFC 9000 §12.3).
    handshake.on_packets_lost(&server, .handshake, &.{record_of(first)});
    try testing.expect(!server.handshake_done.owed);

    // "The HANDSHAKE_DONE frame MUST be retransmitted until it is acknowledged."
    handshake.on_packets_lost(&server, .application, &.{record_of(first)});
    try testing.expect(server.handshake_done.owed);
    try testing.expectEqual(null, server.handshake_done.sent_in);
    const again = (try send_from(&server)).?;
    try testing.expect(again.packets[0].packet_number > first.packets[0].packet_number);
    try testing.expectEqual(again.packets[0].packet_number, server.handshake_done.sent_in.?);
    try testing.expect((try client_reads(again)).handshake_done);

    // A late acknowledgment of the packet declared lost is not the one that counts.
    handshake.on_packets_acknowledged(&server, .application, &.{record_of(first)});
    try testing.expectEqual(again.packets[0].packet_number, server.handshake_done.sent_in.?);
    handshake.on_packets_acknowledged(&server, .handshake, &.{record_of(again)});
    try testing.expectEqual(again.packets[0].packet_number, server.handshake_done.sent_in.?);
    // Nor does a later packet that carried something else.
    var later = record_of(again);
    later.number += 1;
    handshake.on_packets_acknowledged(&server, .application, &.{later});
    try testing.expectEqual(again.packets[0].packet_number, server.handshake_done.sent_in.?);
    handshake.on_packets_acknowledged(&server, .application, &.{record_of(again)});
    try testing.expectEqual(null, server.handshake_done.sent_in);
    // Acknowledged, so a later loss report of it owes nothing.
    handshake.on_packets_lost(&server, .application, &.{record_of(again)});
    try testing.expect(!server.handshake_done.owed);
    try testing.expectEqual(null, try send_from(&server));
}
