//! The tests of `connection_id_frames.zig`: NEW_CONNECTION_ID (RFC 9000 §19.15) and
//! RETIRE_CONNECTION_ID (§19.16), the limits §5.1.1 puts on issuing, and §13.3's rule that both
//! are sent again when lost. Each frame is read back by the peer, whose sets are checked.
const std = @import("std");
const core = @import("core");
const constants = @import("../constants.zig");
const transport_parameters = @import("../transport_parameters.zig");
const connection_id = @import("../connection_id.zig");
const recovery_sent = @import("../recovery/recovery_sent.zig");
const StreamProvider = @import("../stream/stream_provider.zig").StreamProvider;
const connection_module = @import("connection.zig");
const keys = @import("connection_keys.zig");
const receive = @import("connection_receive.zig");
const frames = @import("connection_frames.zig");
const send = @import("connection_send.zig");
const id_frames = @import("connection_id_frames.zig");
const build_test = @import("packet_build/packet_build_test.zig");

const Writer = core.Writer;
const Connection = connection_module.Connection;
const Parameters = transport_parameters.Parameters;
const Record = recovery_sent.Record;
const connection_recovery = @import("connection_recovery.zig");
const testing = std.testing;

/// Where an ACK frame's packets go while RFC 9002 takes them (decision 59). Test-only.
var recovery_scratch: connection_recovery.Scratch = undefined;

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
/// A limit above §18.2's default of 2, so a test can issue two more than the first. Test-only.
const generous_limit: u64 = 3;
/// A connection ID and token the client issues, and a second of each. Test-only.
const issued_octet: u8 = 0x6a;
const issued_id: [id_len]u8 = @splat(issued_octet);
const second_octet: u8 = 0x6b;
const second_id: [id_len]u8 = @splat(second_octet);
const token_octet: u8 = 0x9d;
const token: [constants.stateless_reset_token_len]u8 = @splat(token_octet);

fn parameters(limit: u64) Parameters {
    var held = Parameters.initial();
    held.initial_max_data = test_max_data;
    held.active_connection_id_limit = limit;
    return held;
}

/// Two endpoints past the handshake. Each holds `limit` as the other's active_connection_id_limit.
fn open_pair(limit: u64) void {
    suite_holder.init();
    provider_holder = .{};
    open_one(&client, .client, limit);
    open_one(&server, .server, limit);
    client.apply_peer_parameters(parameters(limit));
    server.apply_peer_parameters(parameters(limit));
}

fn open_one(connection: *Connection, role: connection_module.Role, limit: u64) void {
    connection.init(.{
        .role = role,
        .local_parameters = parameters(limit),
        .now_ns = test_now_ns,
        .identity = .{ .local_initial_source = &local_id, .original_destination = &peer_id },
    });
    keys.on_keys_installed(connection, .application, .read);
    keys.on_keys_installed(connection, .application, .write);
    connection.handshake_complete = true;
    // RFC 9000 §8.1: a server sends only after it has received.
    if (role == .server) connection.path.on_datagram_received(constants.datagram_len_min);
}

fn send_from(connection: *Connection) !?send.Sent {
    return send.send(connection, suite_holder.suite(), provider_holder.provider(), StreamProvider.none(), &scratch, &datagram, test_now_ns);
}

fn deliver(sent: send.Sent, reader: *Connection) !void {
    var walk: receive.Walk = undefined;
    walk.init(.{ .octets = datagram[0..sent.len], .now_ns = test_now_ns, .ecn = .not_ect });
    const opened = (try receive.next(&walk, reader, suite_holder.suite())).?.opened;
    _ = try frames.process(reader, opened, test_now_ns, &recovery_scratch);
}

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

test "RFC 9000 §19.15: an issued connection ID reaches the peer with its token, once" {
    open_pair(transport_parameters.default_active_connection_id_limit);
    const sequence_number = try id_frames.issue(&client, &issued_id, &token);
    // §5.1.1: the first is 0, from the handshake, and "each newly issued connection ID MUST
    // increase by 1".
    try testing.expectEqual(1, sequence_number);
    const sent = (try send_from(&client)).?;
    try testing.expect(sent.packets[0].ack_eliciting);
    try deliver(sent, &server);
    const held = server.remote_ids.active().?;
    try testing.expectEqual(sequence_number, held.sequence_number);
    try testing.expectEqualSlices(u8, &issued_id, held.value());
    try testing.expectEqualSlices(u8, &token, &held.stateless_reset_token);
    // Sent once: nothing more is owed.
    try testing.expectEqual(null, try send_from(&client));
}

test "RFC 9000 §5.1.1: no more connection IDs than the peer's limit, none of another length" {
    open_pair(transport_parameters.default_active_connection_id_limit);
    // The one from the handshake and one more reach §18.2's default limit of 2.
    _ = try id_frames.issue(&client, &issued_id, &token);
    try testing.expectError(error.LimitReached, id_frames.issue(&client, &second_id, &token));
    // A peer that allows more takes more.
    open_pair(generous_limit);
    _ = try id_frames.issue(&client, &issued_id, &token);
    try testing.expectEqual(2, try id_frames.issue(&client, &second_id, &token));
    // §17.3.1: a short header's Destination Connection ID is read by this endpoint's length.
    open_pair(generous_limit);
    const longer: [id_len + 1]u8 = @splat(issued_octet);
    try testing.expectError(error.LengthDiffers, id_frames.issue(&client, &longer, &token));
    // §19.15: an endpoint whose peer sends it zero-length connection IDs sends no frame at all.
    client.local_ids.zero_length = true;
    try testing.expectError(error.ZeroLength, id_frames.issue(&client, &issued_id, &token));
}

test "RFC 9000 §13.3: a lost NEW_CONNECTION_ID goes again with the same sequence number" {
    open_pair(transport_parameters.default_active_connection_id_limit);
    _ = try id_frames.issue(&client, &issued_id, &token);
    const first = (try send_from(&client)).?;
    // Another space's packet with the same number is another packet (§12.3).
    id_frames.on_packets_lost(&client, .handshake, &.{record_of(first)});
    try testing.expectEqual(null, try send_from(&client));
    id_frames.on_packets_lost(&client, .application, &.{record_of(first)});
    const again = (try send_from(&client)).?;
    try deliver(again, &server);
    try testing.expectEqual(1, server.remote_ids.active().?.sequence_number);
    try testing.expectEqual(1, server.remote_ids.active_len());
}

test "RFC 9000 §19.16: a retired connection ID is named until the frame is acknowledged" {
    open_pair(generous_limit);
    // The server issues one, which reaches the client.
    _ = try id_frames.issue(&server, &issued_id, &token);
    try deliver((try send_from(&server)).?, &client);
    try testing.expectEqual(1, client.remote_ids.active_len());
    // The server asks for it back, as a later NEW_CONNECTION_ID with Retire Prior To 2 would.
    var later: connection_id.Entry = .{ .sequence_number = 2, .len = id_len, .octets = @splat(0), .stateless_reset_token = token };
    @memcpy(later.octets[0..id_len], &second_id);
    try client.remote_ids.offer(later, 2, generous_limit);

    // §5.1.2: the peer "MUST stop using the corresponding connection IDs and retire them with
    // RETIRE_CONNECTION_ID frames".
    const retire = (try send_from(&client)).?;
    try testing.expect(retire.packets[0].ack_eliciting);
    try deliver(retire, &server);
    try testing.expectEqual(1, server.local_ids.active_len());
    // Sent and neither lost nor acknowledged: nothing to send again yet.
    try testing.expectEqual(null, try send_from(&client));
    // Lost, so it goes again (§13.3); the server takes the repeat as a retransmission.
    id_frames.on_packets_lost(&client, .application, &.{record_of(retire)});
    const again = (try send_from(&client)).?;
    try deliver(again, &server);
    // Acknowledged in another space, nothing leaves; acknowledged here, it does.
    id_frames.on_packets_acknowledged(&client, .handshake, &.{record_of(again)});
    try testing.expectEqual(1, client.remote_ids.retirements().len);
    id_frames.on_packets_acknowledged(&client, .application, &.{record_of(again)});
    try testing.expectEqual(0, client.remote_ids.retirements().len);
    try testing.expectEqual(null, try send_from(&client));
}

test "RFC 9000 §5.1.2: once the peer retires the ID in use, colibri addresses the next one" {
    open_pair(generous_limit);
    // What the client takes off the server's first Initial (`connection_receive.zig`).
    client.remote_ids.hold_initial(&peer_id);
    var next: connection_id.Entry = .{ .sequence_number = 1, .len = id_len, .octets = @splat(0), .stateless_reset_token = token };
    @memcpy(next.octets[0..id_len], &second_id);
    try client.remote_ids.offer(next, 1, generous_limit);
    // "Upon receipt of an increased Retire Prior To field, the peer MUST stop using the
    // corresponding connection IDs", so the packet retiring sequence number 0 goes to the next
    // one, which also keeps it off the ID it names (§19.16). RFC 9000 §17.3: a short header's
    // Destination Connection ID follows its first octet.
    const retire = (try send_from(&client)).?;
    try testing.expectEqualSlices(u8, &second_id, datagram[1 .. 1 + id_len]);
    try deliver(retire, &server);
    try testing.expectEqual(null, server.local_ids.sequence_number_of(&local_id));
}

test "RFC 9000 §12.4: neither frame goes below 1-RTT" {
    open_pair(transport_parameters.default_active_connection_id_limit);
    _ = try id_frames.issue(&client, &issued_id, &token);
    var room: [constants.datagram_len_min]u8 = undefined;
    var writer = Writer.init(&room);
    try testing.expect(!id_frames.write(&client, .handshake, &writer, 0));
    try testing.expectEqual(0, writer.written().len);
}
