//! The tests of `connection_migration.zig`: RFC 9000 §9.3's answer to a peer whose address
//! changed (decision 72). A client and a server each hold 1-RTT keys, and every datagram between
//! them names the address it came from, so a test moves the client by naming another.
const std = @import("std");
const constants = @import("../constants.zig");
const transport_parameters = @import("../transport_parameters.zig");
const stream_module = @import("../stream/stream.zig");
const PeerAddress = @import("../peer_address.zig").PeerAddress;
const connection_module = @import("connection.zig");
const keys = @import("connection_keys.zig");
const receive = @import("connection_receive.zig");
const send = @import("connection_send.zig");
const datagram_module = @import("connection_datagram.zig");
const migration = @import("connection_migration.zig");
const timer = @import("connection_timer.zig");
const connection_recovery = @import("connection_recovery.zig");
const build_test = @import("packet_build/packet_build_test.zig");

const Connection = connection_module.Connection;
const Parameters = transport_parameters.Parameters;
const testing = std.testing;

var client: Connection = undefined;
var server: Connection = undefined;
var scratch: send.DefaultScratch = .{};
var suite_holder: build_test.RoundTrip = undefined;
var provider_holder: build_test.Fake = undefined;
var datagram_scratch: datagram_module.Scratch = undefined;
var recovery_scratch: connection_recovery.Scratch = undefined;
/// Two buffers, so a test can hold one datagram back and deliver it after the next. Test-only.
const buffer_count: usize = 2;
var buffers: [buffer_count][constants.datagram_len_min]u8 = undefined;

const test_now_ns: u64 = 1_000_000;
const id_len: usize = 4;
const local_octet: u8 = 0xc1;
const peer_octet: u8 = 0x51;
const local_id: [id_len]u8 = @splat(local_octet);
const peer_id: [id_len]u8 = @splat(peer_octet);
const test_max_data: u64 = 1_000;
const client_port: u16 = 50_000;
const rebound_port: u16 = 50_001;
const server_port: u16 = 443;
/// Three IPv4 hosts, each its four octets alike. Test-only.
const ipv4_len: usize = 4;
const client_octet: u8 = 0x0a;
const other_octet: u8 = 0x0b;
const server_octet: u8 = 0x0c;
const client_host: [ipv4_len]u8 = @splat(client_octet);
const other_host: [ipv4_len]u8 = @splat(other_octet);
const server_host: [ipv4_len]u8 = @splat(server_octet);
const client_address = PeerAddress.of(&client_host, client_port);
const rebound_address = PeerAddress.of(&client_host, rebound_port);
const moved_address = PeerAddress.of(&other_host, client_port);
const server_address = PeerAddress.of(&server_host, server_port);
const new_path_octet: u8 = 0x6e;
const previous_path_octet: u8 = 0x70;
const second_octet: u8 = 0x72;
const third_octet: u8 = 0x74;
const new_path_data: [constants.path_challenge_len]u8 = @splat(new_path_octet);
const previous_path_data: [constants.path_challenge_len]u8 = @splat(previous_path_octet);
const second_data: [constants.path_challenge_len]u8 = @splat(second_octet);
const third_data: [constants.path_challenge_len]u8 = @splat(third_octet);
const challenge_data: migration.ChallengeData = .{
    .new_path = .{ new_path_data, second_data, third_data },
    .previous_path = previous_path_data,
};

fn parameters() Parameters {
    var held = Parameters.initial();
    held.initial_max_data = test_max_data;
    return held;
}

/// A client and a server past the handshake. `validated` says whether the server's path to the
/// client is validated already, as a Handshake packet from the client makes it (RFC 9000 §8.1).
fn open_pair(validated: bool) void {
    suite_holder.init();
    provider_holder = .{};
    open_one(&client, .client, server_address);
    open_one(&server, .server, client_address);
    client.apply_peer_parameters(parameters());
    server.apply_peer_parameters(parameters());
    if (validated) server.path.on_handshake_processed();
}

fn open_one(connection: *Connection, role: connection_module.Role, peer: PeerAddress) void {
    connection.init(.{
        .role = role,
        .local_parameters = parameters(),
        .now_ns = test_now_ns,
        .identity = .{ .local_initial_source = &local_id, .original_destination = &peer_id },
        .peer_address = peer,
    });
    keys.on_keys_installed(connection, .application, .read);
    keys.on_keys_installed(connection, .application, .write);
    connection.handshake_complete = true;
    connection.handshake_confirmed = true;
    // RFC 9000 §8.1: a server sends only after it has received.
    if (role == .server) connection.path.on_datagram_received(constants.datagram_len_min);
}

var nothing_context: u8 = 0;
const nothing_vtable: stream_module.stream_provider.VTable = .{ .read = read_nothing };

fn read_nothing(context: *anyopaque, stream_id: u64, offset: u64, output: []u8) usize {
    _ = context;
    _ = stream_id;
    _ = offset;
    _ = output;
    return 0;
}

/// The next datagram `connection` owes, written into buffer `slot`.
fn send_into(connection: *Connection, slot: usize, now_ns: u64) !send.Sent {
    const streams: stream_module.StreamProvider = .{ .context = &nothing_context, .vtable = &nothing_vtable };
    return try send.send(connection, suite_holder.suite(), provider_holder.provider(), streams, &scratch, &buffers[slot], now_ns) orelse error.NothingSent;
}

/// Hands `reader` the datagram in buffer `slot`, as if it came from `from`.
fn deliver(reader: *Connection, sent: send.Sent, slot: usize, from: PeerAddress, now_ns: u64) !datagram_module.Received {
    const datagram: receive.Datagram = .{ .octets = buffers[slot][0..sent.len], .now_ns = now_ns, .ecn = .not_ect, .from = from };
    return datagram_module.receive(reader, suite_holder.suite(), provider_holder.provider(), datagram, &datagram_scratch);
}

/// A PING from the client, which is a non-probing packet (RFC 9000 §9.1), in buffer `slot`.
fn client_ping(slot: usize) !send.Sent {
    send.owe_probes(&client, .application, 1);
    return send_into(&client, slot, test_now_ns);
}

/// The server moves to `from` on the client's next PING, and is given its challenge data.
fn move_server(from: PeerAddress) !void {
    const received = try deliver(&server, try client_ping(0), 0, from, test_now_ns);
    try testing.expect(received.migrated);
    migration.challenge(&server, challenge_data);
}

test "RFC 9000 §9: a client discards a datagram from an address other than its server's" {
    open_pair(true);
    send.owe_probes(&server, .application, 1);
    const sent = try send_into(&server, 0, test_now_ns);
    const received = try deliver(&client, sent, 0, PeerAddress.of(&other_host, server_port), test_now_ns);
    try testing.expect(received.from_unknown_server);
    try testing.expectEqual(0, received.processed);
    try testing.expectEqual(null, client.space_at(.application).received.largest());
}

test "RFC 9000 §9.3: a non-probing packet from a new address moves the path, and a probing one does not" {
    open_pair(true);
    // RFC 9000 §9.1: a packet of a PATH_CHALLENGE and PADDING is a probing packet.
    client.path.owe_challenge(new_path_data);
    const probing = try deliver(&server, try send_into(&client, 0, test_now_ns), 0, moved_address, test_now_ns);
    try testing.expect(!probing.migrated);
    try testing.expect(server.path.address.eql(&client_address));
    const moved = try deliver(&server, try client_ping(0), 0, moved_address, test_now_ns);
    try testing.expect(moved.migrated);
    try testing.expect(server.path.address.eql(&moved_address));
    // RFC 9000 §9.3.1: the new address is not validated, so §8's limit applies to it.
    try testing.expect(!server.path.validated);
    try testing.expect(server.migration.previous.?.address.eql(&client_address));
}

test "RFC 9000 §9.3: a reordered packet from the old address does not move the path back" {
    open_pair(true);
    const older = try client_ping(0);
    const newer = try client_ping(1);
    try testing.expect((try deliver(&server, newer, 1, rebound_address, test_now_ns)).migrated);
    // A lower packet number, so not the highest-numbered non-probing packet.
    try testing.expect(!(try deliver(&server, older, 0, client_address, test_now_ns)).migrated);
    try testing.expect(server.path.address.eql(&rebound_address));
}

test "RFC 9000 §9.3.3: the previous path is challenged in a datagram of its own, and recovery keeps no record" {
    open_pair(true);
    try move_server(moved_address);
    const recorded = server.recovery.table_of(.application).count();
    const probe = try send_into(&server, 0, test_now_ns);
    try testing.expect(probe.to.eql(&client_address));
    // RFC 9000 §8.2.1: the datagram carrying a PATH_CHALLENGE is expanded to 1,200 octets.
    try testing.expectEqual(constants.datagram_len_min, probe.len);
    try testing.expectEqual(recorded, server.recovery.table_of(.application).count());
    try testing.expect(server.migration.previous.?.challenge != null);
    // RFC 9000 §9.1: the probe carried probing frames alone, so the ACK the client's PING earned
    // is still to go, to the new address.
    try testing.expect(server.space_at(.application).has_new_ack_eliciting());
    // The next datagram goes to the new address and carries the new path's challenge.
    const next = try send_into(&server, 1, test_now_ns);
    try testing.expect(next.to.eql(&moved_address));
    try testing.expect(server.path.challenge != null);
}

/// The client answers the challenges the server sent, and the server takes the answers from the
/// client's new address.
fn answer_challenges(from: PeerAddress) !void {
    _ = try deliver(&client, try send_into(&server, 0, test_now_ns), 0, server_address, test_now_ns);
    _ = try deliver(&client, try send_into(&server, 1, test_now_ns), 1, server_address, test_now_ns);
    // Bounded by the two responses the client owes, one a buffer.
    for (0..buffers.len) |_| {
        const sent = send_into(&client, 0, test_now_ns) catch break;
        _ = try deliver(&server, sent, 0, from, test_now_ns);
    }
}

/// A window the tests set before a move, which RFC 9000 §9.4's reset brings back to the initial
/// one. Test-only.
const grown_window: u64 = 40_000;

test "RFC 9000 §9.4: validating a new host resets congestion and RTT, and a new port alone keeps them" {
    open_pair(true);
    server.recovery.congestion.window = grown_window;
    try move_server(moved_address);
    try answer_challenges(moved_address);
    try testing.expect(server.path.validated);
    try testing.expect(server.recovery.congestion.window != grown_window);
    try testing.expect(!server.recovery.rtt.has_sample());

    open_pair(true);
    server.recovery.congestion.window = grown_window;
    try move_server(rebound_address);
    try answer_challenges(rebound_address);
    try testing.expect(server.path.validated);
    try testing.expectEqual(grown_window, server.recovery.congestion.window);
}

test "RFC 9000 §9.3.2: a failed validation moves back to the last validated address" {
    open_pair(true);
    // RFC 9000 §9.3.2's spoofed move: the packet came from an address the client does not hold.
    try move_server(moved_address);
    _ = try send_into(&server, 0, test_now_ns);
    _ = try send_into(&server, 1, test_now_ns);
    // The client, still at its old address, answers the challenge sent there (§9.3.3) in a
    // probing packet, which moves nothing. One carrying an ACK too would move the path back on
    // its own, which the last test here covers.
    migration.on_response(&server, previous_path_data);
    try testing.expect(server.migration.previous.?.challenge == null);
    // Nothing answers at the new address, so its attempt runs out (RFC 9000 §8.2.4).
    const at_ns = server.path.challenge_deadline_ns().?;
    const fired = try timer.on_instant(&server, suite_holder.suite(), &recovery_scratch, at_ns);
    try testing.expect(fired.path_reverted);
    // The abandoned attempt's challenges left to send go with it.
    try testing.expectEqual(0, server.migration.resends_len);
    try testing.expect(server.path.address.eql(&client_address));
    try testing.expect(server.path.validated);
    try testing.expectEqual(null, server.migration.previous);
}

test "RFC 9000 §9.3.2: with no validated address to move back to, the connection closes silently" {
    open_pair(false);
    try move_server(moved_address);
    try testing.expectEqual(null, server.migration.previous);
    _ = try send_into(&server, 0, test_now_ns);
    const at_ns = server.path.challenge_deadline_ns().?;
    _ = try timer.on_instant(&server, suite_holder.suite(), &recovery_scratch, at_ns);
    try testing.expectEqual(.closed, server.termination.state);
    try testing.expectEqual(.path_failed, server.termination.reason.?);
}

test "RFC 9000 §9.3: moving back to the previous address skips its validation" {
    open_pair(true);
    try move_server(moved_address);
    try testing.expect((try deliver(&server, try client_ping(1), 1, client_address, test_now_ns)).migrated);
    try testing.expect(server.path.address.eql(&client_address));
    try testing.expect(server.path.validated);
    // The address left was never validated, so it is not one to move back to (§9.3.2), and its
    // challenges left to send go with it.
    try testing.expectEqual(null, server.migration.previous);
    try testing.expectEqual(0, server.migration.resends_len);
}

test "RFC 9000 §9.3.3: a previous path that does not answer is dropped at its own deadline" {
    open_pair(true);
    try move_server(rebound_address);
    _ = try send_into(&server, 0, test_now_ns);
    _ = try send_into(&server, 1, test_now_ns);
    // The client answers at its new address, so only the previous path's challenge is out.
    migration.on_response(&server, new_path_data);
    try testing.expect(server.path.validated);
    const at_ns = migration.challenge_deadline_ns(&server) orelse return error.NoDeadline;
    try testing.expect(!(try timer.on_instant(&server, suite_holder.suite(), &recovery_scratch, at_ns - 1)).path);
    try testing.expect((try timer.on_instant(&server, suite_holder.suite(), &recovery_scratch, at_ns)).path);
    // A path that no longer answers is not one to move back to (§9.3.2).
    try testing.expectEqual(null, server.migration.previous);
    try testing.expect(server.path.address.eql(&rebound_address));
}

test "RFC 9000 §8.2.2: a PATH_CHALLENGE in the packet that moves the path is answered on the new path" {
    open_pair(true);
    // The server's PING has the client owe an ACK, which makes its next packet non-probing.
    send.owe_probes(&server, .application, 1);
    _ = try deliver(&client, try send_into(&server, 0, test_now_ns), 0, server_address, test_now_ns);
    client.path.owe_challenge(previous_path_data);
    const sent = try send_into(&client, 0, test_now_ns);
    try testing.expect((try deliver(&server, sent, 0, moved_address, test_now_ns)).migrated);
    try testing.expectEqual(previous_path_data, server.path.response_owed.?);
    try testing.expectEqual(null, server.migration.previous.?.response_owed);
}

test "RFC 9000 §13.3: the new path's challenge goes again each PTO with new data, and any answer validates" {
    open_pair(true);
    try move_server(rebound_address);
    _ = try send_into(&server, 0, test_now_ns);
    _ = try send_into(&server, 1, test_now_ns);
    const abandoned_at_ns = server.path.challenge_deadline_ns().?;
    // The previous path answered, so only the new path's attempt is out.
    migration.on_response(&server, previous_path_data);
    const due_ns = migration.challenge_deadline_ns(&server).?;
    _ = try timer.on_instant(&server, suite_holder.suite(), &recovery_scratch, due_ns - 1);
    try testing.expectEqual(null, server.path.challenge_owed);
    try testing.expect((try timer.on_instant(&server, suite_holder.suite(), &recovery_scratch, due_ns)).path_resent);
    // Until it goes out, the owed one is not replaced by the next.
    try testing.expect(!(try timer.on_instant(&server, suite_holder.suite(), &recovery_scratch, due_ns)).path_resent);
    try testing.expectEqual(second_data, server.path.challenge_owed.?);
    try resend_from_new_address(due_ns);
    // §8.2.4's time still runs from the first: the attempt is one attempt.
    try testing.expectEqual(abandoned_at_ns, server.path.challenge_deadline_ns().?);
    const next_due_ns = migration.challenge_deadline_ns(&server).?;
    _ = try timer.on_instant(&server, suite_holder.suite(), &recovery_scratch, next_due_ns);
    try testing.expectEqual(third_data, server.path.challenge_owed.?);
    try resend_from_new_address(next_due_ns);
    // A late answer to the first challenge validates the path (§8.2.3).
    migration.on_response(&server, new_path_data);
    try testing.expect(server.path.validated);
    try testing.expectEqual(null, migration.challenge_deadline_ns(&server));
}

/// The client keeps sending from its new address, which lifts §8's limit enough for the server's
/// next challenge, and the server sends it.
fn resend_from_new_address(now_ns: u64) !void {
    _ = try deliver(&server, try client_ping(1), 1, rebound_address, now_ns);
    _ = try send_into(&server, 0, now_ns);
}

test "decision 72: a path the peer moved to carries ACK and path frames alone until it is validated" {
    open_pair(true);
    try move_server(moved_address);
    _ = try send_into(&server, 0, test_now_ns);
    const allowance = server.path.send_allowance();
    const challenge = try send_into(&server, 1, test_now_ns);
    try testing.expect(challenge.to.eql(&moved_address));
    // RFC 9000 §8.2.1: §8's limit keeps the datagram below 1,200 octets, so it is not padded
    // part of the way, and the octets left are there for the next challenge (§13.3).
    try testing.expect(challenge.len < allowance);
    try testing.expect(server.path.send_allowance() > challenge.len);
    // The ACK the client's PING earned went with the challenge, and a PING waits for the path
    // to be validated.
    try testing.expect(!server.space_at(.application).has_new_ack_eliciting());
    // One more PING from the client: its ACK may wait (RFC 9000 §13.2.1), so nothing goes.
    _ = try deliver(&server, try client_ping(1), 1, moved_address, test_now_ns);
    try testing.expectError(error.NothingSent, send_into(&server, 0, test_now_ns));
    send.owe_probes(&server, .application, 1);
    try testing.expectError(error.NothingSent, send_into(&server, 0, test_now_ns));
    migration.on_response(&server, new_path_data);
    const after = try send_into(&server, 0, test_now_ns);
    try testing.expect(after.packets[0].ack_eliciting);
}

test "decision 72: each challenge on a path awaiting validation repeats the latest ACK" {
    open_pair(true);
    try move_server(rebound_address);
    _ = try send_into(&server, 0, test_now_ns);
    // The first challenge carried the ACK of the client's PING, and is lost.
    _ = try send_into(&server, 1, test_now_ns);
    migration.on_response(&server, previous_path_data);
    const due_ns = migration.challenge_deadline_ns(&server).?;
    _ = try timer.on_instant(&server, suite_holder.suite(), &recovery_scratch, due_ns);
    // A datagram of the client's that asks for nothing lifts §8's limit, and brings nothing new
    // to acknowledge.
    server.path.on_datagram_received(constants.datagram_len_min);
    const recorded = client.recovery.table_of(.application).count();
    const resent = try send_into(&server, 0, due_ns);
    _ = try deliver(&client, resent, 0, server_address, due_ns);
    // The client's PING is acknowledged, so its window has room for the PATH_RESPONSE.
    try testing.expect(client.recovery.table_of(.application).count() < recorded);
}
