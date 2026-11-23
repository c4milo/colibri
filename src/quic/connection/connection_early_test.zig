//! The tests of `connection_early.zig` on a connection: a server keeps the 1-RTT packets that
//! arrive before its handshake completes, and opens them once it does (RFC 9001 §5.7,
//! https://github.com/c4milo/colibri/issues/153). The datagrams come from the other endpoint's
//! send path, so what is received is what colibri writes.
const std = @import("std");
const core = @import("core");
const constants = @import("../constants.zig");
const transport_parameters = @import("../transport_parameters.zig");
const StreamProvider = @import("../stream/stream_provider.zig").StreamProvider;
const connection_module = @import("connection.zig");
const early_module = @import("connection_early.zig");
const keys = @import("connection_keys.zig");
const send = @import("connection_send.zig");
const datagram_module = @import("connection_datagram.zig");
const build_test = @import("packet_build/packet_build_test.zig");
const support = @import("connection_datagram_test_support.zig");

const Level = core.Level;
const Writer = core.Writer;
const Connection = connection_module.Connection;
const Recorder = support.Recorder;
const EarlyPackets = early_module.EarlyPackets;
const Ecn = @FieldType(EarlyPackets.Kept, "ecn");
const testing = std.testing;

var client: Connection align(@alignOf(Connection)) = undefined;
var server: Connection align(@alignOf(Connection)) = undefined;
var suite_holder: build_test.RoundTrip align(@alignOf(build_test.RoundTrip)) = undefined;
var provider_holder: build_test.Fake align(@alignOf(build_test.Fake)) = undefined;
var send_scratch: send.Scratch(.{}) align(@alignOf(send.Scratch(.{}))) = .{};
var scratch: datagram_module.Scratch align(@alignOf(datagram_module.Scratch)) = undefined;
var datagram: [constants.protocol.datagram_len_min]u8 = undefined;
var recorder: Recorder align(@alignOf(Recorder)) = .{};
/// The client's transport parameters as its ClientHello would carry them (RFC 9001 §8.2).
var client_body: [constants.protocol.datagram_len_min]u8 = undefined;

/// When the early packet arrives, and the later instant its Finished does. Test-only.
const arrived_ns: u64 = 1_000_000;
const finished_ns: u64 = 5_000_000;
const test_max_data: u64 = 1_048_576;
const id_len: usize = 4;
const local_octet: u8 = 0xc1;
const peer_octet: u8 = 0x51;
const local_id: [id_len]u8 = @splat(local_octet);
const peer_id: [id_len]u8 = @splat(peer_octet);

fn parameters() transport_parameters.Parameters {
    var held = transport_parameters.Parameters.initial();
    held.initial_max_data = test_max_data;
    return held;
}

/// Two endpoints with the keys of every level, in both directions.
fn open_pair() void {
    suite_holder.init();
    provider_holder = .{};
    recorder = .{};
    open_one(&client, .client);
    open_one(&server, .server);
    // RFC 9000 §8.1: a server sends only after it has received.
    server.path.on_datagram_received(constants.protocol.datagram_len_min);
}

fn open_one(connection: *Connection, role: connection_module.Role) void {
    connection.init(.{
        .role = role,
        .local_parameters = parameters(),
        .now_ns = arrived_ns,
        .identity = .{ .local_initial_source = &local_id, .original_destination = &peer_id },
    });
    for ([_]Level{ .initial, .handshake, .application }) |level| {
        keys.on_keys_installed(connection, level, .read);
        keys.on_keys_installed(connection, level, .write);
    }
}

/// The datagram that `connection` sends next, holding one probe at `level`.
fn probe_from(connection: *Connection, level: Level) !send.Sent {
    send.owe_probes(connection, level, 1);
    return try send.send(connection, suite_holder.suite(), provider_holder.provider(), StreamProvider.none(), .{}, &send_scratch, &datagram, arrived_ns) orelse error.NothingSent;
}

fn receive_at(connection: *Connection, len: usize, now_ns: u64) datagram_module.Error!datagram_module.Received {
    return datagram_module.receive(connection, suite_holder.suite(), recorder.provider(), .{ .octets = datagram[0..len], .now_ns = now_ns, .ecn = .not_ect }, &scratch);
}

/// The client's Handshake packet, which its Finished travels in, arriving at the server at
/// `finished_ns` and completing the server's handshake.
fn complete_server() !datagram_module.Received {
    const finished = try probe_from(&client, .handshake);
    var writer = Writer.init(&client_body);
    try transport_parameters.write(&writer, &client.local_parameters, .client);
    recorder = .{ .peer_body = writer.written(), .done = true };
    return try receive_at(&server, finished.len, finished_ns);
}

fn application_space(connection: *Connection) *@TypeOf(connection.spaces[0]) {
    return connection_module.space_at(connection, .application);
}

test "RFC 9001 §5.7: a 1-RTT packet that arrives before the handshake completes opens once it does" {
    open_pair();
    client.handshake_complete = true;
    // The client's Finished was lost, and its 1-RTT packet arrives alone.
    const early = try probe_from(&client, .application);
    try testing.expectEqual(1, early.count);
    const kept = try receive_at(&server, early.len, arrived_ns);
    try testing.expectEqual(0, kept.processed);
    try testing.expectEqual(1, server.early_packets.count);
    try testing.expectEqual(null, application_space(&server).received.largest());
    // The Finished arrives later, and the kept packet opens behind it.
    const completed = try complete_server();
    try testing.expect(completed.handshake_completed);
    try testing.expectEqual(2, completed.processed);
    try testing.expectEqual(early.packets[0].packet_number, application_space(&server).received.largest().?);
    try testing.expectEqual(0, server.early_packets.count);
    try testing.expectEqual(1, server.early_packets.opened);
    // RFC 9000 §13.2.5: the ACK Delay counts the wait for the keys, so the space records the
    // instant the packet arrived. The idle timer restarts at the instant it opened (§10.1).
    try testing.expectEqual(arrived_ns, application_space(&server).largest_received_at_ns);
    try testing.expectEqual(finished_ns, server.termination.idle_since_ns);
}

test "RFC 9001 §5.7: a server keeps at most early_packets_max packets, and drops the next" {
    open_pair();
    client.handshake_complete = true;
    // Bounded by the limit, and one past it.
    for (0..constants.limits.early_packets_max + 1) |_| {
        const early = try probe_from(&client, .application);
        try testing.expectEqual(0, (try receive_at(&server, early.len, arrived_ns)).processed);
    }
    try testing.expectEqual(constants.limits.early_packets_max, server.early_packets.count);
    const completed = try complete_server();
    try testing.expectEqual(1 + constants.limits.early_packets_max, completed.processed);
    try testing.expectEqual(constants.limits.early_packets_max, server.early_packets.opened);
}

test "RFC 9001 §5.7: a client keeps no 1-RTT packet, and a closing server opens none it kept" {
    open_pair();
    server.handshake_complete = true;
    const from_server = try probe_from(&server, .application);
    try testing.expectEqual(0, (try receive_at(&client, from_server.len, arrived_ns)).processed);
    try testing.expectEqual(0, client.early_packets.count);
    open_pair();
    client.handshake_complete = true;
    const early = try probe_from(&client, .application);
    _ = try receive_at(&server, early.len, arrived_ns);
    try testing.expectEqual(1, server.early_packets.count);
    // RFC 9000 §10.2.1: a closing endpoint is "not required to process any received frame".
    server.termination.on_close_sent(arrived_ns, finished_ns);
    try testing.expectEqual(0, (try complete_server()).processed);
    try testing.expectEqual(0, server.early_packets.opened);
}

test "RFC 9001 §5.7: a long-header packet a server cannot open is not kept" {
    open_pair();
    // The client's Initial packet is held back on the path, behind its Handshake packet.
    const initial = try probe_from(&client, .initial);
    var held: [constants.protocol.datagram_len_min]u8 = undefined;
    @memcpy(held[0..initial.len], datagram[0..initial.len]);
    const handshake = try probe_from(&client, .handshake);
    try testing.expectEqual(1, (try receive_at(&server, handshake.len, arrived_ns)).processed);
    // RFC 9001 §4.9.1: the server discarded its Initial keys on that Handshake packet, so the
    // Initial packet arrives at a level with no keys, before the handshake completes.
    @memcpy(datagram[0..initial.len], held[0..initial.len]);
    try testing.expectEqual(0, (try receive_at(&server, initial.len, arrived_ns)).processed);
    try testing.expectEqual(0, server.early_packets.count);
}

var fixture: EarlyPackets align(@alignOf(EarlyPackets)) = undefined;

test "a kept packet comes back as it arrived, in order, and a full store keeps no more" {
    fixture.init();
    const first = [_]u8{ 0x40, 1, 2, 3 };
    const second = [_]u8{ 0x41, 4, 5 };
    try testing.expect(fixture.keep(&first, 10, .not_ect));
    try testing.expect(fixture.keep(&second, 20, .ect_0));
    try testing.expectEqual(2, fixture.count);
    try testing.expectEqualSlices(u8, &first, fixture.octets_of(0));
    try testing.expectEqualSlices(u8, &second, fixture.octets_of(1));
    try testing.expectEqual(20, fixture.packets[1].arrived_ns);
    try testing.expectEqual(Ecn.ect_0, fixture.packets[1].ecn);
    fixture.clear();
    try testing.expectEqual(0, fixture.count);
    // Bounded by the entries: each one-octet packet takes one.
    for (0..constants.limits.early_packets_max) |_| try testing.expect(fixture.keep(first[0..1], 30, .not_ect));
    try testing.expect(!fixture.keep(first[0..1], 30, .not_ect));
}

test "a packet longer than the octets left is not kept" {
    fixture.init();
    const whole: [constants.limits.early_packet_octets_max]u8 = @splat(0x40);
    try testing.expect(fixture.keep(whole[0 .. whole.len - 1], 10, .not_ect));
    try testing.expect(!fixture.keep(whole[0..2], 10, .not_ect));
    try testing.expect(fixture.keep(whole[0..1], 10, .not_ect));
    try testing.expectEqual(constants.limits.early_packet_octets_max, fixture.octets_len);
}
