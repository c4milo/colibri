//! The tests of the closes colibri owes on its own (`connection_close.zig`): a connection error
//! that `receive` or `send` finds closes the connection at once, and the CONNECTION_CLOSE that
//! names it is owed without the caller asking (RFC 9000 §10.2). Running out of packet numbers
//! closes it with no frame at all (§12.3). Split out of `connection_close_test.zig` for length.
const std = @import("std");
const core = @import("core");
const tls_provider = @import("tls_provider");
const constants = @import("../constants.zig");
const transport_parameters = @import("../transport_parameters.zig");
const connection_module = @import("connection.zig");
const keys = @import("connection_keys.zig");
const send = @import("connection_send.zig");
const close_module = @import("connection_close.zig");
const datagram_module = @import("connection_datagram.zig");
const build_test = @import("packet_build/packet_build_test.zig");
const StreamProvider = @import("../stream/stream_provider.zig").StreamProvider;

const Level = core.Level;
const Connection = connection_module.Connection;
const testing = std.testing;

var client: Connection align(@alignOf(Connection)) = undefined;
var server: Connection align(@alignOf(Connection)) = undefined;
var suite_holder: build_test.RoundTrip align(@alignOf(build_test.RoundTrip)) = undefined;
var provider_holder: build_test.Fake align(@alignOf(build_test.Fake)) = undefined;
var send_scratch: send.DefaultScratch align(@alignOf(send.DefaultScratch)) = .{};
var scratch: datagram_module.Scratch align(@alignOf(datagram_module.Scratch)) = undefined;
var datagram: [constants.datagram_len_min]u8 = undefined;

const test_now_ns: u64 = 1_000_000;
const test_max_data: u64 = 1_048_576;
const id_len: usize = 4;
const local_octet: u8 = 0xc1;
const peer_octet: u8 = 0x51;
const local_id: [id_len]u8 = @splat(local_octet);
const peer_id: [id_len]u8 = @splat(peer_octet);
const flight_octet: u8 = 0x6d;
const flight_len: usize = 40;
const flight: [flight_len]u8 = @splat(flight_octet);
/// A packet number the server never sent, which the client acknowledges.
const unsent_number: u64 = 5;
/// RFC 9001 §4.8: handshake_failure (40) added to 0x0100.
const handshake_failure_code: u64 = 0x0128;

/// Two endpoints with the keys of every level in `levels`, in both directions.
fn open_pair(levels: []const Level) void {
    suite_holder.init();
    provider_holder = .{};
    open_one(&client, .client, levels);
    open_one(&server, .server, levels);
    // RFC 9000 §8.1: a server sends only after it has received.
    server.path.on_datagram_received(constants.datagram_len_min);
}

fn open_one(connection: *Connection, role: connection_module.Role, levels: []const Level) void {
    var parameters = transport_parameters.Parameters.initial();
    parameters.initial_max_data = test_max_data;
    connection.init(.{
        .role = role,
        .local_parameters = parameters,
        .now_ns = test_now_ns,
        .identity = .{ .local_initial_source = &local_id, .original_destination = &peer_id },
    });
    for (levels) |level| {
        keys.on_keys_installed(connection, level, .read);
        keys.on_keys_installed(connection, level, .write);
    }
}

fn send_raw(connection: *Connection) send.Error!?send.Sent {
    return send.send(connection, suite_holder.suite(), provider_holder.provider(), StreamProvider.none(), &send_scratch, &datagram, test_now_ns);
}

fn receive(connection: *Connection, len: usize) datagram_module.Error!datagram_module.Received {
    return datagram_module.receive(connection, suite_holder.suite(), provider_holder.provider(), .{ .octets = datagram[0..len], .now_ns = test_now_ns, .ecn = .not_ect }, &scratch);
}

test "RFC 9000 §10.2: a connection error receive finds owes the CONNECTION_CLOSE that names it" {
    open_pair(&.{.handshake});
    // RFC 9000 §13.1: the client acknowledges a packet the server never sent.
    _ = client.space_at(.handshake).receive(unsent_number, test_now_ns, true, .not_ect);
    const sent = (try send_raw(&client)).?;
    try testing.expectError(error.AcknowledgedUnsentPacket, receive(&server, sent.len));
    const owed = server.pending_close.?;
    try testing.expectEqual(.transport, owed.layer);
    try testing.expectEqual(datagram_module.connection_error_code(&server, error.AcknowledgedUnsentPacket), owed.error_code);
    // The server's next datagram carries it, and the server enters the closing state (§10.2.1).
    try testing.expect(close_module.owes(&server));
    _ = (try send_raw(&server)).?;
    try testing.expectEqual(.closing, server.termination.state);
}

test "RFC 9001 §4.8: TLS failing while send writes its octets owes the alert's CRYPTO_ERROR close" {
    open_pair(&.{.initial});
    provider_holder = .{ .owed = &flight, .refuse_write = true, .alert_held = .handshake_failure };
    try testing.expectError(error.Crypto, send_raw(&client));
    try testing.expectEqual(handshake_failure_code, client.pending_close.?.error_code);
    try testing.expect(client.tls_failed);
}

test "RFC 9000 §12.3: a space out of packet numbers closes with no frame and sends nothing after" {
    open_pair(&.{.initial});
    provider_holder = .{ .owed = &flight };
    client.space_at(.initial).next_packet_number = constants.packet_number_max + 1;
    try testing.expectError(error.PacketNumbersExhausted, send_raw(&client));
    try testing.expectEqual(null, client.pending_close);
    try testing.expectEqual(.closed, client.termination.state);
    try testing.expectEqual(.packet_numbers_exhausted, client.termination.reason.?);
    try testing.expectEqual(null, try send_raw(&client));
}
