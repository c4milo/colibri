//! The tests of `connection_qlog.zig`: what a connection with a log writes into it, read back as
//! the records `qlog.Log` holds. The packets come from the other endpoint's send path, so what is
//! logged on receipt is what colibri writes.
const std = @import("std");
const core = @import("core");
const qlog = @import("qlog");
const constants = @import("../constants.zig");
const error_code = @import("../error_code.zig");
const transport_parameters = @import("../transport_parameters.zig");
const StreamProvider = @import("../stream/stream_provider.zig").StreamProvider;
const connection_module = @import("connection.zig");
const keys = @import("connection_keys.zig");
const send = @import("connection_send.zig");
const close_module = @import("connection_close.zig");
const datagram_module = @import("connection_datagram.zig");
const header_write = @import("../packet/packet_header_write.zig");
const connection_qlog = @import("connection_qlog.zig");
const connection_timer = @import("connection_timer.zig");
const build_test = @import("packet_build/packet_build_test.zig");

const Level = core.Level;
const Connection = connection_module.Connection;
const Parameters = transport_parameters.Parameters;
const testing = std.testing;

/// Room for every record one test writes. Test-only.
const log_len: usize = 16_384;

var client: Connection align(@alignOf(Connection)) = undefined;
var server: Connection align(@alignOf(Connection)) = undefined;
var client_log: qlog.Log align(@alignOf(qlog.Log)) = undefined;
var server_log: qlog.Log align(@alignOf(qlog.Log)) = undefined;
var client_log_buffer: [log_len]u8 = undefined;
var server_log_buffer: [log_len]u8 = undefined;
var suite_holder: build_test.RoundTrip align(@alignOf(build_test.RoundTrip)) = undefined;
var provider_holder: build_test.Fake align(@alignOf(build_test.Fake)) = undefined;
var send_scratch: send.DefaultScratch align(@alignOf(send.DefaultScratch)) = .{};
var scratch: datagram_module.Scratch align(@alignOf(datagram_module.Scratch)) = undefined;
var datagram: [constants.datagram_len_min]u8 = undefined;

const test_now_ns: u64 = 1_000_000;
const test_max_data: u64 = 1_048_576;
/// The instant the tests act at, 1.5 milliseconds into the log. Test-only.
const later_ns: u64 = 2_500_000;
const id_len: usize = 4;
const local_octet: u8 = 0xc1;
const peer_octet: u8 = 0x51;
const local_id: [id_len]u8 = @splat(local_octet);
const peer_id: [id_len]u8 = @splat(peer_octet);
const schemas = [_][]const u8{qlog.quic_event_schema};
/// Probes enough for RFC 9002 §6.1.1's packet threshold of three to lose the first when the last
/// is acknowledged. Test-only.
const threshold_probes: usize = 4;
/// The server acknowledges the last probe 5 ms after the probes left at `later_ns`, and the client
/// reads the acknowledgment 5 ms later, a round trip of 10 ms. Test-only.
const ack_sent_ns: u64 = 7_500_000;
const ack_read_ns: u64 = 12_500_000;
/// Past RFC 9002 §6.1.2's time threshold for the probes, 9/8 of that round trip. Test-only.
const past_loss_time_ns: u64 = 22_500_000;
/// A frame type RFC 9000 §12.4 does not define: the one after the last of Table 3.
const unknown_frame_type: u8 = constants.frame_handshake_done + 1;

fn parameters() Parameters {
    var held = Parameters.initial();
    held.initial_max_data = test_max_data;
    return held;
}

/// Two endpoints with the keys of every level in `levels`, each logging into its own buffer.
fn open_pair(levels: []const Level) !void {
    suite_holder.init();
    provider_holder = .{};
    try open_one(&client, &client_log, &client_log_buffer, .client, levels);
    try open_one(&server, &server_log, &server_log_buffer, .server, levels);
    // RFC 9000 §8.1: a server sends only after it has received.
    server.path.on_datagram_received(constants.datagram_len_min);
}

fn open_one(connection: *Connection, log: *qlog.Log, buffer: []u8, role: connection_module.Role, levels: []const Level) !void {
    log.* = qlog.Log.init(buffer, qlog.Features.none());
    try log.start(.{ .vantage_point = if (role == .client) .client else .server, .group_id = &peer_id, .event_schemas = &schemas }, test_now_ns);
    // The tests read the events the connection writes, so the header goes.
    log.clear();
    open_connection(connection, role, log, levels);
}

fn open_connection(connection: *Connection, role: connection_module.Role, log: ?*qlog.Log, levels: []const Level) void {
    connection.init(.{
        .role = role,
        .local_parameters = parameters(),
        .now_ns = test_now_ns,
        .identity = .{ .local_initial_source = &local_id, .original_destination = &peer_id },
        .qlog = log,
    });
    for (levels) |level| {
        keys.on_keys_installed(connection, level, .read);
        keys.on_keys_installed(connection, level, .write);
    }
}

fn send_from(connection: *Connection, now_ns: u64) !send.Sent {
    return try send.send(connection, suite_holder.suite(), provider_holder.provider(), StreamProvider.none(), &send_scratch, &datagram, now_ns) orelse error.NothingSent;
}

fn receive(connection: *Connection, len: usize, now_ns: u64) datagram_module.Error!datagram_module.Received {
    return datagram_module.receive(connection, suite_holder.suite(), provider_holder.provider(), .{ .octets = datagram[0..len], .now_ns = now_ns, .ecn = .not_ect }, &scratch);
}

fn expect_record(log: *const qlog.Log, expected: []const u8) !void {
    if (std.mem.indexOf(u8, log.bytes(), expected) != null) return;
    std.debug.print("record not in the log: {s}\nlog: {s}\n", .{ expected, log.bytes() });
    return error.TestExpectedRecord;
}

fn count_of(log: *const qlog.Log, needle: []const u8) usize {
    return std.mem.count(u8, log.bytes(), needle);
}

test "a connection with a log starts it with its versions and its own parameters" {
    try open_pair(&.{});
    var log = qlog.Log.init(&client_log_buffer, qlog.Features.none());
    try log.start(.{ .vantage_point = .client, .group_id = &peer_id, .event_schemas = &schemas }, test_now_ns);
    const header_len = log.len;
    open_connection(&client, .client, &log, &.{});
    const events = log.bytes()[header_len..];
    try testing.expect(std.mem.startsWith(u8, events, "\x1e{\"time\":0.000,\"name\":\"quic:version_information\",\"data\":" ++
        "{\"client_versions\":[\"6b3343cf\",\"00000001\"],\"chosen_version\":\"00000001\"}}\n"));
    // RFC 9000 §7.3: a client's parameters carry its own first Source Connection ID alone.
    try expect_record(&log, "\"name\":\"quic:parameters_set\",\"data\":{\"initiator\":\"local\"," ++
        "\"initial_source_connection_id\":\"c1c1c1c1\",\"disable_active_migration\":false,");
    try testing.expectEqual(2, std.mem.count(u8, events, "\x1e"));
    try expect_record(&server_log, "\"server_versions\":[\"00000001\",\"6b3343cf\"],\"chosen_version\":\"00000001\"");
    try expect_record(&server_log, "\"original_destination_connection_id\":\"51515151\"");
}

test "a probe is logged as sent and as received, with its frames" {
    try open_pair(&.{.handshake});
    client_log.clear();
    server_log.clear();
    send.owe_probes(&client, .handshake, 1);
    const sent = try send_from(&client, later_ns);
    try expect_record(&client_log, "\x1e{\"time\":1.500,\"name\":\"quic:packet_sent\",\"data\":{\"header\":" ++
        "{\"packet_type\":\"handshake\",\"packet_number\":0},\"raw\":{\"length\":");
    try expect_record(&client_log, "\"frames\":[{\"frame_type\":\"ping\"}]}}\n");
    // Quic-events §4.6: a Handshake packet sent is the handshake started.
    try expect_record(&client_log, "\"name\":\"quic:connection_state_updated\",\"data\":{\"new\":\"handshake_started\"}}\n");
    try expect_record(&client_log, "\"name\":\"quic:recovery_metrics_updated\",\"data\":{\"smoothed_rtt\":333.000,");
    // A state is logged when the connection enters it, and not again.
    connection_qlog.log_changes(&client, null, later_ns);
    try testing.expectEqual(1, count_of(&client_log, "quic:connection_state_updated"));
    _ = try receive(&server, sent.len, later_ns);
    try expect_record(&server_log, "\"name\":\"quic:packet_received\",\"data\":{\"header\":" ++
        "{\"packet_type\":\"handshake\",\"packet_number\":0},\"raw\":{\"length\":");
    try expect_record(&server_log, "\"frames\":[{\"frame_type\":\"ping\"}]}}\n");
    // RFC 9000 §12.3: the same packet again is a duplicate, and dropped as one.
    _ = try receive(&server, sent.len, later_ns);
    try expect_record(&server_log, "\"name\":\"quic:packet_dropped\",\"data\":{\"raw\":{\"length\":");
    try expect_record(&server_log, "},\"trigger\":\"duplicate\"}}\n");
}

test "each packet of a coalesced datagram is logged with its own length" {
    try open_pair(&.{ .initial, .handshake });
    send.owe_probes(&client, .initial, 1);
    send.owe_probes(&client, .handshake, 1);
    const sent = try send_from(&client, later_ns);
    try testing.expectEqual(2, sent.count);
    server_log.clear();
    _ = try receive(&server, sent.len, later_ns);
    try testing.expectEqual(2, count_of(&server_log, "\"name\":\"quic:packet_received\""));
    var expected: [2][64]u8 = undefined;
    for (sent.written(), 0..) |packet, index| {
        const length = try std.fmt.bufPrint(&expected[index], "\"raw\":{{\"length\":{d},", .{packet.len});
        try expect_record(&server_log, length);
    }
    // RFC 9000 §14.1: the client padded the datagram, and the padding is a frame of the last
    // packet, logged with its length.
    try expect_record(&client_log, "{\"frame_type\":\"padding\",\"raw\":{\"payload_length\":");
}

test "an ACK frame's delay is decoded by the exponent of the endpoint that sent it" {
    try open_pair(&.{.handshake});
    // RFC 9000 §18.2: an exponent other than the default 3, which each side reads its own way.
    const exponent: u64 = 10;
    server.local_parameters.ack_delay_exponent = exponent;
    var peer = parameters();
    peer.ack_delay_exponent = exponent;
    connection_module.apply_peer_parameters(&client, peer);
    send.owe_probes(&client, .handshake, 1);
    const probe = try send_from(&client, later_ns);
    _ = try receive(&server, probe.len, later_ns);
    // 10 milliseconds later the ACK Delay is 10,000 microseconds, which the exponent writes as 9
    // (RFC 9000 §19.3) and reads back as 9,216 microseconds.
    const ack_at_ns = later_ns + 10_000_000;
    const ack = try send_from(&server, ack_at_ns);
    const delay = "{\"frame_type\":\"ack\",\"ack_delay\":9.216,\"acked_ranges\":[[0]]}";
    try expect_record(&server_log, delay);
    _ = try receive(&client, ack.len, ack_at_ns);
    try expect_record(&client_log, delay);
}

test "a frame that does not parse ends a packet's frame list, and the packet is still logged" {
    try open_pair(&.{ .initial, .handshake });
    send.owe_probes(&client, .initial, 1);
    send.owe_probes(&client, .handshake, 1);
    const sent = try send_from(&client, later_ns);
    // `RoundTrip` protects nothing, so the last packet's PING is the datagram's last octet that is
    // not zero: its PADDING and its tag follow. The first octet of the PADDING becomes a frame of
    // no defined type.
    const ping_at = std.mem.findLastNone(u8, datagram[0..sent.len], &.{0}).?;
    datagram[ping_at + 1] = unknown_frame_type;
    server_log.clear();
    try testing.expectError(error.FrameEncoding, receive(&server, sent.len, later_ns));
    // Both packets are logged, each with the PING a reader could follow.
    try testing.expectEqual(2, count_of(&server_log, "\"frames\":[{\"frame_type\":\"ping\"}]}}\n"));
    try testing.expectEqual(0, server_log.dropped);
}

test "a lost packet is logged with its cause, when one cause alone explains it" {
    try open_pair(&.{.handshake});
    var last: send.Sent = undefined;
    for (0..threshold_probes) |_| {
        send.owe_probes(&client, .handshake, 1);
        last = try send_from(&client, later_ns);
    }
    // The server reads the last probe alone, and its ACK names that one.
    _ = try receive(&server, last.len, ack_sent_ns);
    const ack = try send_from(&server, ack_sent_ns);
    _ = try receive(&client, ack.len, ack_read_ns);
    // Either threshold may declare a packet an ACK reveals lost, so no cause is logged.
    try expect_record(&client_log, "\"name\":\"quic:packet_lost\",\"data\":{\"header\":" ++
        "{\"packet_type\":\"handshake\",\"packet_number\":0}}}\n");
    // The two between wait for the time threshold, which the loss timer is set for.
    _ = try connection_timer.on_instant(&client, suite_holder.suite(), &scratch.recovery, past_loss_time_ns);
    try expect_record(&client_log, "\"packet_number\":1},\"trigger\":\"time_threshold\"}}\n");
    try expect_record(&client_log, "\"packet_number\":2},\"trigger\":\"time_threshold\"}}\n");
    try testing.expectEqual(3, count_of(&client_log, "quic:packet_lost"));
}

test "a probe timeout logs the packets it declares lost, and counts itself" {
    try open_pair(&.{.handshake});
    send.owe_probes(&client, .handshake, 1);
    _ = try send_from(&client, later_ns);
    const deadline = connection_timer.next(&client).?;
    try testing.expectEqual(connection_timer.Kind.loss, deadline.kind);
    _ = try connection_timer.on_instant(&client, suite_holder.suite(), &scratch.recovery, deadline.at_ns);
    // Decision 64 declares every Handshake packet in flight lost on a probe timeout.
    try expect_record(&client_log, "\"name\":\"quic:packet_lost\",\"data\":{\"header\":" ++
        "{\"packet_type\":\"handshake\",\"packet_number\":0},\"trigger\":\"pto_expired\"}}\n");
    try expect_record(&client_log, "\"pto_count\":1");
}

test "a packet that does not open is logged as dropped, with the octets it held" {
    try open_pair(&.{.handshake});
    server_log.clear();
    // Octets whose first says a short header of a connection ID nothing issued, so nothing opens.
    const garbage_len: usize = 50;
    @memset(datagram[0..garbage_len], 0);
    const received = try receive(&server, garbage_len, later_ns);
    try testing.expectEqual(0, received.processed);
    try expect_record(&server_log, "\"name\":\"quic:packet_dropped\",\"data\":{\"raw\":{\"length\":50},\"trigger\":\"invalid\"}}\n");
}

test "a packet in a version the connection does not admit is logged as dropped, unsupported" {
    try open_pair(&.{.handshake});
    server_log.clear();
    var writer = core.Writer.init(&datagram);
    try header_write.write_long(&writer, .{ .version = .v2, .type = .handshake, .dcid = &local_id, .scid = &peer_id, .packet_number = .{ .value = 0, .len = 1 }, .protected_payload_len = 32 });
    try writer.write_bytes(&([_]u8{0} ** 32));
    const received = try receive(&server, writer.written().len, later_ns);
    try testing.expectEqual(0, received.processed);
    // Quic-events §5.7: "unsupported: unknown or unsupported version".
    try expect_record(&server_log, "\"name\":\"quic:packet_dropped\"");
    try expect_record(&server_log, "\"trigger\":\"unsupported\"}}\n");
}

test "a close is logged once on each side, with its code and the state it enters" {
    try open_pair(&.{.handshake});
    close_module.owe(&client, close_module.transport(error_code.protocol_violation, null));
    const sent = try send_from(&client, later_ns);
    try expect_record(&client_log, "\"name\":\"quic:connection_closed\",\"data\":{\"initiator\":\"local\"," ++
        "\"connection_error\":\"protocol_violation\",\"trigger\":\"error\"}}\n");
    try expect_record(&client_log, "\"data\":{\"new\":\"closing\"}}\n");
    _ = try receive(&server, sent.len, later_ns);
    try expect_record(&server_log, "{\"frame_type\":\"connection_close\",\"error_space\":\"transport\"," ++
        "\"error\":\"protocol_violation\"");
    try expect_record(&server_log, "\"name\":\"quic:connection_closed\",\"data\":{\"initiator\":\"remote\"," ++
        "\"connection_error\":\"protocol_violation\",\"trigger\":\"error\"}}\n");
    // The server had logged no state: the close was the first packet it received.
    try expect_record(&server_log, "\"name\":\"quic:connection_state_updated\",\"data\":{\"new\":\"draining\"}}\n");
    try testing.expectEqual(1, count_of(&server_log, "quic:connection_closed"));
}

test "the peer's parameters and the chosen protocol are logged once, when the parameters arrive" {
    try open_pair(&.{});
    connection_qlog.log_changes(&client, provider_holder.provider(), later_ns);
    try testing.expectEqual(0, count_of(&client_log, "\"initiator\":\"remote\""));
    try testing.expectEqual(0, count_of(&client_log, "quic:alpn_information"));
    var peer = Parameters.initial();
    peer.initial_source_connection_id = .of(&peer_id);
    connection_module.apply_peer_parameters(&client, peer);
    connection_qlog.log_changes(&client, provider_holder.provider(), later_ns);
    connection_qlog.log_changes(&client, provider_holder.provider(), later_ns);
    try testing.expectEqual(1, count_of(&client_log, "\"initiator\":\"remote\""));
    try expect_record(&client_log, "\"initiator\":\"remote\",\"initial_source_connection_id\":\"51515151\"");
    // `Fake` negotiates h3 (RFC 9114 §3.1).
    try expect_record(&client_log, "\"name\":\"quic:alpn_information\",\"data\":{\"chosen_alpn\":{\"byte_value\":\"6833\"}}}\n");
    try testing.expectEqual(1, count_of(&client_log, "quic:alpn_information"));
}

test "recovery metrics are logged only when one changed, and only the ones that did" {
    try open_pair(&.{});
    client_log.clear();
    connection_qlog.log_changes(&client, null, later_ns);
    try testing.expectEqual(1, count_of(&client_log, "quic:recovery_metrics_updated"));
    connection_qlog.log_changes(&client, null, later_ns);
    try testing.expectEqual(1, count_of(&client_log, "quic:recovery_metrics_updated"));
    client_log.clear();
    client.recovery.congestion.window -= 1;
    connection_qlog.log_changes(&client, null, later_ns);
    var expected: [128]u8 = undefined;
    try expect_record(&client_log, try std.fmt.bufPrint(&expected, "\"name\":\"quic:recovery_metrics_updated\",\"data\":" ++
        "{{\"congestion_window\":{d}}}}}\n", .{client.recovery.congestion.window}));
    // Nothing was sent or received, so no state was entered.
    try testing.expectEqual(0, count_of(&client_log, "quic:connection_state_updated"));
}

test "a log changes nothing the connection sends" {
    try open_pair(&.{ .initial, .handshake });
    send.owe_probes(&client, .initial, 1);
    const logged = try send_from(&client, later_ns);
    var logged_datagram: [constants.datagram_len_min]u8 = undefined;
    @memcpy(logged_datagram[0..logged.len], datagram[0..logged.len]);
    suite_holder.init();
    open_connection(&client, .client, null, &.{ .initial, .handshake });
    send.owe_probes(&client, .initial, 1);
    const unlogged = try send_from(&client, later_ns);
    try testing.expectEqualSlices(u8, logged_datagram[0..logged.len], datagram[0..unlogged.len]);
    try testing.expect(client.qlog.log == null);
}
