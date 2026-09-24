//! The tests of `connection_recovery.zig`: one batch of acknowledged or lost packets reaches every
//! piece that keeps a record of what it sent. Each piece's own rules are tested where it lives;
//! these check only that the batch arrives.
const std = @import("std");
const core = @import("core");
const constants = @import("../constants.zig");
const transport_parameters = @import("../transport_parameters.zig");
const connection_id = @import("../connection_id.zig");
const recovery_sent = @import("../recovery/recovery_sent.zig");
const stream_module = @import("../stream/stream.zig");
const connection_module = @import("connection.zig");
const keys = @import("connection_keys.zig");
const id_frames = @import("connection_id_frames.zig");
const recovery = @import("connection_recovery.zig");
const stream_send = @import("connection_stream/connection_stream_send.zig");
const frame_module = @import("../frame/frame.zig");
const frames = @import("connection_frames.zig");
const build_test = @import("packet_build/packet_build_test.zig");

const Level = core.Level;
const Connection = connection_module.Connection;
const Parameters = transport_parameters.Parameters;
const Record = recovery_sent.Record;
const StreamId = stream_module.StreamId;
const testing = std.testing;

var server: Connection = undefined;
var suite_holder: build_test.RoundTrip = undefined;

const test_now_ns: u64 = 1_000_000;
const id_len: usize = 4;
const local_octet: u8 = 0xc1;
const peer_octet: u8 = 0x51;
const local_id: [id_len]u8 = @splat(local_octet);
const peer_id: [id_len]u8 = @splat(peer_octet);
const test_max_data: u64 = 1_048_576;
const generous_limit: u64 = 4;
const issued_octet: u8 = 0x6a;
const issued_id: [id_len]u8 = @splat(issued_octet);
const token_octet: u8 = 0x9d;
const token: [constants.stateless_reset_token_len]u8 = @splat(token_octet);
/// The packet every piece says it last carried its frame in. Test-only.
const carrying: u64 = 5;
/// Octets of the stream range the packet carried. Test-only.
const range_len: u16 = 100;
const completed_max: usize = 2;

fn parameters() Parameters {
    var held = Parameters.initial();
    held.initial_max_data = test_max_data;
    held.initial_max_stream_data_bidi_remote = test_max_data;
    held.initial_max_streams_bidi = generous_limit;
    held.active_connection_id_limit = generous_limit;
    return held;
}

fn open_server() void {
    open_as(.server);
    server.apply_peer_parameters(parameters());
}

/// An endpoint of `role` holding keys at every level, before the peer's parameters arrive.
fn open_as(role: connection_module.Role) void {
    suite_holder.init();
    server.init(.{
        .role = role,
        .local_parameters = parameters(),
        .now_ns = test_now_ns,
        .identity = .{ .local_initial_source = &local_id, .original_destination = &peer_id },
    });
    for ([_]Level{ .initial, .handshake, .application }) |level| {
        keys.on_keys_installed(&server, level, .read);
        keys.on_keys_installed(&server, level, .write);
    }
}

/// A stream the server opened and framed `range_len` octets and its FIN on, as one packet would.
fn framed_stream() !StreamId {
    const id = try stream_send.open(&server, .bidirectional);
    try stream_send.supply(&server, id, range_len, true);
    const stream = server.streams.lookup(id).live;
    _ = stream.sending.on(.sent_fin);
    stream.outgoing.on_framed(range_len, true);
    return id;
}

fn carried_range(id: StreamId) Record {
    return .{
        .number = carrying,
        .sent_at_ns = test_now_ns,
        .sent_len = range_len,
        .ack_eliciting = true,
        .in_flight = true,
        .carries = .stream_fin,
        .data_offset = 0,
        .data_len = range_len,
        .stream_id = id.value,
    };
}

test "decision 59: a lost packet reaches every piece that sent what it carried" {
    open_server();
    const id = try framed_stream();
    server.handshake_done.sent_in = carrying;
    server.max_data.on_sent(carrying);
    _ = try id_frames.issue(&server, &issued_id, &token);
    server.local_ids.active_ids()[1].new_frame.on_sent(carrying);

    try recovery.on_packets_lost(&server, .application, &.{carried_range(id)});
    try testing.expectEqual(1, server.streams.lost.count);
    try testing.expect(server.handshake_done.owed);
    try testing.expect(server.max_data.owed);
    try testing.expect(server.local_ids.active_ids()[1].new_frame.owed);
}

test "decision 59: a lost packet whose CRYPTO octets are forgotten, or a full table, ends the connection" {
    open_server();
    // A window that forgot what it framed, which `connection_crypto.on_packets_lost` reports.
    server.crypto_at(.initial).send_base = 1;
    var crypto: Record = .{ .number = 0, .sent_at_ns = test_now_ns, .sent_len = range_len, .ack_eliciting = true, .in_flight = true };
    crypto.carries = .crypto;
    try testing.expectError(error.CryptoForgotten, recovery.on_packets_lost(&server, .initial, &.{crypto}));

    open_server();
    const id = try framed_stream();
    const gap: u64 = 2;
    for (0..constants.stream_lost_ranges_max) |index| {
        try server.streams.lost.add(.{ .stream_id = id.value + 4, .offset = gap * index, .len = 1, .fin = false });
    }
    try testing.expectError(error.LostRangesFull, recovery.on_packets_lost(&server, .application, &.{carried_range(id)}));
    // RFC 9000 §20.1: INTERNAL_ERROR is 0x01.
    try testing.expectEqual(0x01, recovery.connection_error_code(error.LostRangesFull));
}

test "decision 59: an acknowledged packet reaches every piece that waits on one" {
    open_server();
    const id = try framed_stream();
    server.handshake_done.sent_in = carrying;
    // A retirement whose frame the packet carried.
    const offered: connection_id.Entry = .{ .sequence_number = 1, .len = id_len, .octets = @splat(peer_octet), .stateless_reset_token = token };
    try server.remote_ids.offer(offered, 0, generous_limit);
    const later: connection_id.Entry = .{ .sequence_number = 2, .len = id_len, .octets = @splat(issued_octet), .stateless_reset_token = token };
    try server.remote_ids.offer(later, 2, generous_limit);
    server.remote_ids.retirements()[0].frame.on_sent(carrying);

    var completed: [completed_max]StreamId = undefined;
    const held = recovery.on_packets_acknowledged(&server, .application, &.{carried_range(id)}, &completed);
    try testing.expectEqual(1, held.written);
    try testing.expectEqual(id.value, completed[0].value);
    try testing.expectEqual(null, server.handshake_done.sent_in);
    try testing.expectEqual(0, server.remote_ids.retirements().len);
}

/// Where an ACK frame's packets go while RFC 9002 takes them. Test-only.
var scratch: recovery.Scratch = undefined;
/// When the tests send, and two round trips a path might show. Test-only.
const sent_at_ns: u64 = 1_000_000_000;
const round_trip_ns: u64 = 100_000_000;
const slower_round_trip_ns: u64 = 150_000_000;
/// 50 ms as the ACK Delay field carries it: microseconds over 2^4, an exponent the peer's
/// parameters set above RFC 9000 §18.2's default of 3. Test-only.
const peer_exponent: u64 = 4;
const delay_field: u64 = 3_125;
/// Packets one space sends before an ACK of the last reveals the first lost (RFC 9002 §6.1.1).
const threshold_packets: u64 = constants.loss_packet_threshold + 1;

/// Records that packet `number` carried `range` of stream `id`, as the send path will (RFC 9002
/// Appendix A.5), and spends the number in the space so the peer may acknowledge it.
fn record_sent(level: Level, carries: recovery_sent.Carries, id: u64, offset: u64, at_ns: u64) !void {
    const number = try server.space_at(level).next_number();
    const kind: @import("../space/space.zig").Kind = @enumFromInt(@intFromEnum(level));
    try server.recovery.on_packet_sent(kind, .{
        .number = number,
        .sent_at_ns = at_ns,
        .sent_len = range_len,
        .ack_eliciting = true,
        .in_flight = true,
        .carries = carries,
        .data_offset = offset,
        .data_len = range_len,
        .stream_id = id,
    }, at_ns);
}

/// The server reads an ACK frame for `smallest` to `largest` at `level`, at `at_ns`.
fn take_ack(level: Level, smallest: u64, largest: u64, delay: u64, at_ns: u64) !frames.Report {
    var payload: [constants.datagram_len_min]u8 = undefined;
    var writer = core.Writer.init(&payload);
    const ack: frame_module.Ack = .{
        .ranges = .{ .largest_acknowledged = largest, .first_range = largest - smallest, .octets = &.{}, .count = 0 },
        .delay = delay,
        .ecn = null,
    };
    try frame_module.write(&writer, .{ .ack = ack });
    return frames.process(&server, .{ .level = level, .payload = writer.written() }, at_ns, &scratch);
}

test "RFC 9002 A.7, decision 59: an ACK frame the connection reads takes its packets out" {
    open_server();
    const id = try framed_stream();
    const window = server.recovery.congestion.window;
    try record_sent(.application, .stream_fin, id.value, 0, sent_at_ns);
    const report = try take_ack(.application, 0, 0, 0, sent_at_ns + round_trip_ns);
    // RFC 9002 §7.8: the window did not bound what was sent, so the acknowledgment grows nothing.
    try testing.expectEqual(window, server.recovery.congestion.window);
    // The packet left flight, the round trip was measured, and the stream it finished is named.
    try testing.expectEqual(0, server.recovery.in_flight_len());
    try testing.expectEqual(round_trip_ns, server.recovery.rtt.smoothed_ns);
    try testing.expectEqual(1, report.completed_streams);
    try testing.expectEqual(id.value, scratch.completed[0].value);
}

test "RFC 9002 A.10, decision 59: an ACK that reveals a loss owes the lost octets again" {
    open_server();
    const id = try stream_send.open(&server, .bidirectional);
    try stream_send.supply(&server, id, range_len * threshold_packets, false);
    const stream = server.streams.lookup(id).live;
    _ = stream.sending.on(.sent_data);
    stream.outgoing.on_framed(range_len * threshold_packets, false);
    for (0..threshold_packets) |index| try record_sent(.application, .stream, id.value, range_len * index, sent_at_ns);
    // Only the last is acknowledged, which RFC 9002 §6.1.1's threshold makes the first lost.
    _ = try take_ack(.application, threshold_packets - 1, threshold_packets - 1, 0, sent_at_ns + round_trip_ns);
    try testing.expectEqual(1, server.streams.lost.count);
    try testing.expectEqual(0, server.streams.lost.oldest().?.offset);
}

test "RFC 9000 §19.3: the ACK Delay is decoded with the peer's exponent, and ignored at Initial" {
    open_server();
    server.peer_parameters.?.ack_delay_exponent = peer_exponent;
    // The first sample sets the estimate; the second arrives 50 ms late by the peer's own account.
    try record_sent(.application, .none, 0, 0, sent_at_ns);
    _ = try take_ack(.application, 0, 0, 0, sent_at_ns + round_trip_ns);
    const later_ns = sent_at_ns + slower_round_trip_ns;
    try record_sent(.application, .none, 0, 0, later_ns);
    _ = try take_ack(.application, 1, 1, delay_field, later_ns + slower_round_trip_ns);
    // RFC 9002 §5.3: the delay comes off the sample, which is the round trip again.
    try testing.expectEqual(round_trip_ns, server.recovery.rtt.smoothed_ns);

    // RFC 9002 §5.3: an endpoint "MAY ignore the acknowledgment delay for Initial packets".
    open_server();
    server.peer_parameters.?.ack_delay_exponent = peer_exponent;
    try record_sent(.initial, .none, 0, 0, sent_at_ns);
    _ = try take_ack(.initial, 0, 0, 0, sent_at_ns + round_trip_ns);
    try record_sent(.initial, .none, 0, 0, later_ns);
    _ = try take_ack(.initial, 1, 1, delay_field, later_ns + slower_round_trip_ns);
    try testing.expect(server.recovery.rtt.smoothed_ns > round_trip_ns);
}

test "decision 59: an ACK that reveals a loss the connection cannot repair is a connection error" {
    open_server();
    // CRYPTO octets the level's window already forgot (`connection_crypto.on_packets_lost`).
    server.crypto_at(.initial).send_base = 1;
    for (0..threshold_packets) |_| try record_sent(.initial, .crypto, 0, 0, sent_at_ns);
    try testing.expectError(
        error.CryptoForgotten,
        take_ack(.initial, threshold_packets - 1, threshold_packets - 1, 0, sent_at_ns + round_trip_ns),
    );
}

/// A max_ack_delay other than RFC 9000 §18.2's default of 25, so a test can see it arrive.
/// Test-only.
const peer_max_ack_delay_ms: u64 = 50;

/// A client's padded Initial carrying only an ACK: in flight, eliciting nothing (RFC 9002 §2).
/// It sets the loss detection timer (Appendix A.5) and leaves the peer nothing to acknowledge.
fn send_padded_ack() !void {
    const number = try server.space_at(.initial).next_number();
    try server.recovery.on_packet_sent(.initial, .{
        .number = number,
        .sent_at_ns = sent_at_ns,
        .sent_len = @intCast(constants.datagram_len_min),
        .ack_eliciting = false,
        .in_flight = true,
    }, sent_at_ns);
}

/// The loss timer, run at the instant it is set for.
fn fire_loss_timer() !bool {
    const at_ns = recovery.loss_deadline_ns(&server).?;
    return recovery.on_loss_timer(&server, at_ns, &scratch);
}

test "RFC 9002 A.9, decision 59: the loss timer declares a packet lost and owes its octets again" {
    open_server();
    const id = try stream_send.open(&server, .bidirectional);
    try stream_send.supply(&server, id, range_len * 2, false);
    const stream = server.streams.lookup(id).live;
    _ = stream.sending.on(.sent_data);
    stream.outgoing.on_framed(range_len * 2, false);
    try record_sent(.application, .stream, id.value, 0, sent_at_ns);
    try record_sent(.application, .stream, id.value, range_len, sent_at_ns);
    // The second is acknowledged, one short of §6.1.1's threshold, so the first waits on §6.1.2.
    _ = try take_ack(.application, 1, 1, 0, sent_at_ns + round_trip_ns);
    try testing.expectEqual(0, server.streams.lost.count);
    const at_ns = recovery.loss_deadline_ns(&server).?;
    try testing.expect(!try recovery.on_loss_timer(&server, at_ns - 1, &scratch));
    try testing.expect(try recovery.on_loss_timer(&server, at_ns, &scratch));
    try testing.expectEqual(1, server.streams.lost.count);
    try testing.expectEqual(0, server.recovery.in_flight_len());
}

test "decision 59: a loss the timer finds that the connection cannot repair is a connection error" {
    open_server();
    server.crypto_at(.initial).send_base = 1;
    try record_sent(.initial, .crypto, 0, 0, sent_at_ns);
    try record_sent(.initial, .crypto, 0, 0, sent_at_ns);
    _ = try take_ack(.initial, 1, 1, 0, sent_at_ns + round_trip_ns);
    try testing.expectError(error.CryptoForgotten, fire_loss_timer());
}

test "RFC 9002 A.9, decision 59: a Probe Timeout owes probes in the space that set it" {
    open_server();
    server.path.on_datagram_received(constants.datagram_len_min);
    // RFC 9002 §6.2.1: no Application Data probe before the handshake is confirmed.
    try record_sent(.application, .none, 0, 0, sent_at_ns);
    try testing.expectEqual(null, recovery.loss_deadline_ns(&server));
    server.confirm_handshake();
    try testing.expect(try fire_loss_timer());
    // RFC 9002 §6.2.4: two probes, because a packet is in flight.
    try testing.expectEqual(constants.probe_packets, server.probes_owed[@intFromEnum(Level.application)]);
    try testing.expectEqual(1, server.recovery.timer.pto_count);
}

test "decision 66: an application PTO declares the oldest packets lost, one for each probe" {
    open_server();
    server.path.on_datagram_received(constants.datagram_len_min);
    server.confirm_handshake();
    const id = try framed_stream();
    // The stream's range went out first, then two packets of nothing a probe could carry.
    try record_sent(.application, .stream_fin, id.value, 0, sent_at_ns);
    for (0..constants.probe_packets) |_| try record_sent(.application, .none, 0, 0, sent_at_ns);
    try testing.expect(try fire_loss_timer());
    // The oldest two are lost, so the probes carry the stream's range; the newest stays.
    try testing.expectEqual(1, server.streams.lost.count);
    try testing.expectEqual(1, server.recovery.tables[@intFromEnum(Level.application)].count());
    try testing.expectEqual(constants.probe_packets, server.probes_owed[@intFromEnum(Level.application)]);
}

test "decision 64: a Handshake PTO declares its packets lost, and the window stays" {
    open_as(.client);
    try record_sent(.handshake, .none, 0, 0, sent_at_ns);
    const window = server.recovery.congestion.window;
    try testing.expect(try fire_loss_timer());
    // RFC 9002 §6.2.4: "the sender MAY mark any packets still in flight as lost", so the probes
    // carry what they held.
    try testing.expectEqual(0, server.recovery.tables[@intFromEnum(Level.handshake)].count());
    try testing.expectEqual(0, server.recovery.in_flight_len());
    try testing.expectEqual(constants.probe_packets, server.probes_owed[@intFromEnum(Level.handshake)]);
    // Declared lost to move their octets and not for congestion, so no rate reduction.
    try testing.expectEqual(window, server.recovery.congestion.window);
}

test "RFC 9002 A.8: a server at the anti-amplification limit sets no probe timer" {
    open_server();
    server.confirm_handshake();
    try record_sent(.application, .none, 0, 0, sent_at_ns);
    // RFC 9000 §8.1: a server that has received nothing may send nothing, and one that has
    // received a single octet may send three, which holds no packet.
    try testing.expectEqual(null, recovery.loss_deadline_ns(&server));
    server.path.on_datagram_received(1);
    try testing.expectEqual(null, recovery.loss_deadline_ns(&server));
    server.path.on_datagram_received(constants.datagram_len_min);
    try testing.expect(recovery.loss_deadline_ns(&server) != null);
}

test "RFC 9002 A.8: a client probes until the server has validated its address" {
    // "Assume clients validate the server's address implicitly": a server with nothing the peer
    // must acknowledge sets no timer, although a packet in flight has set it.
    open_server();
    server.path.on_datagram_received(constants.datagram_len_min);
    try send_padded_ack();
    try testing.expectEqual(null, recovery.loss_deadline_ns(&server));

    // A client with nothing in flight sends an anti-deadlock probe (Appendix A.9), in a Handshake
    // packet because it holds Handshake keys.
    open_as(.client);
    try send_padded_ack();
    try testing.expect(try fire_loss_timer());
    try testing.expectEqual(1, server.probes_owed[@intFromEnum(Level.handshake)]);
    // "has received Handshake ACK || handshake confirmed" ends it.
    server.recovery.largest_acknowledged[@intFromEnum(Level.handshake)] = 0;
    try testing.expectEqual(null, recovery.loss_deadline_ns(&server));
    open_as(.client);
    try send_padded_ack();
    server.confirm_handshake();
    try testing.expectEqual(null, recovery.loss_deadline_ns(&server));
}

test "RFC 9002 A.9: a client without Handshake keys probes with an Initial" {
    suite_holder.init();
    server.init(.{
        .role = .client,
        .local_parameters = parameters(),
        .now_ns = test_now_ns,
        .identity = .{ .local_initial_source = &local_id, .original_destination = &peer_id },
    });
    keys.on_keys_installed(&server, .initial, .write);
    try send_padded_ack();
    try testing.expect(try fire_loss_timer());
    try testing.expectEqual(1, server.probes_owed[@intFromEnum(Level.initial)]);
}

test "RFC 9002 §6.4: discarding keys discards the packets sent with them" {
    open_server();
    try record_sent(.handshake, .none, 0, 0, sent_at_ns);
    try testing.expectEqual(range_len, server.recovery.in_flight_len());
    // RFC 9001 §4.9.2: a server discards its Handshake keys when the handshake is confirmed.
    keys.on_handshake_confirmed(&server, suite_holder.suite());
    try testing.expectEqual(0, server.recovery.in_flight_len());
    try testing.expectEqual(0, server.recovery.table_of(.handshake).count());
}

test "RFC 9000 §18.2: the peer's max_ack_delay reaches the Probe Timeout" {
    open_as(.server);
    var peer = parameters();
    peer.max_ack_delay_ms = peer_max_ack_delay_ms;
    server.apply_peer_parameters(peer);
    const expected_ns = peer_max_ack_delay_ms * constants.nanoseconds_per_millisecond;
    try testing.expectEqual(expected_ns, server.recovery.rtt.peer_max_ack_delay_ns);
}

test "RFC 9000 §10.2.1: a connection that has stopped being active sets no loss timer" {
    open_server();
    server.path.on_datagram_received(constants.datagram_len_min);
    try record_sent(.initial, .none, 0, 0, sent_at_ns);
    try testing.expect(recovery.loss_deadline_ns(&server) != null);
    server.termination.on_close_sent(sent_at_ns, round_trip_ns);
    try testing.expectEqual(null, recovery.loss_deadline_ns(&server));
}

test "RFC 9002 A.7: a client's first Handshake ACK starts the backoff again" {
    open_as(.client);
    try record_sent(.handshake, .none, 0, 0, sent_at_ns);
    try testing.expect(try fire_loss_timer());
    try testing.expectEqual(1, server.recovery.timer.pto_count);
    // Decision 64 declared packet 0 lost, so the probe is what the peer acknowledges.
    try record_sent(.handshake, .none, 0, 0, sent_at_ns + round_trip_ns);
    // "Reset pto_count unless the client is unsure if the server has validated the client's
    // address", and the Handshake ACK is what makes it sure.
    _ = try take_ack(.handshake, 1, 1, 0, sent_at_ns + 2 * round_trip_ns);
    try testing.expectEqual(0, server.recovery.timer.pto_count);
}

test "RFC 9002 §5.3: once the handshake is confirmed the ACK Delay counts up to max_ack_delay" {
    open_server();
    server.peer_parameters.?.ack_delay_exponent = peer_exponent;
    try record_sent(.application, .none, 0, 0, sent_at_ns);
    _ = try take_ack(.application, 0, 0, 0, sent_at_ns + round_trip_ns);
    server.confirm_handshake();
    // The peer reports 50 ms, above its max_ack_delay of 25, so only 25 comes off the sample.
    const later_ns = sent_at_ns + slower_round_trip_ns;
    try record_sent(.application, .none, 0, 0, later_ns);
    _ = try take_ack(.application, 1, 1, delay_field, later_ns + slower_round_trip_ns);
    try testing.expect(server.recovery.rtt.smoothed_ns > round_trip_ns);
    try testing.expect(server.recovery.rtt.smoothed_ns < slower_round_trip_ns);
}
