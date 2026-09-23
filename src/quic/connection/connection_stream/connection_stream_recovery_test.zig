//! The tests of `connection_stream_recovery.zig`: records that loss recovery wrote out, turned into
//! acknowledged stream octets (RFC 9000 §3.1) and lost ones sent again (§13.3). The connections,
//! the provider and the send path are `connection_stream_send_test.zig`'s.
const std = @import("std");
const constants = @import("../../constants.zig");
const stream_module = @import("../../stream/stream.zig");
const recovery_sent = @import("../../recovery/recovery_sent.zig");
const send = @import("../connection_send.zig");
const stream_send = @import("connection_stream_send.zig");
const stream_recovery = @import("connection_stream_recovery.zig");
const send_test = @import("connection_stream_send_test.zig");

const Record = recovery_sent.Record;
const StreamId = stream_module.StreamId;
const Body = send_test.Body;
const testing = std.testing;

const test_sent_at_ns: u64 = 1_000_000;
/// Room for every stream a test completes at once.
const completed_max: usize = 4;

/// The record the caller keeps for a packet `send` reported (RFC 9002 Appendix A.1.1).
fn record_of(packet: send.Packet) Record {
    return .{
        .number = packet.packet_number,
        .sent_at_ns = test_sent_at_ns,
        .sent_len = @intCast(packet.len),
        .ack_eliciting = packet.ack_eliciting,
        .in_flight = packet.in_flight,
        .carries = packet.carries,
        .data_offset = packet.data_offset,
        .data_len = packet.data_len,
        .stream_id = packet.stream_id,
    };
}

/// Sends one packet and returns its record.
fn sent_record(body: *Body) !Record {
    const sent = (try send_test.send_from(body, send_test.datagram.len)).?;
    return record_of(sent.packets[0]);
}

test "§3.1: the acknowledgment that covers a stream's last range moves it to Data Recvd" {
    send_test.open_pair(.{});
    var body: Body = .{ .len = send_test.long_body_len };
    const id = try send_test.open_supplied(send_test.long_body_len, true);
    var records: [3]Record = undefined;
    for (&records) |*record| record.* = try sent_record(&body);
    try testing.expectEqual(recovery_sent.Carries.stream_fin, records[2].carries);

    var completed: [completed_max]StreamId = undefined;
    // The last range and the first arrive before the middle one, which leaves the stream short.
    const early = stream_recovery.on_packets_acknowledged(&send_test.client, .application, &.{ records[2], records[0] }, &completed);
    try testing.expectEqual(0, early.written);
    try testing.expectEqual(.data_sent, send_test.stream_of(id).sending.state);
    const last = stream_recovery.on_packets_acknowledged(&send_test.client, .application, records[1..2], &completed);
    try testing.expectEqual(1, last.written);
    try testing.expectEqual(id.value, completed[0].value);
    try testing.expectEqual(.data_recvd, send_test.stream_of(id).sending.state);
}

test "§13.3: records that carried no stream octets count toward no stream" {
    send_test.open_pair(.{});
    var body: Body = .{ .len = send_test.long_body_len };
    const id = try send_test.open_supplied(send_test.long_body_len, true);
    const streamed = try sent_record(&body);
    // A CRYPTO record's range sits at the same offsets in another flow, and stream 0 is open.
    var crypto = streamed;
    crypto.carries = .crypto;
    crypto.stream_id = 0;
    var quiet = streamed;
    quiet.carries = .none;
    var completed: [completed_max]StreamId = undefined;
    _ = stream_recovery.on_packets_acknowledged(&send_test.client, .application, &.{ crypto, quiet }, &completed);
    try testing.expectEqual(0, send_test.stream_of(id).outgoing.acknowledged_len);
    try stream_recovery.on_packets_lost(&send_test.client, .application, &.{ crypto, quiet });
    try testing.expectEqual(0, send_test.client.streams.lost.count);
}

test "§3.1: a slice too short for the completed streams is told how many did not fit" {
    send_test.open_pair(.{});
    var body: Body = .{ .len = send_test.short_body_len };
    const first_id = try send_test.open_supplied(send_test.short_body_len, true);
    _ = try send_test.open_supplied(send_test.short_body_len, true);
    const records = [_]Record{ try sent_record(&body), try sent_record(&body) };
    var completed: [1]StreamId = undefined;
    const held = stream_recovery.on_packets_acknowledged(&send_test.client, .application, &records, &completed);
    try testing.expectEqual(1, held.written);
    try testing.expectEqual(1, held.unwritten);
    try testing.expectEqual(first_id.value, completed[0].value);
}

test "§13.3: lost records' ranges are kept, joined where they meet, and sent again" {
    send_test.open_pair(.{});
    var body: Body = .{ .len = send_test.long_body_len };
    _ = try send_test.open_supplied(send_test.long_body_len, true);
    const first = try sent_record(&body);
    const second = try sent_record(&body);
    try stream_recovery.on_packets_lost(&send_test.client, .application, &.{ first, second });
    // The two ranges meet, so the table holds one.
    try testing.expectEqual(1, send_test.client.streams.lost.count);
    const again = try sent_record(&body);
    try testing.expectEqual(0, again.data_offset);
    try testing.expectEqual(first.data_len, again.data_len);
    const rest = try sent_record(&body);
    try testing.expectEqual(second.data_offset, rest.data_offset);
    try testing.expectEqual(second.data_len, rest.data_len);
}

test "§20.1: a lost range the full table cannot hold closes the connection with INTERNAL_ERROR" {
    send_test.open_pair(.{});
    var body: Body = .{ .len = send_test.long_body_len };
    const id = try send_test.open_supplied(send_test.long_body_len, true);
    const lost = try sent_record(&body);
    // Another stream's ranges, a gap apart, fill the table.
    const gap: u64 = 2;
    for (0..constants.stream_lost_ranges_max) |index| {
        try send_test.client.streams.lost.add(.{ .stream_id = id.value + 4, .offset = gap * index, .len = 1, .fin = false });
    }
    try testing.expectError(error.Full, stream_recovery.on_packets_lost(&send_test.client, .application, &.{lost}));
    try testing.expectEqual(0x01, stream_recovery.connection_error_code(error.Full));
}
