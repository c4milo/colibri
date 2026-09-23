//! The tests of the frames that end one direction of a stream, in `connection_stream_send.zig`:
//! RESET_STREAM (RFC 9000 §19.4) and STOP_SENDING (§19.5), the answer §3.5 requires to a peer's
//! STOP_SENDING, and §13.3's rules for sending each again. The connections and the provider are
//! `connection_stream_send_test.zig`'s, and each frame is read back at the peer.
const std = @import("std");
const core = @import("core");
const constants = @import("../../constants.zig");
const frame_module = @import("../../frame/frame.zig");
const stream_module = @import("../../stream/stream.zig");
const recovery_sent = @import("../../recovery/recovery_sent.zig");
const connection_module = @import("../connection.zig");
const receive = @import("../connection_receive.zig");
const frames = @import("../connection_frames.zig");
const send = @import("../connection_send.zig");
const stream_send = @import("connection_stream_send.zig");
const stream_recovery = @import("connection_stream_recovery.zig");
const send_test = @import("connection_stream_send_test.zig");

const Writer = core.Writer;
const Connection = connection_module.Connection;
const Record = recovery_sent.Record;
const StreamId = stream_module.StreamId;
const Body = send_test.Body;
const Frame = frame_module.Frame;
const testing = std.testing;

const test_now_ns: u64 = 1_000_000;
/// The application's codes, distinct so a frame naming the wrong one shows. Test-only.
const reset_code: u64 = 7;
const stop_code: u64 = 9;
/// Frames one packet carries in these tests, and room for the streams a test completes.
const frames_max: usize = 16;
const completed_max: usize = 4;

/// Two endpoints past the handshake; the server may send, having received the client's first
/// datagram (RFC 9000 §8.1).
fn open_pair() void {
    send_test.open_pair(.{});
    send_test.server.path.on_datagram_received(constants.datagram_len_min);
}

fn send_as(connection: *Connection, body: *Body) !?send.Sent {
    return send.send(
        connection,
        send_test.suite_holder.suite(),
        send_test.provider_holder.provider(),
        body.provider(),
        &send_test.scratch,
        &send_test.datagram,
        test_now_ns,
    );
}

/// Opens the one packet of `sent` at `reader`, takes its frames, and returns them read back.
fn deliver(sent: send.Sent, reader: *Connection, out: *[frames_max]Frame) ![]Frame {
    var walk: receive.Walk = undefined;
    walk.init(.{ .octets = send_test.datagram[0..sent.len], .now_ns = test_now_ns, .ecn = .not_ect });
    const opened = (try receive.next(&walk, reader, send_test.suite_holder.suite())).?.opened;
    _ = try frames.process(reader, opened, test_now_ns);
    var payload = core.Reader.init(opened.payload);
    var count: usize = 0;
    // Bounded by `frames_max`, and each read shortens the payload.
    while (payload.remaining_len() > 0 and count < frames_max) : (count += 1) {
        out[count] = try frame_module.read(&payload);
    }
    return out[0..count];
}

fn find(held: []const Frame, kind: std.meta.Tag(Frame)) !Frame {
    for (held) |frame| {
        if (std.meta.activeTag(frame) == kind) return frame;
    }
    return error.TestExpectedFrame;
}

fn record_of(sent: send.Sent) Record {
    const packet = sent.packets[0];
    return .{
        .number = packet.packet_number,
        .sent_at_ns = test_now_ns,
        .sent_len = @intCast(sent.len),
        .ack_eliciting = packet.ack_eliciting,
        .in_flight = packet.in_flight,
        .carries = packet.carries,
        .data_offset = packet.data_offset,
        .data_len = packet.data_len,
        .stream_id = packet.stream_id,
    };
}

fn client_stream(id: StreamId) *stream_module.Stream {
    return send_test.client.streams.lookup(id).live;
}

fn server_stream(id: StreamId) *stream_module.Stream {
    return send_test.server.streams.lookup(id).live;
}

/// The client opens a stream and sends its first packet of octets, which the server takes.
fn one_packet_sent(body: *Body) !struct { id: StreamId, framed: u64 } {
    const id = try send_test.open_supplied(send_test.long_body_len, true);
    const first = (try send_as(&send_test.client, body)).?;
    var read: [frames_max]Frame = undefined;
    _ = try deliver(first, &send_test.server, &read);
    return .{ .id = id, .framed = first.packets[0].data_len };
}

test "RFC 9000 §19.4: a reset stream sends RESET_STREAM with what was framed as its final size" {
    open_pair();
    var body: Body = .{ .len = send_test.long_body_len };
    const sent = try one_packet_sent(&body);
    try stream_send.reset(&send_test.client, sent.id, reset_code);
    try testing.expectEqual(.reset_sent, client_stream(sent.id).sending.state);
    // "After sending a RESET_STREAM, an endpoint ceases transmission and retransmission of STREAM
    // frames": the next packet carries the reset and none of the remaining octets.
    const reset = (try send_as(&send_test.client, &body)).?;
    try testing.expectEqual(recovery_sent.Carries.none, reset.packets[0].carries);
    try testing.expect(reset.packets[0].ack_eliciting);
    var read: [frames_max]Frame = undefined;
    const held = (try find(try deliver(reset, &send_test.server, &read), .reset_stream)).reset_stream;
    try testing.expectEqual(sent.id.value, held.stream_id);
    try testing.expectEqual(reset_code, held.error_code);
    // RFC 9000 §4.5: the final size is every octet sent, which the peer's receiving part checks.
    try testing.expectEqual(sent.framed, held.final_size);
    try testing.expectEqual(.reset_recvd, server_stream(sent.id).receiving.state);
    try testing.expectEqual(null, try send_as(&send_test.client, &body));
    // §3.1: a part already reset is not reset again.
    try testing.expectError(error.NotWritable, stream_send.reset(&send_test.client, sent.id, reset_code));
}

test "RFC 9000 §13.3: a lost RESET_STREAM goes again unchanged until one is acknowledged" {
    open_pair();
    var body: Body = .{ .len = send_test.long_body_len };
    const id = try send_test.open_supplied(send_test.long_body_len, true);
    try stream_send.reset(&send_test.client, id, reset_code);
    const first = (try send_as(&send_test.client, &body)).?;
    // A loss in another space is another packet (RFC 9000 §12.3).
    try stream_recovery.on_packets_lost(&send_test.client, .handshake, &.{record_of(first)});
    try testing.expect(!client_stream(id).reset_stream.owed);
    // "The content of a RESET_STREAM frame MUST NOT change when it is sent again."
    try stream_recovery.on_packets_lost(&send_test.client, .application, &.{record_of(first)});
    try testing.expect(client_stream(id).reset_stream.owed);
    const again = (try send_as(&send_test.client, &body)).?;
    var read: [frames_max]Frame = undefined;
    const held = (try find(try deliver(again, &send_test.server, &read), .reset_stream)).reset_stream;
    try testing.expectEqual(reset_code, held.error_code);
    try testing.expectEqual(0, held.final_size);

    // Another space's packet with the same number is not the one that carried it (§12.3).
    var completed: [completed_max]StreamId = undefined;
    _ = stream_recovery.on_packets_acknowledged(&send_test.client, .handshake, &.{record_of(again)}, &completed);
    try testing.expectEqual(.reset_sent, client_stream(id).sending.state);
    // Nor is a packet that carried something else.
    var other = record_of(again);
    other.number += 1;
    _ = stream_recovery.on_packets_acknowledged(&send_test.client, .application, &.{other}, &completed);
    try testing.expectEqual(.reset_sent, client_stream(id).sending.state);
    // RFC 9000 §3.1: its acknowledgment enters "Reset Recvd", and nothing more is owed.
    _ = stream_recovery.on_packets_acknowledged(&send_test.client, .application, &.{record_of(again)}, &completed);
    try testing.expectEqual(.reset_recvd, client_stream(id).sending.state);
    try testing.expectEqual(0, send_test.client.streams.resets_unacknowledged);
    try testing.expectEqual(null, try send_as(&send_test.client, &body));
    // Loss recovery never reports an acknowledged packet lost, but if it did, nothing is owed.
    try stream_recovery.on_packets_lost(&send_test.client, .application, &.{record_of(again)});
    try testing.expectEqual(null, try send_as(&send_test.client, &body));
}

test "RFC 9000 §3.5: a peer's STOP_SENDING is answered with RESET_STREAM carrying its error code" {
    open_pair();
    var body: Body = .{ .len = send_test.long_body_len };
    const sent = try one_packet_sent(&body);
    try stream_send.stop_sending(&send_test.server, sent.id, stop_code);
    const stop = (try send_as(&send_test.server, &body)).?;
    try testing.expect(stop.packets[0].ack_eliciting);
    var read: [frames_max]Frame = undefined;
    const asked = (try find(try deliver(stop, &send_test.client, &read), .stop_sending)).stop_sending;
    try testing.expectEqual(stop_code, asked.error_code);
    // "An endpoint that receives a STOP_SENDING frame MUST send a RESET_STREAM frame", and it
    // "SHOULD copy the error code from the STOP_SENDING frame".
    try testing.expectEqual(.reset_sent, client_stream(sent.id).sending.state);
    const reset = (try send_as(&send_test.client, &body)).?;
    const held = (try find(try deliver(reset, &send_test.server, &read), .reset_stream)).reset_stream;
    try testing.expectEqual(stop_code, held.error_code);
    try testing.expectEqual(sent.framed, held.final_size);

    // With the reset in, STOP_SENDING is "unnecessary" (§3.5), even when its packet is lost.
    try stream_recovery.on_packets_lost(&send_test.server, .application, &.{record_of(stop)});
    try testing.expectEqual(null, try send_as(&send_test.server, &body));
    try testing.expect(!server_stream(sent.id).stop_sending.owed);
}

test "RFC 9000 §3.5: STOP_SENDING goes again when lost while the peer may still send" {
    open_pair();
    var body: Body = .{ .len = send_test.long_body_len };
    const sent = try one_packet_sent(&body);
    try stream_send.stop_sending(&send_test.server, sent.id, stop_code);
    // Asking twice changes nothing, the code included.
    try stream_send.stop_sending(&send_test.server, sent.id, reset_code);
    const first = (try send_as(&send_test.server, &body)).?;
    try stream_recovery.on_packets_lost(&send_test.server, .application, &.{record_of(first)});
    try testing.expect(server_stream(sent.id).stop_sending.owed);
    const again = (try send_as(&send_test.server, &body)).?;
    var read: [frames_max]Frame = undefined;
    const asked = (try find(try deliver(again, &send_test.client, &read), .stop_sending)).stop_sending;
    try testing.expectEqual(sent.id.value, asked.stream_id);
    try testing.expectEqual(stop_code, asked.error_code);
}

test "RFC 9000 §2.1, §19.5: each ending is refused on a stream it cannot end" {
    open_pair();
    const client = &send_test.client;
    // RESET_STREAM ends a sending part: not a stream only the peer sends on, nor one not opened.
    const peer_unidirectional = StreamId.of(.server, .unidirectional, 0);
    _ = try client.streams.open_peer(peer_unidirectional);
    try testing.expectError(error.NotWritable, stream_send.reset(client, peer_unidirectional, reset_code));
    try testing.expectError(error.NotWritable, stream_send.reset(client, StreamId.of(.client, .bidirectional, 3), reset_code));
    // STOP_SENDING ends a receiving part: not a stream only this endpoint sends on.
    const own_unidirectional = try stream_send.open(client, .unidirectional);
    try testing.expectError(error.NotReadable, stream_send.stop_sending(client, own_unidirectional, stop_code));
    try testing.expectError(error.NotReadable, stream_send.stop_sending(client, StreamId.of(.server, .bidirectional, 0), stop_code));
    // §19.5: nor a receiving part that left "Recv" and "Size Known".
    _ = client.streams.lookup(peer_unidirectional).live.receiving.on(.received_reset);
    try testing.expectError(error.NotReadable, stream_send.stop_sending(client, peer_unidirectional, stop_code));
    // Below 1-RTT neither is written (RFC 9000 §12.4, Table 3).
    const bidirectional = try stream_send.open(client, .bidirectional);
    try stream_send.reset(client, bidirectional, reset_code);
    var room: [constants.datagram_len_min]u8 = undefined;
    var writer = Writer.init(&room);
    try testing.expect(!stream_send.write_endings(client, .handshake, &writer, 0));
    try testing.expectEqual(0, writer.written().len);
}
