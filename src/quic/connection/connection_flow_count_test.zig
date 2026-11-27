//! The tests of decision 130 as amended on 2026-11-19: a MAX_STREAMS frame owed as each stream the
//! peer opened closes goes out at once only while the peer holds half its stream count or less.
//! Above that, it waits for a packet that goes out for another reason, so it costs no packet of
//! its own and no acknowledgment of one (https://github.com/c4milo/colibri/issues/139). RFC 9000
//! §4.6 leaves the timing to the receiver.
const std = @import("std");
const constants = @import("../constants.zig");
const transport_parameters = @import("../transport_parameters.zig");
const frame_module = @import("../frame/frame.zig");
const stream_module = @import("../stream/stream.zig");
const connection_module = @import("connection.zig");
const keys = @import("connection_keys.zig");
const receive = @import("connection_receive.zig");
const send = @import("connection_send.zig");
const stream_send = @import("connection_stream/connection_stream_send.zig");
const stream_frames = @import("connection_stream/connection_stream_frames.zig");
const build_test = @import("packet_build/packet_build_test.zig");
const flow_frames = @import("connection_flow.zig");
const core = @import("core");

const Connection = connection_module.Connection;
const Parameters = transport_parameters.Parameters;
const StreamId = stream_module.StreamId;
const StreamProvider = stream_module.StreamProvider;
const testing = std.testing;

var client: Connection align(@alignOf(Connection)) = undefined;
var server: Connection align(@alignOf(Connection)) = undefined;
var scratch: send.Scratch(.{}) align(@alignOf(send.Scratch(.{}))) = .{};
var datagram: [constants.protocol.datagram_len_min]u8 = undefined;
var suite_holder: build_test.RoundTrip align(@alignOf(build_test.RoundTrip)) = undefined;
var provider_holder: build_test.Fake align(@alignOf(build_test.Fake)) = undefined;

const test_now_ns: u64 = 1_000_000;
const id_len: usize = 4;
const local_octet: u8 = 0xc1;
const peer_octet: u8 = 0x51;
const local_id: [id_len]u8 = @splat(local_octet);
const peer_id: [id_len]u8 = @splat(peer_octet);
/// The byte of every response. Test-only.
const body_octet: u8 = 0x42;
/// The bidirectional streams each side lets its peer open, of which half is 4. Test-only.
const max_streams: u64 = 8;
/// The bytes of the server's one response. Test-only.
const response_len: u64 = 8;

/// The server's bytes, the same at every offset. Test-only.
var body_context: u8 = 0;
const body_vtable: StreamProvider.VTable = .{ .read = read_body };

fn read_body(context: *anyopaque, stream_id: u64, offset: u64, output: []u8) usize {
    _ = context;
    _ = stream_id;
    _ = offset;
    @memset(output, body_octet);
    return output.len;
}

fn parameters() Parameters {
    var held = Parameters.initial();
    held.initial_max_data = constants.protocol.datagram_len_min;
    held.initial_max_stream_data_bidi_local = constants.protocol.datagram_len_min;
    held.initial_max_stream_data_bidi_remote = constants.protocol.datagram_len_min;
    held.initial_max_streams_bidi = max_streams;
    return held;
}

fn open_pair() void {
    suite_holder.init();
    provider_holder = .{};
    for ([_]*Connection{ &client, &server }, [_]connection_module.Role{ .client, .server }) |connection, role| {
        connection.init(.{
            .role = role,
            .local_parameters = parameters(),
            .now_ns = test_now_ns,
            .identity = .{ .local_initial_source = &local_id, .original_destination = &peer_id },
        });
        keys.on_keys_installed(connection, .application, .read);
        keys.on_keys_installed(connection, .application, .write);
        connection.handshake_complete = true;
        connection_module.apply_peer_parameters(connection, parameters());
    }
    // RFC 9000 §8.1: a server sends only after it has received.
    server.path.on_datagram_received(constants.protocol.datagram_len_min);
}

fn send_from_server() !?send.Sent {
    const provider: StreamProvider = .{ .context = &body_context, .vtable = &body_vtable };
    return send.send(&server, suite_holder.suite(), provider_holder.provider(), provider, .{}, &scratch, &datagram, test_now_ns);
}

/// The server opens the client's first `count` bidirectional streams, each with the limits RFC
/// 9000 §18.2 gives it, then closes the first, whose both halves end, so its count is owed back
/// (§4.6).
fn open_and_close_first(count: u64) !void {
    for (0..count) |index| {
        const id = StreamId.init(.client, .bidirectional, index);
        stream_frames.initialise_flow(&server, try server.streams.open_peer(id), id);
    }
    const first = StreamId.init(.client, .bidirectional, 0);
    const stream = server.streams.lookup(first).live;
    _ = stream.receiving.on(.received_reset);
    _ = stream.receiving.on(.application_read_reset);
    _ = stream.sending.on(.sent_reset);
    _ = stream.sending.on(.reset_acknowledged);
    server.streams.close(first);
    try testing.expect(server.streams.peer_limit[0].count_credit_due());
}

/// Frames one packet holds in these tests. Test-only.
const frames_max: usize = 8;

/// The kinds of the frames in the one packet of `sent`, which the client opens and reads without
/// taking them. Test-only.
fn kinds_of(sent: send.Sent, out: *[frames_max]frame_module.Frame) ![]frame_module.Frame {
    var walk: receive.Walk = undefined;
    walk.init(.{ .octets = datagram[0..sent.len], .now_ns = test_now_ns, .ecn = .not_ect });
    const opened = (try receive.next(&walk, &client, suite_holder.suite())).?.opened;
    var reader = core.Reader.init(opened.payload);
    var count: usize = 0;
    // Bounded by `frames_max`, and each read shortens the payload.
    while (reader.remaining_len() > 0 and count < frames_max) : (count += 1) {
        out[count] = try frame_module.read(&reader);
    }
    return out[0..count];
}

fn holds(held: []const frame_module.Frame, kind: std.meta.Tag(frame_module.Frame)) bool {
    for (held) |frame| {
        if (std.meta.activeTag(frame) == kind) return true;
    }
    return false;
}

test "decision 130 as amended: a stream count owed above half waits, and rides with a response" {
    open_pair();
    // The client opened 2 of 8 streams, so it holds 6 unused after one closes.
    try open_and_close_first(2);
    try testing.expect(!server.streams.peer_limit[0].count_credit_low());
    try testing.expect(!server.count_credit_owed());
    // No packet goes for the frame alone.
    try testing.expectEqual(null, try send_from_server());
    // The response on the second stream carries it.
    try stream_send.supply(&server, StreamId.init(.client, .bidirectional, 1), response_len, true);
    const sent = (try send_from_server()).?;
    var held: [frames_max]frame_module.Frame = undefined;
    const frames = try kinds_of(sent, &held);
    try testing.expect(holds(frames, .stream));
    try testing.expect(holds(frames, .max_streams));
    try testing.expectEqual(sent.packets[0].packet_number, server.streams.max_streams[0].sent_in);
    try testing.expectEqual(max_streams + 1, server.streams.peer_limit[0].limit);
}

test "RFC 9000 §13.3: a lost MAX_STREAMS goes out again at once, above half too" {
    open_pair();
    try open_and_close_first(2);
    try stream_send.supply(&server, StreamId.init(.client, .bidirectional, 1), response_len, true);
    const sent = (try send_from_server()).?;
    // The peer never learned the new limit, so this endpoint's own count says nothing of its need.
    const packet = sent.packets[0];
    flow_frames.on_packets_lost(&server, .application, &.{.{
        .number = packet.packet_number,
        .sent_at_ns = test_now_ns,
        .sent_len = @intCast(sent.len),
        .ack_eliciting = packet.ack_eliciting,
        .in_flight = packet.in_flight,
    }});
    try testing.expect(!server.streams.peer_limit[0].count_credit_low());
    try testing.expect(server.count_credit_owed());
    const again = (try send_from_server()).?;
    var held: [frames_max]frame_module.Frame = undefined;
    try testing.expect(holds(try kinds_of(again, &held), .max_streams));
    try testing.expectEqual(again.packets[0].packet_number, server.streams.max_streams[0].sent_in);
}

test "decision 130 as amended: a stream count owed at half or below goes out at once, alone" {
    open_pair();
    // The client opened 5 of 8 streams, so it holds 3 unused, below half, after one closes.
    try open_and_close_first(5);
    try testing.expect(server.streams.peer_limit[0].count_credit_low());
    try testing.expect(server.count_credit_owed());
    const sent = (try send_from_server()).?;
    var held: [frames_max]frame_module.Frame = undefined;
    const frames = try kinds_of(sent, &held);
    try testing.expect(holds(frames, .max_streams));
    try testing.expect(!holds(frames, .stream));
    try testing.expectEqual(sent.packets[0].packet_number, server.streams.max_streams[0].sent_in);
    try testing.expectEqual(max_streams + 1, server.streams.peer_limit[0].limit);
}
