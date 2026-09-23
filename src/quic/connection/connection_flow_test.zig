//! The tests of `connection_flow.zig`: credit the application's reading earns (RFC 9000 §4.1,
//! §4.2), stream counts given back (§4.6), and a lost limit frame sent again at its current value
//! (§13.3). The client sends stream data and the server gives credit, and each side reads the
//! other's packets, so a limit is checked where the peer takes it.
const std = @import("std");
const core = @import("core");
const constants = @import("../constants.zig");
const transport_parameters = @import("../transport_parameters.zig");
const recovery_sent = @import("../recovery/recovery_sent.zig");
const flow = @import("../flow.zig");
const frame_module = @import("../frame/frame.zig");
const stream_module = @import("../stream/stream.zig");
const connection_module = @import("connection.zig");
const keys = @import("connection_keys.zig");
const receive = @import("connection_receive.zig");
const frames = @import("connection_frames.zig");
const send = @import("connection_send.zig");
const flow_frames = @import("connection_flow.zig");
const stream_send = @import("connection_stream/connection_stream_send.zig");
const build_test = @import("packet_build/packet_build_test.zig");

const Level = core.Level;
const Writer = core.Writer;
const Connection = connection_module.Connection;
const Parameters = transport_parameters.Parameters;
const Record = recovery_sent.Record;
const StreamId = stream_module.StreamId;
const StreamProvider = stream_module.StreamProvider;
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
/// Every data limit, which one packet fills, and half of it, which is what earns a frame.
const window: u64 = 1_000;
const half_window: u64 = 500;
const max_streams: u64 = 2;
/// A body longer than the first window, so credit is what lets the rest go.
const body_len: u64 = 2_000;
const body_octet: u8 = 0x42;

/// The client's octets, the same at every offset. Test-only.
var body_context: u8 = 0;
const body_vtable: stream_module.stream_provider.VTable = .{ .read = read_body };

fn read_body(context: *anyopaque, stream_id: u64, offset: u64, output: []u8) usize {
    _ = context;
    _ = stream_id;
    _ = offset;
    @memset(output, body_octet);
    return output.len;
}

fn body() StreamProvider {
    return .{ .context = &body_context, .vtable = &body_vtable };
}

fn parameters() Parameters {
    var held = Parameters.initial();
    held.initial_max_data = window;
    held.initial_max_stream_data_bidi_local = window;
    held.initial_max_stream_data_bidi_remote = window;
    held.initial_max_stream_data_uni = window;
    held.initial_max_streams_bidi = max_streams;
    held.initial_max_streams_uni = max_streams;
    return held;
}

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
    keys.on_keys_installed(connection, .application, .read);
    keys.on_keys_installed(connection, .application, .write);
    connection.handshake_complete = true;
    // RFC 9000 §8.1: a server sends only after it has received.
    if (role == .server) connection.path.on_datagram_received(constants.datagram_len_min);
}

fn send_from(connection: *Connection) !?send.Sent {
    return send.send(connection, suite_holder.suite(), provider_holder.provider(), body(), &scratch, &datagram, test_now_ns);
}

/// Opens every packet of `sent` at `reader` and takes its frames.
fn deliver(sent: send.Sent, reader: *Connection) !void {
    var walk: receive.Walk = undefined;
    walk.init(.{ .octets = datagram[0..sent.len], .now_ns = test_now_ns, .ecn = .not_ect });
    // Bounded by what one datagram can hold (RFC 9000 §12.2).
    for (0..constants.coalesced_packets_max) |_| {
        const outcome = try receive.next(&walk, reader, suite_holder.suite()) orelse return;
        _ = try frames.process(reader, outcome.opened, test_now_ns, &recovery_scratch);
    }
}

/// Frames one packet can carry in these tests. Test-only.
const frames_max: usize = 16;

/// Opens the one packet of `sent` at the server, takes its frames, and returns them read back, so
/// a frame the server ignores can still be checked. Test-only.
fn frames_of(sent: send.Sent, out: *[frames_max]frame_module.Frame) ![]frame_module.Frame {
    var walk: receive.Walk = undefined;
    walk.init(.{ .octets = datagram[0..sent.len], .now_ns = test_now_ns, .ecn = .not_ect });
    const opened = (try receive.next(&walk, &server, suite_holder.suite())).?.opened;
    _ = try frames.process(&server, opened, test_now_ns, &recovery_scratch);
    var reader = core.Reader.init(opened.payload);
    var count: usize = 0;
    // Bounded by `frames_max`, and each read shortens the payload.
    while (reader.remaining_len() > 0 and count < frames_max) : (count += 1) {
        out[count] = try frame_module.read(&reader);
    }
    return out[0..count];
}

/// The first frame of `kind` among `held`. Test-only.
fn find(held: []const frame_module.Frame, kind: std.meta.Tag(frame_module.Frame)) !frame_module.Frame {
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
    };
}

/// The client opens a stream whose octets reach `end`, sends a window's worth and is blocked; the
/// server takes it.
fn fill_window(end: u64, fin: bool) !StreamId {
    const id = try stream_send.open(&client, .bidirectional);
    try stream_send.supply(&client, id, end, fin);
    try deliver((try send_from(&client)).?, &server);
    try testing.expect(client.send_flow.is_blocked());
    return id;
}

fn server_stream(id: StreamId) *stream_module.Stream {
    return server.streams.lookup(id).live;
}

fn client_stream(id: StreamId) *stream_module.Stream {
    return client.streams.lookup(id).live;
}

test "RFC 9000 §4.1: reading half the window sends MAX_DATA and MAX_STREAM_DATA, and the peer sends more" {
    open_pair();
    const id = try fill_window(body_len, false);
    // Nothing read, so nothing to offer: §4.1 measures credit from what was consumed.
    try testing.expect(!server.max_data.sent);
    try flow_frames.consume(&server, id, half_window);
    const credit = (try send_from(&server)).?;
    try testing.expect(credit.packets[0].ack_eliciting);
    try testing.expectEqual(credit.packets[0].packet_number, server.max_data.sent_in);
    try deliver(credit, &client);
    // §19.9 and §19.10: the limits are the offset consumed plus the window.
    try testing.expectEqual(window + half_window, client.send_flow.limit);
    try testing.expectEqual(window + half_window, client_stream(id).send_flow.limit);
    // The client sends what the credit allows.
    const more = (try send_from(&client)).?;
    try testing.expectEqual(window, more.packets[0].data_offset);
    try testing.expectEqual(half_window, more.packets[0].data_len);
}

test "RFC 9000 §13.3: a lost limit frame is sent again at the current value, for the most recent only" {
    open_pair();
    const id = try fill_window(body_len, false);
    try flow_frames.consume(&server, id, half_window);
    const first = (try send_from(&server)).?;
    try flow_frames.consume(&server, id, half_window);
    const second = (try send_from(&server)).?;
    try testing.expectEqual(second.packets[0].packet_number, server.max_data.sent_in);

    // The first packet no longer carries the most recent frame, so its loss owes nothing.
    flow_frames.on_packets_lost(&server, .application, &.{record_of(first)});
    try testing.expect(!server.max_data.owed);
    try testing.expectEqual(null, try send_from(&server));
    // Nor does a record of another space with the same number (RFC 9000 §12.3).
    flow_frames.on_packets_lost(&server, .handshake, &.{record_of(second)});
    try testing.expect(!server.max_data.owed);

    // "An updated value is sent in a MAX_DATA frame if the packet containing the most recently
    // sent MAX_DATA frame is declared lost", and the same for MAX_STREAM_DATA.
    flow_frames.on_packets_lost(&server, .application, &.{record_of(second)});
    try testing.expect(server.max_data.owed);
    try testing.expect(server_stream(id).max_stream_data.owed);
    const again = (try send_from(&server)).?;
    try testing.expect(!server.max_data.owed);
    try deliver(again, &client);
    try testing.expectEqual(window + window, client.send_flow.limit);
    try testing.expectEqual(window + window, client_stream(id).send_flow.limit);
}

test "RFC 9000 §4.6, §19.11: a stream the peer opened gives its count back when it closes" {
    open_pair();
    const id = StreamId.of(.client, .bidirectional, 0);
    const stream = try server.streams.open_peer(id);
    // Both halves end, and the stream closes.
    _ = stream.receiving.on(.received_reset);
    _ = stream.receiving.on(.application_read_reset);
    _ = stream.sending.on(.sent_reset);
    _ = stream.sending.on(.reset_acknowledged);
    server.streams.close(id);
    const credit = (try send_from(&server)).?;
    try testing.expectEqual(credit.packets[0].packet_number, server.streams.max_streams[0].sent_in);
    try deliver(credit, &client);
    try testing.expectEqual(max_streams + 1, client.streams.local_limit[0].limit);
    // Given once: nothing more is owed.
    try testing.expectEqual(null, try send_from(&server));
    // A lost MAX_STREAMS is owed again, and the next packet carries it.
    flow_frames.on_packets_lost(&server, .application, &.{record_of(credit)});
    try testing.expect(server.streams.max_streams[0].owed);
    const again = (try send_from(&server)).?;
    try testing.expectEqual(again.packets[0].packet_number, server.streams.max_streams[0].sent_in);
    try testing.expect(!server.streams.max_streams[0].owed);
}

/// A cap above the window, so decision 49's growth has room. Test-only: the connection's own
/// cap is its initial window until one is named.
const grown_window_max: u64 = 4_000;
const test_round_trip_ns: u64 = 100_000_000;

test "decision 49: credit is measured against the round trip, so a window drained inside it grows" {
    open_pair();
    server.receive_flow = flow.Receiver.init(window, grown_window_max);
    server.recovery.rtt.update(.{
        .rtt_ns = test_round_trip_ns,
        .ack_delay_ns = 0,
        .handshake_confirmed = true,
        .taken_at_ns = test_now_ns,
    });
    const id = try fill_window(body_len, false);
    try flow_frames.consume(&server, id, half_window);
    try deliver((try send_from(&server)).?, &client);
    try testing.expectEqual(window + half_window, client.send_flow.limit);
    // The second half is read at the same instant, well inside a round trip of the first credit,
    // so the window doubles before the limit is computed.
    try flow_frames.consume(&server, id, half_window);
    try deliver((try send_from(&server)).?, &client);
    try testing.expectEqual(window + window + window, client.send_flow.limit);
}

test "RFC 9000 §13.3: MAX_STREAM_DATA stops once the stream's final size is known" {
    open_pair();
    // The FIN arrives with the window, so the server's receiving part is in "Size Known".
    const id = try fill_window(window, true);
    try testing.expectEqual(.size_known, server_stream(id).receiving.state);
    try flow_frames.consume(&server, id, half_window);
    try deliver((try send_from(&server)).?, &client);
    // The connection's limit still rises; the stream's does not.
    try testing.expectEqual(window + half_window, client.send_flow.limit);
    try testing.expectEqual(window, client_stream(id).send_flow.limit);
    try testing.expect(!server_stream(id).max_stream_data.sent);
}

test "RFC 9000 §13.3: a limit frame with no room stays owed for the next packet" {
    open_pair();
    const id = try fill_window(body_len, false);
    try flow_frames.consume(&server, id, half_window);
    var tiny: [1]u8 = undefined;
    var writer = Writer.init(&tiny);
    try testing.expect(!flow_frames.write_limits(&server, .application, &writer, 0, test_now_ns));
    try testing.expect(server.max_data.owed);
    try testing.expect(server_stream(id).max_stream_data.owed);
    // Below 1-RTT nothing is written at all (RFC 9000 §12.4, Table 3).
    var room: [constants.datagram_len_min]u8 = undefined;
    var handshake_writer = Writer.init(&room);
    try testing.expect(!flow_frames.write_limits(&server, .handshake, &handshake_writer, 0, test_now_ns));
    try testing.expectEqual(0, handshake_writer.written().len);
    try deliver((try send_from(&server)).?, &client);
    try testing.expectEqual(window + half_window, client.send_flow.limit);
}

test "RFC 9000 §2.1: only a stream this endpoint receives on can be consumed" {
    open_pair();
    // A unidirectional stream the client opened carries data to the server alone.
    const outgoing = try stream_send.open(&client, .unidirectional);
    try testing.expectError(error.NotReadable, flow_frames.consume(&client, outgoing, 1));
    const unopened = StreamId.of(.server, .bidirectional, 0);
    try testing.expectError(error.NotReadable, flow_frames.consume(&client, unopened, 1));
}

test "RFC 9000 §4.1, §19.12, §19.13: a sender with octets held back by both limits says so once per limit" {
    open_pair();
    const id = try fill_window(body_len, false);
    // Below 1-RTT nothing is written (RFC 9000 §12.4, Table 3).
    var room: [constants.datagram_len_min]u8 = undefined;
    var handshake_writer = Writer.init(&room);
    try testing.expect(!flow_frames.write_blocked(&client, .handshake, &handshake_writer, 0));
    try testing.expectEqual(0, handshake_writer.written().len);
    const blocked = (try send_from(&client)).?;
    try testing.expect(blocked.packets[0].ack_eliciting);
    try testing.expectEqual(blocked.packets[0].packet_number, client.data_blocked.sent_in);
    try testing.expectEqual(blocked.packets[0].packet_number, client_stream(id).stream_data_blocked.sent_in);
    // The server takes both frames, which oblige it to nothing, and each names the limit that
    // blocks (§19.12, §19.13).
    var read: [frames_max]frame_module.Frame = undefined;
    const held = try frames_of(blocked, &read);
    try testing.expectEqual(window, (try find(held, .data_blocked)).data_blocked.limit);
    const stream_blocked = (try find(held, .stream_data_blocked)).stream_data_blocked;
    try testing.expectEqual(id.value, stream_blocked.stream_id);
    try testing.expectEqual(window, stream_blocked.limit);
    // Once for each limit: nothing more goes out while the limits stay where they are.
    try testing.expectEqual(null, try send_from(&client));
}

test "RFC 9000 §4.1: a sender blocked with nothing more to send says nothing" {
    open_pair();
    // The whole body and its FIN went out in the window, so the limit holds nothing back.
    _ = try fill_window(window, true);
    try testing.expectEqual(null, try send_from(&client));
    try testing.expect(!client.data_blocked.sent);
    // Nor with every supplied octet out and the stream not yet ended.
    open_pair();
    const open_id = try fill_window(window, false);
    try testing.expectEqual(.send, client_stream(open_id).sending.state);
    try testing.expectEqual(null, try send_from(&client));
    // Nor for a stream reset with octets unsent: §3.1 sends none from "Reset Sent".
    open_pair();
    const reset_id = try fill_window(body_len, false);
    _ = client_stream(reset_id).sending.on(.sent_reset);
    try testing.expectEqual(null, try send_from(&client));
    try testing.expect(!client.data_blocked.sent);
    try testing.expect(!client_stream(reset_id).stream_data_blocked.sent);
}

test "RFC 9000 §13.3: a lost BLOCKED frame is sent again only while still blocked" {
    open_pair();
    const id = try fill_window(body_len, false);
    const first = (try send_from(&client)).?;
    flow_frames.on_packets_lost(&client, .application, &.{record_of(first)});
    try testing.expect(client.data_blocked.owed);
    try testing.expect(client_stream(id).stream_data_blocked.owed);
    // Still blocked, so the next packet carries both again, naming the same limits.
    const again = (try send_from(&client)).?;
    try testing.expectEqual(again.packets[0].packet_number, client.data_blocked.sent_in);
    try testing.expectEqual(again.packets[0].packet_number, client_stream(id).stream_data_blocked.sent_in);

    // Lost again, but credit arrives first: "only while the endpoint is blocked on the
    // corresponding limit", so octets go out and no BLOCKED frame with them.
    flow_frames.on_packets_lost(&client, .application, &.{record_of(again)});
    try flow_frames.consume(&server, id, half_window);
    try deliver((try send_from(&server)).?, &client);
    const unblocked = (try send_from(&client)).?;
    try testing.expectEqual(recovery_sent.Carries.stream, unblocked.packets[0].carries);
    try testing.expect(!client.data_blocked.owed);
    try testing.expect(!client_stream(id).stream_data_blocked.owed);
}

test "RFC 9000 §4.6, §19.14: a stream the peer's limit refused is what STREAMS_BLOCKED reports" {
    open_pair();
    for (0..max_streams) |_| _ = try stream_send.open(&client, .bidirectional);
    // At the limit and nothing refused yet: §4.6 asks for the frame from an endpoint "unable to
    // open a new stream", which this one has not tried to do.
    try testing.expectEqual(null, try send_from(&client));
    try testing.expectError(error.StreamLimitReached, stream_send.open(&client, .bidirectional));
    const blocked = (try send_from(&client)).?;
    try testing.expectEqual(blocked.packets[0].packet_number, client.streams.streams_blocked[0].sent_in);
    try testing.expect(!client.streams.streams_blocked[1].sent);
    var read: [frames_max]frame_module.Frame = undefined;
    const reported = (try find(try frames_of(blocked, &read), .streams_blocked)).streams_blocked;
    try testing.expectEqual(frame_module.Directionality.bidirectional, reported.directionality);
    try testing.expectEqual(max_streams, reported.limit);
    try testing.expectEqual(null, try send_from(&client));
    // Lost, and still refused, so it goes again.
    flow_frames.on_packets_lost(&client, .application, &.{record_of(blocked)});
    const again = (try send_from(&client)).?;
    try testing.expectEqual(again.packets[0].packet_number, client.streams.streams_blocked[0].sent_in);

    // Lost again, but the peer raises the limit first, so nothing is owed any more.
    flow_frames.on_packets_lost(&client, .application, &.{record_of(again)});
    try testing.expect(client.streams.raise_local_limit(.bidirectional, max_streams + 1));
    try testing.expectEqual(null, try send_from(&client));
    try testing.expect(!client.streams.streams_blocked[0].owed);
    // A stream opened since clears the refusal, so reaching the new limit says nothing.
    _ = try stream_send.open(&client, .bidirectional);
    try testing.expectEqual(null, try send_from(&client));
}
