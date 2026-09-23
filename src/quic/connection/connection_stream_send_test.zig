//! The tests of `connection_stream_send.zig`: STREAM frames read from the caller's stream
//! provider (decision 57), one per packet (decision 56), and lost ranges sent again (RFC 9000
//! §13.3).
//!
//! Every packet is opened by the peer and its STREAM frame read back, so what is checked is the
//! octets that went out and where, not what the sender says about them.
const std = @import("std");
const core = @import("core");
const constants = @import("../constants.zig");
const transport_parameters = @import("../transport_parameters.zig");
const frame_module = @import("../frame/frame.zig");
const frame_stream = @import("../frame/frame_stream.zig");
const stream_module = @import("../stream/stream.zig");
const recovery_sent = @import("../recovery/recovery_sent.zig");
const connection_module = @import("connection.zig");
const keys = @import("connection_keys.zig");
const receive = @import("connection_receive.zig");
const frames = @import("connection_frames.zig");
const send = @import("connection_send.zig");
const stream_send = @import("connection_stream_send.zig");
const build_test = @import("packet_build/packet_build_test.zig");

const Level = core.Level;
const Reader = core.Reader;
const Connection = connection_module.Connection;
const Parameters = transport_parameters.Parameters;
const StreamId = stream_module.StreamId;
const StreamProvider = stream_module.StreamProvider;
const Range = stream_module.stream_lost.Range;
const Carries = recovery_sent.Carries;
const testing = std.testing;

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
/// Enough of everything that no limit but the one a test sets is reached.
const test_max_data: u64 = 1_048_576;
const test_max_streams: u64 = 8;
/// A body one packet holds, and one that takes three.
const short_body_len: u64 = 300;
const long_body_len: u64 = 3_000;
/// A limit below the short body, for the flow control tests.
const small_window: u64 = 100;
/// Octets a provider has ready, below 64, so a Length field that measured two octets for the
/// supplied range holds it in one (RFC 9000 §16).
const short_read_len: u64 = 50;
/// A datagram smaller than the one a range was first sent in, for §13.3's split.
const small_datagram_len: usize = 600;

/// Each octet is set by its offset, so a frame read at the wrong offset shows.
const octet_stride: u64 = 7;
const octet_seed: u64 = 0x2b;

fn octet_at(offset: u64) u8 {
    return @truncate(offset *% octet_stride +% octet_seed);
}

/// The caller's octets on every stream, `len` of them, read back by offset. Test-only.
const Body = struct {
    len: u64,

    fn provider(body: *Body) StreamProvider {
        return .{ .context = body, .vtable = &body_vtable };
    }
};

const body_vtable: stream_module.stream_provider.VTable = .{ .read = read_body };

fn read_body(context: *anyopaque, stream_id: u64, offset: u64, output: []u8) usize {
    _ = stream_id;
    const body: *Body = @ptrCast(@alignCast(context));
    if (offset >= body.len) return 0;
    const len: usize = @intCast(@min(output.len, body.len - offset));
    for (output[0..len], 0..) |*octet, index| octet.* = octet_at(offset + index);
    return len;
}

/// The windows the peer's parameters give. Test-only.
const Windows = struct {
    stream: u64 = test_max_data,
    connection: u64 = test_max_data,
};

fn parameters(windows: Windows) Parameters {
    var held = Parameters.initial();
    held.initial_max_data = windows.connection;
    held.initial_max_stream_data_bidi_local = windows.stream;
    held.initial_max_stream_data_bidi_remote = windows.stream;
    held.initial_max_stream_data_uni = windows.stream;
    held.initial_max_streams_bidi = test_max_streams;
    held.initial_max_streams_uni = test_max_streams;
    return held;
}

/// Two endpoints past the handshake, each holding the other's parameters. The client, which
/// sends in these tests, holds `windows`.
fn open_pair(windows: Windows) void {
    suite_holder.init();
    provider_holder = .{};
    open_one(&client, .client);
    open_one(&server, .server);
    client.apply_peer_parameters(parameters(windows));
    server.apply_peer_parameters(parameters(.{}));
}

fn open_one(connection: *Connection, role: connection_module.Role) void {
    connection.init(.{
        .role = role,
        .local_parameters = parameters(.{}),
        .now_ns = test_now_ns,
        .identity = .{ .local_initial_source = &local_id, .original_destination = &peer_id },
    });
    // Every level's keys, so a test shows which level a STREAM frame is allowed at.
    for ([_]Level{ .initial, .handshake, .application }) |level| {
        keys.on_keys_installed(connection, level, .read);
        keys.on_keys_installed(connection, level, .write);
    }
    connection.handshake_complete = true;
}

fn send_from(body: *Body, output_len: usize) !?send.Sent {
    return send.send(&client, suite_holder.suite(), provider_holder.provider(), body.provider(), &scratch, datagram[0..output_len], test_now_ns);
}

/// A body's stream, opened and supplied whole, ended when `fin` is set.
fn open_supplied(len: u64, fin: bool) !StreamId {
    const id = try stream_send.open(&client, .bidirectional);
    try stream_send.supply(&client, id, len, fin);
    return id;
}

fn stream_of(id: StreamId) *stream_module.Stream {
    return client.streams.lookup(id).live;
}

/// The range a packet's record keeps, as the loss path hands it to the stream table.
fn range_of(packet: send.Packet) Range {
    return .{
        .stream_id = packet.stream_id,
        .offset = packet.data_offset,
        .len = packet.data_len,
        .fin = packet.carries == .stream_fin,
    };
}

/// Opens the datagram as the server, which takes every frame, and returns the STREAM frame the
/// one packet carried after checking its octets against the body.
fn stream_frame_of(sent: send.Sent) !frame_stream.Stream {
    var walk: receive.Walk = undefined;
    walk.init(.{ .octets = datagram[0..sent.len], .now_ns = test_now_ns, .ecn = .not_ect });
    const opened = (try receive.next(&walk, &server, suite_holder.suite())).?.opened;
    _ = try frames.process(&server, opened, test_now_ns);
    var reader = Reader.init(opened.payload);
    // Bounded by the payload, which each frame read shortens.
    while (reader.remaining_len() > 0) {
        switch (try frame_module.read(&reader)) {
            .stream => |held| {
                for (held.data, 0..) |octet, index| try testing.expectEqual(octet_at(held.offset + index), octet);
                return held;
            },
            else => {},
        }
    }
    return error.TestExpectedStreamFrame;
}

test "§19.8: a stream's octets go out in a STREAM frame, read from the provider" {
    open_pair(.{});
    var body: Body = .{ .len = short_body_len };
    const id = try open_supplied(short_body_len, true);
    const sent = (try send_from(&body, datagram.len)).?;
    const packet = sent.packets[0];
    try testing.expectEqual(Level.application, packet.level);
    try testing.expectEqual(Carries.stream_fin, packet.carries);
    try testing.expectEqual(id.value, packet.stream_id);
    try testing.expectEqual(0, packet.data_offset);
    try testing.expectEqual(short_body_len, packet.data_len);
    try testing.expect(packet.ack_eliciting);
    const held = try stream_frame_of(sent);
    try testing.expectEqual(short_body_len, held.data.len);
    try testing.expect(held.fin);
    // RFC 9000 §3.1: the FIN went out, so the sending part is in "Data Sent" and owes nothing.
    try testing.expectEqual(.data_sent, stream_of(id).sending.state);
    try testing.expectEqual(null, try send_from(&body, datagram.len));
}

test "decision 56: one STREAM frame per packet, whatever the streams" {
    open_pair(.{});
    var body: Body = .{ .len = short_body_len };
    const first_id = try open_supplied(short_body_len, true);
    const second_id = try open_supplied(short_body_len, true);
    const first = (try send_from(&body, datagram.len)).?;
    try testing.expectEqual(first_id.value, (try stream_frame_of(first)).stream_id);
    const second = (try send_from(&body, datagram.len)).?;
    try testing.expectEqual(second_id.value, (try stream_frame_of(second)).stream_id);
}

test "§13.3: a lost range goes out again first, with the same octets at the same offset" {
    open_pair(.{});
    var body: Body = .{ .len = long_body_len };
    _ = try open_supplied(long_body_len, true);
    const first = (try send_from(&body, datagram.len)).?;
    const second = (try send_from(&body, datagram.len)).?;
    try testing.expectEqual(first.packets[0].data_len, second.packets[0].data_offset);
    try client.streams.on_range_lost(range_of(first.packets[0]));

    // "Endpoints SHOULD prioritize retransmission of data over sending new data."
    const again = (try send_from(&body, datagram.len)).?;
    try testing.expect(again.packets[0].packet_number > second.packets[0].packet_number);
    try testing.expectEqual(0, again.packets[0].data_offset);
    try testing.expectEqual(first.packets[0].data_len, again.packets[0].data_len);
    _ = try stream_frame_of(again);
    try testing.expectEqual(0, client.streams.lost.count);
    // Then the new octets, from where they stopped.
    const third = (try send_from(&body, datagram.len)).?;
    try testing.expectEqual(second.packets[0].data_offset + second.packets[0].data_len, third.packets[0].data_offset);
}

test "§13.3: a lost range that a smaller packet cannot hold goes out in pieces" {
    open_pair(.{});
    var body: Body = .{ .len = long_body_len };
    _ = try open_supplied(long_body_len, true);
    const first = (try send_from(&body, datagram.len)).?;
    try client.streams.on_range_lost(range_of(first.packets[0]));
    // §13.3 names a smaller path MTU among the reasons a payload shrinks.
    const piece = (try send_from(&body, small_datagram_len)).?;
    try testing.expectEqual(0, piece.packets[0].data_offset);
    try testing.expect(piece.packets[0].data_len < first.packets[0].data_len);
    const rest = (try send_from(&body, datagram.len)).?;
    try testing.expectEqual(piece.packets[0].data_len, rest.packets[0].data_offset);
    try testing.expectEqual(first.packets[0].data_len, piece.packets[0].data_len + rest.packets[0].data_len);
}

test "§4.5: the FIN goes out alone when the stream ends after its octets, and again if lost" {
    open_pair(.{});
    var body: Body = .{ .len = short_body_len };
    const id = try open_supplied(short_body_len, false);
    const octets = (try send_from(&body, datagram.len)).?;
    try testing.expectEqual(Carries.stream, octets.packets[0].carries);
    try testing.expectEqual(.send, stream_of(id).sending.state);
    try stream_send.supply(&client, id, short_body_len, true);

    const fin = (try send_from(&body, datagram.len)).?;
    try testing.expectEqual(Carries.stream_fin, fin.packets[0].carries);
    try testing.expectEqual(short_body_len, fin.packets[0].data_offset);
    try testing.expectEqual(0, fin.packets[0].data_len);
    try testing.expect((try stream_frame_of(fin)).fin);

    // "A sender always communicates the final size of a stream to the receiver reliably."
    try client.streams.on_range_lost(range_of(fin.packets[0]));
    const again = (try send_from(&body, datagram.len)).?;
    try testing.expectEqual(Carries.stream_fin, again.packets[0].carries);
    try testing.expectEqual(short_body_len, again.packets[0].data_offset);
}

test "§13.3: a lost range of a stream reset since is not sent again" {
    open_pair(.{});
    var body: Body = .{ .len = long_body_len };
    const id = try open_supplied(long_body_len, true);
    const first = (try send_from(&body, datagram.len)).?;
    try client.streams.on_range_lost(range_of(first.packets[0]));
    // "Once an endpoint sends a RESET_STREAM frame, no further STREAM frames are needed."
    _ = stream_of(id).sending.on(.sent_reset);
    try testing.expectEqual(null, try send_from(&body, datagram.len));
    try testing.expectEqual(0, client.streams.lost.count);
    // Nor are new octets on a stream reset before any went out.
    const unsent = try open_supplied(short_body_len, true);
    _ = stream_of(unsent).sending.on(.sent_reset);
    try testing.expectEqual(null, try send_from(&body, datagram.len));
}

test "§13.3: a lost range of a stream closed since is not sent again" {
    open_pair(.{});
    var body: Body = .{ .len = long_body_len };
    // A unidirectional stream has no receiving half, so the reset's acknowledgment closes it.
    const id = try stream_send.open(&client, .unidirectional);
    try stream_send.supply(&client, id, long_body_len, true);
    const first = (try send_from(&body, datagram.len)).?;
    try client.streams.on_range_lost(range_of(first.packets[0]));
    _ = stream_of(id).sending.on(.sent_reset);
    _ = stream_of(id).sending.on(.reset_acknowledged);
    client.streams.close(id);
    try testing.expectEqual(null, try send_from(&body, datagram.len));
    try testing.expectEqual(0, client.streams.lost.count);
}

test "§4.1: new octets stop at the peer's limit for the stream, and at the connection's" {
    open_pair(.{ .stream = small_window });
    var body: Body = .{ .len = short_body_len };
    const id = try open_supplied(short_body_len, true);
    const limited = (try send_from(&body, datagram.len)).?;
    try testing.expectEqual(small_window, limited.packets[0].data_len);
    // "Senders MUST NOT send data in excess of either limit": nothing more until it rises.
    try testing.expectEqual(null, try send_from(&body, datagram.len));
    _ = stream_of(id).send_flow.raise(short_body_len);
    const rest = (try send_from(&body, datagram.len)).?;
    try testing.expectEqual(Carries.stream_fin, rest.packets[0].carries);
    try testing.expectEqual(short_body_len - small_window, rest.packets[0].data_len);

    open_pair(.{ .connection = small_window });
    _ = try open_supplied(short_body_len, true);
    const connection_limited = (try send_from(&body, datagram.len)).?;
    try testing.expectEqual(small_window, connection_limited.packets[0].data_len);
    try testing.expectEqual(small_window, client.send_flow.used);
}

test "decision 57: a provider with fewer octets than supplied is framed for what it gave" {
    open_pair(.{});
    // The caller said its octets reach further than the provider can yet read.
    var body: Body = .{ .len = short_read_len };
    const id = try open_supplied(short_body_len, true);
    const partial = (try send_from(&body, datagram.len)).?;
    try testing.expectEqual(Carries.stream, partial.packets[0].carries);
    try testing.expectEqual(short_read_len, partial.packets[0].data_len);
    try testing.expectEqual(short_read_len, (try stream_frame_of(partial)).data.len);
    // With nothing more to read, nothing goes out, and the stream waits rather than ending early.
    try testing.expectEqual(null, try send_from(&body, datagram.len));
    try testing.expectEqual(.send, stream_of(id).sending.state);
    // Another stream's octets the provider can read go out meanwhile.
    const other = try open_supplied(short_read_len, true);
    const other_sent = (try send_from(&body, datagram.len)).?;
    try testing.expectEqual(other.value, other_sent.packets[0].stream_id);
    body.len = short_body_len;
    const rest = (try send_from(&body, datagram.len)).?;
    try testing.expectEqual(id.value, rest.packets[0].stream_id);
    try testing.expectEqual(Carries.stream_fin, rest.packets[0].carries);
}

test "decision 57: a packet that carries CRYPTO carries no STREAM frame" {
    open_pair(.{});
    var body: Body = .{ .len = short_body_len };
    _ = try open_supplied(short_body_len, true);
    // A handshake message after the handshake, such as a NewSessionTicket, goes in 1-RTT CRYPTO.
    provider_holder = .{ .owed = "ticket", .owed_level = .application };
    const crypto = (try send_from(&body, datagram.len)).?;
    try testing.expectEqual(Carries.crypto, crypto.packets[0].carries);
    const streamed = (try send_from(&body, datagram.len)).?;
    try testing.expectEqual(Carries.stream_fin, streamed.packets[0].carries);
}

test "§2.1, §3.1: octets are supplied only on a stream this endpoint may still send on" {
    open_pair(.{});
    // A unidirectional stream the server opened carries data to the client alone.
    const peer_unidirectional = StreamId.of(.server, .unidirectional, 0);
    _ = try client.streams.open_peer(peer_unidirectional);
    try testing.expectError(stream_send.Error.NotWritable, stream_send.supply(&client, peer_unidirectional, 1, false));
    // One this endpoint has not opened yet.
    const unopened = StreamId.of(.client, .bidirectional, 0);
    try testing.expectError(stream_send.Error.NotWritable, stream_send.supply(&client, unopened, 1, false));
    const id = try open_supplied(short_body_len, true);
    // Once ended, the final size is fixed (§4.5).
    try testing.expectError(stream_send.Error.NotWritable, stream_send.supply(&client, id, long_body_len, false));
    const other = try stream_send.open(&client, .bidirectional);
    try testing.expectError(stream_send.Error.OffsetTooLarge, stream_send.supply(&client, other, constants.stream_offset_max + 1, false));
    // A stream the caller reset takes no more (§3.1: "Reset Sent" originates nothing).
    _ = stream_of(other).sending.on(.sent_reset);
    try testing.expectError(stream_send.Error.NotWritable, stream_send.supply(&client, other, 1, false));
}

test "§19.8: a packet with no room for a STREAM frame's header leaves the octets owed" {
    open_pair(.{});
    var body: Body = .{ .len = short_body_len };
    const id = try open_supplied(short_body_len, true);
    // Two octets hold a STREAM frame's type and Stream ID, and nothing of its Length.
    var tiny: [2]u8 = undefined;
    const written = stream_send.write(&client, body.provider(), &tiny);
    try testing.expectEqual(0, written.len);
    try testing.expectEqual(short_body_len, stream_of(id).outgoing.unframed_len());
    try testing.expectEqual(.ready, stream_of(id).sending.state);
}
