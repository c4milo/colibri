//! The tests of `connection_stream_read.zig` and `connection_stream_close.zig`: a server with a
//! receive pool reads what a client sent on a stream (decision 61), in order, and each read gives
//! the client credit (RFC 9000 §4.1); a stream closes once both its parts finish (§3). Every
//! datagram goes through the sender's send path and the receiver's `connection_datagram`.
const std = @import("std");
const core = @import("core");
const constants = @import("../../constants.zig");
const transport_parameters = @import("../../transport_parameters.zig");
const stream_module = @import("../../stream/stream.zig");
const StreamProvider = stream_module.stream_provider.StreamProvider;
const connection_module = @import("../connection.zig");
const keys = @import("../connection_keys.zig");
const send = @import("../connection_send.zig");
const datagram_module = @import("../connection_datagram.zig");
const stream_send = @import("connection_stream_send.zig");
const stream_read = @import("connection_stream_read.zig");
const stream_incoming = stream_module.stream_incoming;
const build_test = @import("../packet_build/packet_build_test.zig");

const Level = core.Level;
const Connection = connection_module.Connection;
const Parameters = transport_parameters.Parameters;
const StreamId = stream_module.StreamId;
const testing = std.testing;

var client: Connection = undefined;
var server: Connection = undefined;
var suite_holder: build_test.RoundTrip = undefined;
var provider_holder: build_test.Fake = undefined;
var send_scratch: send.DefaultScratch = .{};
var datagram_scratch: datagram_module.Scratch = undefined;

/// The server's receive pool: sixteen blocks' capacity, which is also its window cap. Test-only.
const pool_blocks: usize = 16;
const pool_capacity: usize = pool_blocks * stream_module.stream_incoming.block_len;
var pool: stream_module.stream_incoming.Pool(pool_capacity) = .{};
var client_pool: stream_module.stream_incoming.Pool(pool_capacity) = .{};

/// Datagrams held while a test decides when each arrives. Test-only.
const held_max: usize = 8;
var held: [held_max][constants.datagram_len_min]u8 = undefined;
var held_len: [held_max]usize = undefined;
var output: [pool_capacity]u8 = undefined;

const test_now_ns: u64 = 1_000_000;
/// The instant the helpers send and receive at, which `exchange` moves on. Test-only.
var clock_ns: u64 = test_now_ns;
/// Longer than RFC 9000 §18.2's default max_ack_delay of 25 ms, so each round owes its ACKs.
const round_ns: u64 = 30_000_000;
const id_len: usize = 4;
const local_octet: u8 = 0xc1;
const peer_octet: u8 = 0x51;
const local_id: [id_len]u8 = @splat(local_octet);
const peer_id: [id_len]u8 = @splat(peer_octet);
/// The windows the server grants: a stream's, below the pool, and the connection's. Test-only.
const stream_window: u64 = 4_000;
const connection_window: u64 = pool_capacity;
/// A body one datagram cannot carry, and one past the stream's window. Test-only.
const body_len: u64 = 3_000;
const long_body_len: u64 = 6_000;

/// The client's octets, each set by its offset so one read from the wrong place shows. Test-only.
const octet_stride: u64 = 7;
fn octet_at(offset: u64) u8 {
    return @truncate(offset *% octet_stride);
}
var body_context: u8 = 0;
const body_vtable: stream_module.stream_provider.VTable = .{ .read = read_body };
fn read_body(_: *anyopaque, _: u64, offset: u64, out: []u8) usize {
    for (out, 0..) |*octet, index| octet.* = octet_at(offset + index);
    return out.len;
}

fn parameters() Parameters {
    var granted = Parameters.initial();
    granted.initial_max_data = connection_window;
    granted.initial_max_stream_data_bidi_remote = stream_window;
    granted.initial_max_stream_data_bidi_local = stream_window;
    granted.initial_max_stream_data_uni = stream_window;
    granted.initial_max_streams_bidi = 1;
    granted.initial_max_streams_uni = 1;
    return granted;
}

fn open_pair() void {
    clock_ns = test_now_ns;
    suite_holder.init();
    provider_holder = .{};
    open_one(&client, .client, client_pool.storage());
    open_one(&server, .server, pool.storage());
    client.apply_peer_parameters(parameters());
    server.apply_peer_parameters(parameters());
}

fn open_one(connection: *Connection, role: connection_module.Role, receive: ?stream_module.stream_incoming.Storage) void {
    connection.init(.{
        .role = role,
        .local_parameters = parameters(),
        .now_ns = test_now_ns,
        .identity = .{ .local_initial_source = &local_id, .original_destination = &peer_id },
        .receive = receive,
    });
    keys.on_keys_installed(connection, .application, .read);
    keys.on_keys_installed(connection, .application, .write);
    connection.handshake_complete = true;
    // RFC 9000 §8.1: a server sends only after it has received.
    if (role == .server) connection.path.on_datagram_received(constants.datagram_len_min);
}

/// Sends every datagram `from` owes now into `held`, and returns how many.
fn send_all(from: *Connection) !usize {
    var count: usize = 0;
    // Bounded by `held_max`.
    while (count < held_max) : (count += 1) {
        const sent = try send.send(from, suite_holder.suite(), provider_holder.provider(), .{ .context = &body_context, .vtable = &body_vtable }, &send_scratch, &held[count], clock_ns) orelse break;
        held_len[count] = sent.len;
    }
    return count;
}

fn deliver(index: usize, to: *Connection) !void {
    _ = try datagram_module.receive(to, suite_holder.suite(), provider_holder.provider(), .{ .octets = held[index][0..held_len[index]], .now_ns = clock_ns, .ecn = .not_ect }, &datagram_scratch);
}

fn expect_octets(from: u64, octets: []const u8) !void {
    for (octets, 0..) |octet, index| try testing.expectEqual(octet_at(from + index), octet);
}

/// The client opens its stream and hands colibri `len` octets and, when `fin`, their end.
fn client_stream(len: u64, fin: bool) !StreamId {
    const id = try stream_send.open(&client, .bidirectional);
    try stream_send.supply(&client, id, len, fin);
    return id;
}

test "decision 61: the application reads a stream in order, and all of it with the FIN" {
    open_pair();
    const id = try client_stream(body_len, true);
    const count = try send_all(&client);
    try testing.expect(count > 1);
    for (0..count) |index| try deliver(index, &server);
    const read = try stream_read.read(&server, id, &output);
    try testing.expectEqual(body_len, read.len);
    try testing.expect(read.fin);
    try expect_octets(0, output[0..read.len]);
    // RFC 9000 §3.2: every octet was read, so the receiving part is in "Data Read".
    try testing.expectEqual(.data_read, server.streams.lookup(id).live.receiving.state);
}

test "decision 80: a peek leaves the octets unread and gives no credit, and consume takes them" {
    open_pair();
    const id = try client_stream(body_len, true);
    for (0..try send_all(&client)) |index| try deliver(index, &server);
    const flow = &server.streams.lookup(id).live.receive_flow;
    const peeked = try stream_read.peek(&server, id, &output);
    try testing.expectEqual(body_len, peeked.len);
    try testing.expect(peeked.fin);
    try expect_octets(0, output[0..peeked.len]);
    try testing.expectEqual(0, flow.consumed);
    try testing.expectEqual(0, server.receive_flow.consumed);
    // A peek cut short does not reach the FIN.
    const short_len: usize = 100;
    const short = try stream_read.peek(&server, id, output[0..short_len]);
    try testing.expectEqual(short_len, short.len);
    try testing.expect(!short.fin);
    const taken = try stream_read.consume(&server, id, short_len);
    try testing.expect(!taken.fin);
    try testing.expectEqual(short_len, flow.consumed);
    try testing.expectEqual(short_len, server.receive_flow.consumed);
    // The rest reads from where the consume stopped, and ends the stream.
    const rest = try stream_read.read(&server, id, &output);
    try testing.expectEqual(body_len - short_len, rest.len);
    try testing.expect(rest.fin);
    try expect_octets(short_len, output[0..rest.len]);
}

test "RFC 9000 §2.2: octets that arrive out of order wait for the ones before them" {
    open_pair();
    const id = try client_stream(body_len, true);
    const count = try send_all(&client);
    try deliver(count - 1, &server);
    const early = try stream_read.read(&server, id, &output);
    try testing.expectEqual(0, early.len);
    try testing.expect(!early.fin);
    for (0..count - 1) |index| try deliver(index, &server);
    const read = try stream_read.read(&server, id, &output);
    try testing.expectEqual(body_len, read.len);
    try expect_octets(0, output[0..read.len]);
}

test "RFC 9000 §4.1: what the application reads is what lets the peer send more" {
    open_pair();
    const id = try client_stream(long_body_len, false);
    const count = try send_all(&client);
    for (0..count) |index| try deliver(index, &server);
    const limit = &client.streams.lookup(id).live.send_flow.limit;
    try testing.expect(client.streams.lookup(id).live.send_flow.is_blocked());
    // Nothing read, nothing to give: what the server sends acknowledges and raises no limit.
    for (0..try send_all(&server)) |index| try deliver(index, &client);
    try testing.expectEqual(stream_window, limit.*);
    const read = try stream_read.read(&server, id, &output);
    try testing.expectEqual(stream_window, read.len);
    // The server's next datagram carries MAX_STREAM_DATA, which raises the client's limit.
    for (0..try send_all(&server)) |index| try deliver(index, &client);
    try testing.expect(limit.* > stream_window);
}

test "decision 61: every receive window grows no further than the pool holds" {
    open_pair();
    try testing.expectEqual(pool_capacity, server.receive_flow.window_max);
    const id = try client_stream(body_len, true);
    const count = try send_all(&client);
    for (0..count) |index| try deliver(index, &server);
    try testing.expectEqual(pool_capacity, server.streams.lookup(id).live.receive_flow.window_max);
    // A connection given no pool keeps its windows where they start.
    open_one(&client, .client, null);
    try testing.expectEqual(connection_window, client.receive_flow.window_max);
}

/// The application error code the client resets its stream with (RFC 9000 §19.4). Test-only.
const reset_error_code: u64 = 0x10c;

/// A datagram held back past a reset, as a delayed one arrives. Test-only.
var late: [constants.datagram_len_min]u8 = undefined;
var late_len: usize = 0;

test "RFC 9000 §3.2: a reset stream is reported once, and its octets go back to the pool" {
    open_pair();
    const id = try client_stream(long_body_len, false);
    const count = try send_all(&client);
    // The first datagram, which carries the stream's first octets, is the one held back.
    for (1..count) |index| try deliver(index, &server);
    late_len = held_len[0];
    @memcpy(late[0..late_len], held[0][0..late_len]);
    try testing.expect(!server.streams.lookup(id).live.incoming.is_empty());
    try testing.expectEqual(null, stream_read.reset_code(&server, id));
    try stream_send.reset(&client, id, reset_error_code);
    const reset_count = try send_all(&client);
    for (0..reset_count) |index| try deliver(index, &server);
    try testing.expect(server.streams.lookup(id).live.incoming.is_empty());
    // Octets that arrive after the reset are for no one (RFC 9000 §3.2), so none is kept.
    _ = try datagram_module.receive(&server, suite_holder.suite(), provider_holder.provider(), .{ .octets = late[0..late_len], .now_ns = test_now_ns, .ecn = .not_ect }, &datagram_scratch);
    try testing.expect(server.streams.lookup(id).live.incoming.is_empty());
    // The application learns the peer's code before it reads, and reading reports the reset.
    try testing.expectEqual(reset_error_code, stream_read.reset_code(&server, id).?);
    try testing.expectError(error.StreamReset, stream_read.read(&server, id, &output));
    try testing.expectEqual(.reset_read, server.streams.lookup(id).live.receiving.state);
    try testing.expectEqual(null, stream_read.reset_code(&server, id));
}

test "RFC 9000 §2.1: a stream this endpoint only sends on is not one to read" {
    open_pair();
    const own = try stream_send.open(&server, .unidirectional);
    try testing.expectError(error.NotReadable, stream_read.read(&server, own, &output));
    const unopened: StreamId = .{ .value = 8 };
    try testing.expectError(error.NotReadable, stream_read.read(&server, unopened, &output));
}

/// Rounds of sending each way until neither endpoint owes anything. Test-only.
const exchange_rounds_max: usize = 8;

/// Each endpoint sends what it owes and the other takes it, until both are quiet.
fn exchange() !void {
    // Bounded by `exchange_rounds_max`.
    for (0..exchange_rounds_max) |_| {
        clock_ns += round_ns;
        const from_client = try send_all(&client);
        for (0..from_client) |index| try deliver(index, &server);
        const from_server = try send_all(&server);
        for (0..from_server) |index| try deliver(index, &client);
        if (from_client == 0 and from_server == 0) return;
    }
    return error.TestExchangeNotQuiet;
}

/// Blocks on the pool's free list. Test-only.
fn free_blocks() usize {
    const storage = server.receive_storage.?;
    var count: usize = 0;
    var index = storage.header.free_head;
    while (index != std.math.maxInt(u16)) : (count += 1) index = storage.blocks[index].next;
    return count;
}

test "RFC 9000 §3: a stream closes once each endpoint has finished both of its parts" {
    open_pair();
    const all = free_blocks();
    const id = try client_stream(body_len, true);
    try exchange();
    const read = try stream_read.read(&server, id, &output);
    try testing.expect(read.fin);
    // The server has read everything and not yet ended its own side, so the stream stays.
    try testing.expect(server.streams.lookup(id) == .live);
    try stream_send.supply(&server, id, 0, true);
    try exchange();
    // RFC 9000 §3.1: the server's FIN was acknowledged, so both of its parts are finished.
    try testing.expect(server.streams.lookup(id) == .closed);
    // RFC 9000 §4.6: a closed stream the client opened is one more it may open.
    try testing.expectEqual(1, server.streams.peer_limit[@intFromEnum(stream_module.Directionality.bidirectional)].consumed);
    // Decision 61: the block the last octets sat in went back with the stream.
    try testing.expectEqual(all, free_blocks());
    // The client closes once it reads the server's FIN, its own having been acknowledged.
    try testing.expect(client.streams.lookup(id) == .live);
    const end = try stream_read.read(&client, id, &output);
    try testing.expect(end.fin);
    try testing.expect(client.streams.lookup(id) == .closed);
}

test "RFC 9000 §3: a unidirectional stream closes when its one part finishes at each end" {
    open_pair();
    const id = try stream_send.open(&client, .unidirectional);
    try stream_send.supply(&client, id, body_len, true);
    try exchange();
    // RFC 9000 §3.1: the client's octets and FIN were acknowledged.
    try testing.expect(client.streams.lookup(id) == .closed);
    try testing.expect((try stream_read.read(&server, id, &output)).fin);
    // RFC 9000 §3.2: the server read to the end, and receiving is all it does on this stream.
    try testing.expect(server.streams.lookup(id) == .closed);
}

test "RFC 9000 §3: a reset stream closes once the reset is acknowledged and read" {
    open_pair();
    const id = try stream_send.open(&client, .unidirectional);
    try stream_send.supply(&client, id, body_len, false);
    try stream_send.reset(&client, id, 0);
    try exchange();
    // RFC 9000 §3.1: the RESET_STREAM was acknowledged, which is "Reset Recvd".
    try testing.expect(client.streams.lookup(id) == .closed);
    try testing.expectError(error.StreamReset, stream_read.read(&server, id, &output));
    // RFC 9000 §3.2: the application was told, which is "Reset Read".
    try testing.expect(server.streams.lookup(id) == .closed);
}
