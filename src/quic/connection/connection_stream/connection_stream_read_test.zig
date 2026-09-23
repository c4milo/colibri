//! The tests of `connection_stream_read.zig`: a server with a receive pool reads what a client
//! sent on a stream (decision 61), in order, and each read gives the client credit (RFC 9000 §4.1).
//! Every datagram goes through the client's send path and the server's `connection_datagram`.
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

/// Datagrams held while a test decides when each arrives. Test-only.
const held_max: usize = 8;
var held: [held_max][constants.datagram_len_min]u8 = undefined;
var held_len: [held_max]usize = undefined;
var output: [pool_capacity]u8 = undefined;

const test_now_ns: u64 = 1_000_000;
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
    granted.initial_max_streams_bidi = 1;
    granted.initial_max_streams_uni = 1;
    return granted;
}

fn open_pair() void {
    suite_holder.init();
    provider_holder = .{};
    open_one(&client, .client, null);
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
        const sent = try send.send(from, suite_holder.suite(), provider_holder.provider(), .{ .context = &body_context, .vtable = &body_vtable }, &send_scratch, &held[count], test_now_ns) orelse break;
        held_len[count] = sent.len;
    }
    return count;
}

fn deliver(index: usize, to: *Connection) !void {
    _ = try datagram_module.receive(to, suite_holder.suite(), provider_holder.provider(), .{ .octets = held[index][0..held_len[index]], .now_ns = test_now_ns, .ecn = .not_ect }, &datagram_scratch);
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
    try testing.expectEqual(connection_window, client.receive_flow.window_max);
}

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
    try stream_send.reset(&client, id, 0);
    const reset_count = try send_all(&client);
    for (0..reset_count) |index| try deliver(index, &server);
    try testing.expect(server.streams.lookup(id).live.incoming.is_empty());
    // Octets that arrive after the reset are for no one (RFC 9000 §3.2), so none is kept.
    _ = try datagram_module.receive(&server, suite_holder.suite(), provider_holder.provider(), .{ .octets = late[0..late_len], .now_ns = test_now_ns, .ecn = .not_ect }, &datagram_scratch);
    try testing.expect(server.streams.lookup(id).live.incoming.is_empty());
    try testing.expectError(error.StreamReset, stream_read.read(&server, id, &output));
    try testing.expectEqual(.reset_read, server.streams.lookup(id).live.receiving.state);
}

test "RFC 9000 §2.1: a stream this endpoint only sends on is not one to read" {
    open_pair();
    const own = try stream_send.open(&server, .unidirectional);
    try testing.expectError(error.NotReadable, stream_read.read(&server, own, &output));
    const unopened: StreamId = .{ .value = 8 };
    try testing.expectError(error.NotReadable, stream_read.read(&server, unopened, &output));
}
