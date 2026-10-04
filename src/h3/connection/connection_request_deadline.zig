//! What a server's deadlines ask of h3's request streams (decision 110 as amended, design §8 step
//! 20c): the stream that has waited longest for its request's head, and reading no more of a
//! request the server answers without the rest of it. Split out of `connection_request.zig`
//! because a hand-written source file stays at or under 500 lines (CLAUDE.md).
const std = @import("std");
const assert = std.debug.assert;
const quic = @import("quic");
const connection_module = @import("connection.zig");
const connection_request = @import("connection_request.zig");

const Connection = connection_module.Connection;
const QuicConnection = quic.Connection;

/// A request stream whose head has not arrived whole, and the instant colibri first saw it.
pub const HeadWait = struct {
    stream_id: u64,
    since_ns: u64,
};

/// The request stream that has waited longest for its head, at a server, or null when none waits.
/// A look that finds none is not repeated until `accept` takes another stream, so a connection
/// whose heads arrive whole walks its request streams once for each stream and not at each call.
pub fn oldest_head_wait(connection: *Connection) ?HeadWait {
    assert(connection.options.role == .server);
    if (!connection.requests.head_wait_possible) return null;
    var oldest: ?HeadWait = null;
    for (&connection.requests.slots) |*slot| {
        const request = if (slot.*) |*held| held else continue;
        if (request.phase != .head) continue;
        if (oldest) |found| {
            if (found.since_ns <= request.opened_ns) continue;
        }
        oldest = .{ .stream_id = request.id, .since_ns = request.opened_ns };
    }
    connection.requests.head_wait_possible = oldest != null;
    return oldest;
}

/// Reads no more of the request on `stream_id`, and asks the peer to stop sending it, with
/// `code`. colibri's side of the stream stays open, so a response still goes out on it.
pub fn stop_reading(connection: *Connection, transport: *QuicConnection, stream_id: u64, code: u64) void {
    const request = connection.requests.find(stream_id) orelse return;
    if (request.phase == .abandoned) return;
    // RFC 9114 §4.1: a server that needs no more of a request "MAY abort reading the request
    // stream", and "the error code H3_NO_ERROR SHOULD be used when requesting that the client
    // stop sending on the request stream". A receiving part that already ended refuses nothing.
    quic.connection_stream_send.stop_sending(transport, .{ .value = stream_id }, code) catch {};
    // RFC 9204 §2.2.2.2: a decoder that abandons a stream cancels the references it held.
    connection_request.owe_cancel(connection, request);
    request.phase = .abandoned;
    request.data_left = 0;
    request.skip_left = 0;
    request.blocked_at = null;
}

const testing = std.testing;
const core = @import("core");
const constants = @import("../constants.zig");
const harness = @import("connection_test.zig");
const request_tests = @import("connection_request_test.zig");

const client = &harness.client;
const server = &harness.server;

/// Room for the HEADERS frame a test writes. Test-only.
const frame_len_max: usize = 256;
/// The instants the tests' server first sees each stream at. Test-only.
const first_ns: u64 = 5;
const second_ns: u64 = 9;

/// A GET's HEADERS frame, whole, in `storage`. Test-only.
fn get_frame(storage: *[frame_len_max]u8) ![]const u8 {
    var writer = core.Writer.init(storage);
    try request_tests.headers_frame(&writer, &harness.get_lines);
    return writer.written();
}

/// The client opens a request stream and sends all of `frame` but its last octet. Test-only.
fn open_short_of_head(frame: []const u8) !u64 {
    const id = try quic.connection_stream_send.open(&client.transport, .bidirectional);
    try client.send_raw(id.value, frame[0 .. frame.len - 1], false);
    return id.value;
}

/// What the server reads at `now_ns`. Test-only.
fn server_reads(now_ns: u64) !?connection_module.Event {
    try harness.transfer(client, server);
    return server.h3.receive(&server.transport, &server.body, now_ns);
}

test "decision 110: the request stream that has waited longest for its head is the first seen whose head is not whole" {
    try harness.pair(.{ .role = .client }, .{ .role = .server });
    try testing.expectEqual(null, oldest_head_wait(&server.h3));
    var storage: [frame_len_max]u8 = undefined;
    const frame = try get_frame(&storage);
    const first = try open_short_of_head(frame);
    try testing.expectEqual(null, try server_reads(first_ns));
    const second = try open_short_of_head(frame);
    try testing.expectEqual(null, try server_reads(second_ns));
    try testing.expectEqual(HeadWait{ .stream_id = first, .since_ns = first_ns }, oldest_head_wait(&server.h3).?);
    // The first stream's head arrives whole, so the second has waited longest.
    try client.send_raw(first, frame[frame.len - 1 ..], true);
    try testing.expectEqual(first, (try server_reads(second_ns)).?.request.stream_id);
    try testing.expectEqual(HeadWait{ .stream_id = second, .since_ns = second_ns }, oldest_head_wait(&server.h3).?);
}

test "decision 110: a look that finds no request stream waiting is repeated only once another opens" {
    try harness.pair(.{ .role = .client }, .{ .role = .server });
    try testing.expect(!server.h3.requests.head_wait_possible);
    var storage: [frame_len_max]u8 = undefined;
    const frame = try get_frame(&storage);
    const id = try open_short_of_head(frame);
    try testing.expectEqual(null, try server_reads(first_ns));
    try testing.expect(server.h3.requests.head_wait_possible);
    // A look that finds a stream waiting is repeated at the next call.
    try testing.expectEqual(id, oldest_head_wait(&server.h3).?.stream_id);
    try testing.expectEqual(id, oldest_head_wait(&server.h3).?.stream_id);
    // The flag alone says whether a look walks the streams.
    server.h3.requests.head_wait_possible = false;
    try testing.expectEqual(null, oldest_head_wait(&server.h3));
    server.h3.requests.head_wait_possible = true;
    try client.send_raw(id, frame[frame.len - 1 ..], true);
    try testing.expectEqual(id, (try server_reads(second_ns)).?.request.stream_id);
    try testing.expectEqual(null, oldest_head_wait(&server.h3));
    try testing.expect(!server.h3.requests.head_wait_possible);
}

test "RFC 9114 §4.1: a server that stops reading a request asks the client to stop sending, and still answers" {
    try harness.pair(.{ .role = .client }, .{ .role = .server });
    var storage: [frame_len_max]u8 = undefined;
    const id = try open_short_of_head(try get_frame(&storage));
    try testing.expectEqual(null, try server_reads(first_ns));
    stop_reading(&server.h3, &server.transport, id, constants.error_no_error);
    // The stream waits for no head any more.
    try testing.expectEqual(null, oldest_head_wait(&server.h3));
    try harness.respond(id, &harness.ok_lines, "");
    try harness.exchange();
    // RFC 9000 §3.5: the client answers STOP_SENDING by resetting its side.
    const stream_id: quic.stream.StreamId = .{ .value = id };
    const sending = client.transport.streams.lookup(stream_id).live.sending;
    try testing.expect(sending.state == .reset_sent or sending.state == .reset_recvd);
    // The response's HEADERS frame arrived, and ended the stream.
    var read: [frame_len_max]u8 = undefined;
    const arrived = try quic.connection_stream_read.peek(&client.transport, stream_id, &read);
    try testing.expect(arrived.len > 0 and arrived.fin);
    try testing.expectEqual(constants.frame_headers, read[0]);
}
