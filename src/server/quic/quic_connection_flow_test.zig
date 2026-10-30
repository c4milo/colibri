//! More tests of the server over QUIC (`quic_connection.zig`, `quic_connection_h3.zig`): when a
//! request is done or cancelled while its stream stays open, a request's trailer section, and the
//! windows a smaller receive pool sets. Split out of `quic_connection_test.zig` for length.
const std = @import("std");
const quic = @import("quic");
const support = @import("quic_test_support.zig");
const internal = @import("quic_connection_internal.zig");

const testing = std.testing;
const connection = &support.connection;

const ok: u16 = 200;
const trailer_fields = [_]support.Field{.{ .name = "checksum", .value = "1" }};

/// A connected pair, and a request whose stream the client leaves open. Test-only.
fn open_request() !*support.Fetch {
    try support.start();
    try support.connect();
    const fetch = try support.request_open("POST", "/upload", "part");
    try support.pump(support.rounds_default);
    return fetch;
}

/// Whether the server's side of stream `id` was reset, or the stream closed. Test-only.
fn response_reset(id: u64) bool {
    return switch (connection.transport.streams.lookup(.{ .value = id })) {
        .closed => true,
        .unopened => false,
        .live => |stream| stream.sending.state == .reset_sent or stream.sending.state == .reset_recvd,
    };
}

test "RFC 9000 §3.1: a response the peer acknowledged is done while the request's stream stays open" {
    const fetch = try open_request();
    try connection.respond(fetch.id, .{ .status = ok, .end = false });
    _ = try connection.write_body(fetch.id, .{ .bytes = "answer", .end = true });
    try support.pump(support.rounds_default);
    try testing.expectEqualStrings("answer", support.content_of(fetch));
    try testing.expectEqual(fetch.id, support.nth(.done, 0).?.id);
    try testing.expect(connection.transport.streams.lookup(.{ .value = fetch.id }) == .live);
    // A connection not shut down stays open once its requests are done.
    try support.pump(support.rounds_default);
    try testing.expect(support.client.termination.state == .active);
    try testing.expect(!internal.ended(connection));
}

test "RFC 9000 §3.5: a client's STOP_SENDING cancels the request while its stream stays open" {
    const fetch = try open_request();
    try connection.respond(fetch.id, .{ .status = ok, .end = false });
    _ = try connection.write_body(fetch.id, .{ .bytes = "partial", .end = false });
    try support.stop_fetch(fetch);
    try support.pump(support.rounds_default);
    try testing.expectEqual(fetch.id, support.nth(.cancelled, 0).?.id);
    try testing.expect(support.nth(.cancelled, 0).?.reason.? == .peer_reset);
    try testing.expect(connection.transport.streams.lookup(.{ .value = fetch.id }) == .live);
    try testing.expectEqual(null, support.nth(.done, 0));
}

test "RFC 9114 §4.1.1: a client's reset of its request cancels it, and the server resets its response" {
    const fetch = try open_request();
    try connection.respond(fetch.id, .{ .status = ok, .end = false });
    try support.reset_fetch(fetch);
    try support.pump(support.rounds_default);
    try testing.expectEqual(fetch.id, support.nth(.cancelled, 0).?.id);
    try testing.expect(support.nth(.cancelled, 0).?.reason.? == .peer_reset);
    try testing.expect(response_reset(fetch.id));
}

test "RFC 9114 §4.1.2: a request whose content falls short of its content-length is cancelled as refused" {
    try support.start();
    try support.connect();
    const declared = [_]support.Field{.{ .name = "content-length", .value = "5" }};
    const fetch = try support.request_with_fields("POST", "/upload", &declared);
    try support.pump(support.rounds_default);
    try testing.expectEqual(fetch.id, support.nth(.cancelled, 0).?.id);
    try testing.expect(support.nth(.cancelled, 0).?.reason.? == .refused);
}

test "RFC 9110 §6.5: a request's trailer section ends it, and no end of its content follows" {
    try support.start();
    try support.connect();
    const fetch = try support.request_with_trailers("/upload", &trailer_fields);
    try support.pump(support.rounds_default);
    try testing.expectEqual(fetch.id, support.nth(.request, 0).?.id);
    try testing.expectEqual(fetch.id, support.nth(.trailers, 0).?.id);
    try testing.expectEqual(null, support.nth(.body, 0));
}

/// A receive pool smaller than a request stream's window. Test-only.
const small_pool_len: usize = 32_768;
const SmallPool = quic.stream.stream_incoming.Pool(small_pool_len);
threadlocal var small_pool: SmallPool align(@alignOf(SmallPool)) = undefined;

test "RFC 9000 §4.1: no window the server advertises grants more than a smaller receive pool holds" {
    try support.start_with_pool(small_pool.storage());
    try support.connect();
    const granted = connection.transport.local_parameters;
    try testing.expectEqual(small_pool_len, granted.initial_max_data);
    try testing.expectEqual(small_pool_len, granted.initial_max_stream_data_bidi_remote);
    try testing.expectEqual(small_pool_len, granted.initial_max_stream_data_uni);
}

/// A response of about 200 packets in datagrams of the smallest size, past the first skip when
/// the intervals are the shortest. Test-only.
const long_body_len: usize = long_body_packets * quic.constants.protocol.datagram_len_min;
const long_body_packets: usize = 200;
const long_body: [long_body_len]u8 = @splat('x');
/// Calls of `write_body` and rounds of pumping that carry the long response. Test-only.
const write_rounds_max: usize = 512;

test "RFC 9000 §21.4: the server skips a packet number, and a long response reaches an honest client whole" {
    try support.start();
    support.server_datagram_len = quic.constants.protocol.datagram_len_min;
    try support.connect();
    const space = quic.connection.space_at(&connection.transport, .application);
    // The server drew the intervals at start. From here every interval is the shortest, so the
    // response passes a skip whatever the draw was.
    try testing.expect(space.skips != null);
    space.skips = .init(0);
    const fetch = try support.request("GET", "/", "");
    try support.pump(support.rounds_default);
    try connection.respond(fetch.id, .{ .status = ok, .end = false });
    var written: usize = 0;
    for (0..write_rounds_max) |_| {
        if (support.content_of(fetch).len == long_body.len) break;
        if (written < long_body.len) {
            written += try connection.write_body(fetch.id, .{ .bytes = long_body[written..], .end = true });
        }
        try support.pump(1);
    }
    try testing.expectEqual(long_body.len, support.content_of(fetch).len);
    try support.pump(support.rounds_default);
    // The client's ACK frames left the skipped number out, so the server closed nothing.
    try testing.expect(space.skips.?.skipped != null);
    try testing.expect(!support.server_failed);
    try testing.expectEqual(fetch.id, support.nth(.done, 0).?.id);
}
