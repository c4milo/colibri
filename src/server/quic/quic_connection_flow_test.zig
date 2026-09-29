//! More tests of the server over QUIC (`quic_connection.zig`, `quic_connection_h3.zig`): when a
//! request is done or cancelled while its stream stays open, a request's trailer section, and the
//! windows a smaller receive pool sets. Split out of `quic_connection_test.zig` for length.
const std = @import("std");
const quic = @import("quic");
const support = @import("quic_test_support.zig");

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
    _ = try connection.write_body(fetch.id, .{ .octets = "answer", .end = true });
    try support.pump(support.rounds_default);
    try testing.expectEqualStrings("answer", support.content_of(fetch));
    try testing.expectEqual(fetch.id, support.nth(.done, 0).?.id);
    try testing.expect(connection.transport.streams.lookup(.{ .value = fetch.id }) == .live);
    // A connection not shut down stays open once its requests are done.
    try support.pump(support.rounds_default);
    try testing.expect(support.client.termination.state == .active);
    try testing.expect(!connection.ended());
}

test "RFC 9000 §3.5: a client's STOP_SENDING cancels the request while its stream stays open" {
    const fetch = try open_request();
    try connection.respond(fetch.id, .{ .status = ok, .end = false });
    _ = try connection.write_body(fetch.id, .{ .octets = "partial", .end = false });
    try support.stop_fetch(fetch);
    try support.pump(support.rounds_default);
    try testing.expectEqual(fetch.id, support.nth(.cancelled, 0).?.id);
    try testing.expect(connection.transport.streams.lookup(.{ .value = fetch.id }) == .live);
    try testing.expectEqual(null, support.nth(.done, 0));
}

test "RFC 9114 §4.1.1: a client's reset of its request cancels it, and the server resets its response" {
    const fetch = try open_request();
    try connection.respond(fetch.id, .{ .status = ok, .end = false });
    try support.reset_fetch(fetch);
    try support.pump(support.rounds_default);
    try testing.expectEqual(fetch.id, support.nth(.cancelled, 0).?.id);
    try testing.expect(response_reset(fetch.id));
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
