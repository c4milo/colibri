//! The tests of a long response through a `colibri.Server`'s router (design §8 step 46): a struct
//! route writes sixteen times the router's room for a response through `body()`, and a
//! `colibri.Client` reads it whole and in order over h11, h2 and h3. Decision 150 ruling 7 lets
//! these tests bind loopback.
const std = @import("std");
const client = @import("client");
const testdata = @import("testdata");
const support = @import("test_support.zig");
const fixture = @import("client_test_support.zig");

const testing = std.testing;
const test_client = &fixture.test_client;

/// Fetches `/stream` once over a client of `protocols`, from a server over TLS when `secure` is
/// set, with a UDP socket when `udp` is set.
fn fetch_stream(protocols: client.Protocols, secure: bool, udp: bool, handler: *fixture.Handler) !void {
    var counter: support.Counter = .{};
    try fixture.start_server(secure, udp);
    defer fixture.stop_server();
    var pool = fixture.pool_config(protocols, secure);
    pool.protocols.h3 = udp;
    try test_client.init(.{
        .host = "127.0.0.1",
        .port = fixture.port(),
        .pool = pool,
        .random = counter.random(),
        .unix_seconds = testdata.now_seconds,
    });
    defer test_client.deinit();
    handler.path = "/stream";
    try handler.request(1);
    test_client.shutdown();
    try fixture.run(handler);
}

test "design §8 step 46: a route streams sixteen times response_bytes over h11" {
    var handler: fixture.Handler = .{};
    try fetch_stream(.{ .h2 = false }, false, false, &handler);
    try testing.expectEqual(client.Protocol.h11, handler.connected.?);
    try testing.expectEqual(1, handler.streams);
}

test "design §8 step 46: a route streams sixteen times response_bytes over h2" {
    var handler: fixture.Handler = .{};
    // RFC 9113 §3.3: a client that knows the server speaks h2 sends the preface at once.
    try fetch_stream(.{ .h11 = false }, false, false, &handler);
    try testing.expectEqual(client.Protocol.h2, handler.connected.?);
    try testing.expectEqual(1, handler.streams);
}

test "design §8 step 46: a route streams sixteen times response_bytes over h3" {
    var handler: fixture.Handler = .{};
    // RFC 9114 §3.1: the pool tries QUIC first, and the server's QUIC handshake selects h3.
    try fetch_stream(.{ .prefer = .quic }, true, true, &handler);
    try testing.expectEqual(client.Protocol.h3, handler.connected.?);
    try testing.expectEqual(1, handler.streams);
}
