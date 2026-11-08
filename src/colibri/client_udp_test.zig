//! The tests of a `colibri.Client` over QUIC (design §8 step 42): a `colibri.Server` with the test
//! identity runs on a thread of its own on 127.0.0.1, and the client fetches over h3 from its UDP
//! socket, or falls back to h2 over TCP when the server opens none. These tests also send the
//! server's first datagrams, which the record of design §8 step 37c left with no check. Decision
//! 150 ruling 7 lets these tests bind loopback.
const std = @import("std");
const client = @import("client");
const testdata = @import("testdata");
const support = @import("test_support.zig");
const fixture = @import("client_test_support.zig");

const testing = std.testing;
const test_client = &fixture.test_client;

/// Fetches `count` greetings over TLS from a server with a UDP socket when `udp` is set, with
/// `shutdown` before `run`. The pool's configuration asks for QUIC first, and leaves `ecn` false.
fn fetch(udp: bool, count: u32, handler: *fixture.Handler) !void {
    try fetch_speaking(.{ .prefer = .quic }, udp, count, handler);
}

/// As `fetch`, with the pool's configuration speaking `protocols`.
fn fetch_speaking(protocols: client.Protocols, udp: bool, count: u32, handler: *fixture.Handler) !void {
    const limit_ms: u64 = if (udp) fixture.watchdog_ms else fixture.unanswered_quic_watchdog_ms;
    var counter: support.Counter = .{};
    try fixture.start_server(true, udp);
    defer fixture.stop_server();
    const pool = fixture.pool_config(protocols, true);
    try testing.expect(!pool.ecn);
    try test_client.init(&.{
        .host = "127.0.0.1",
        .port = fixture.port(),
        .pool = pool,
        .random = counter.random(),
        .unix_seconds = testdata.now_seconds,
    }, handler);
    defer test_client.deinit();
    try testing.expect(test_client.udp.served);
    try handler.request(count);
    test_client.shutdown();
    try fixture.run_within(limit_ms);
}

test "design §8 step 42: a client fetches over h3 from a server's UDP socket" {
    var handler: fixture.Handler = .{};
    // RFC 9114 §3.1: the pool tries QUIC first, as it asks, and the server's QUIC handshake
    // selects h3.
    try fetch(true, 1, &handler);
    try testing.expect(handler.greeted());
    try testing.expectEqual(client.Protocol.h3, handler.connected.?);
    try testing.expectEqual(1, handler.connections);
}

test "design §8 step 42: three exchanges go over one QUIC connection" {
    var handler: fixture.Handler = .{};
    try fetch(true, 3, &handler);
    try testing.expect(handler.greeted());
    try testing.expectEqual(client.Protocol.h3, handler.connected.?);
    try testing.expectEqual(1, handler.connections);
}

test "design §8 step 42: twenty exchanges, one after another, go over one QUIC connection" {
    var counter: support.Counter = .{};
    try fixture.start_server(true, true);
    defer fixture.stop_server();
    var handler: fixture.Handler = .{ .more = sequential_exchanges - 1, .stop_after = sequential_exchanges };
    try test_client.init(&.{ .host = "127.0.0.1", .port = fixture.port(), .pool = fixture.pool_config(.{ .prefer = .quic }, true), .random = counter.random(), .unix_seconds = testdata.now_seconds }, &handler);
    defer test_client.deinit();
    // More datagrams go each way than the UDP socket has batches, so each batch is sent again
    // once its send has ended.
    try handler.request(1);
    try fixture.run();
    try testing.expectEqual(sequential_exchanges, handler.requested);
    try testing.expect(handler.greeted());
    try testing.expectEqual(client.Protocol.h3, handler.connected.?);
    try testing.expectEqual(1, handler.connections);
}

/// The exchanges the test above makes, one after another: more than the UDP socket's batches.
const sequential_exchanges = 20;

comptime {
    std.debug.assert(sequential_exchanges > @import("constants.zig").limits.udp_batches);
}

test "design §8 step 42: ECN codepoints cross both UDP sockets, and the exchange ends whole" {
    var handler: fixture.Handler = .{};
    // RFC 9000 §13.4: each side marks its datagrams ECT(0) and counts what it reads. The pool's
    // configuration leaves `ecn` false, and the client sets it (decision 68), so the server's
    // first datagram marked ECT(0) does not halt the pool.
    try fetch(true, 2, &handler);
    try testing.expect(handler.greeted());
    try testing.expectEqual(client.Protocol.h3, handler.connected.?);
    try testing.expect(fixture.ecn_read_as_ect0());
}

test "design §8 step 42: with no UDP socket at the server, the client falls back to h2" {
    var handler: fixture.Handler = .{};
    // RFC 9114 §3.1: QUIC gets no answer, so TCP opens once the fallback delay passes, and ALPN
    // selects h2.
    try fetch(false, 1, &handler);
    try testing.expect(handler.greeted());
    try testing.expectEqual(client.Protocol.h2, handler.connected.?);
}

test "decision 117 as amended: by default the client fetches over h2 from a server with a UDP socket" {
    var handler: fixture.Handler = .{};
    // `ClientConfig.pool.protocols.prefer` is `.tcp` by default, so TCP opens first and ALPN
    // selects h2, though the server answers QUIC too.
    try fetch_speaking(.{}, true, 1, &handler);
    try testing.expect(handler.greeted());
    try testing.expectEqual(client.Protocol.h2, handler.connected.?);
    try testing.expectEqual(1, handler.connections);
}
