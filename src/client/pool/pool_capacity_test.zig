//! The tests of a pool's capacity (`pool.zig`, decision 124). A pool with no QUIC holds no
//! QUIC state, refuses `versions` that allow h3, and has no QUIC connection for a call to use. A
//! call of its `start_quic` does not compile, so no test makes one. `client.Pool` holds QUIC.
//! The tests over TCP run on both types (`pool_test_support.zig`).
const std = @import("std");
const support = @import("../connection/connection_test_support.zig");
const tls_support = @import("../connection/connection_tls_test_support.zig");
const quic_connection = @import("../quic/quic_connection.zig");
const protocols_module = @import("../protocols.zig");
const pool_module = @import("pool.zig");
const pool_support = @import("pool_test_support.zig");

const testing = std.testing;
const Pool = pool_module.Pool;
const TcpAlone = pool_module.PoolOf(.{ .quic = false });

/// The pool with no QUIC the tests drive, and its configuration, outside any stack frame.
/// Test-only.
var pool: TcpAlone align(@alignOf(TcpAlone)) = undefined;
var pool_memory: [TcpAlone.memory_bytes(.{})]u8 align(TcpAlone.memory_alignment) = undefined;
var config: pool_module.Config align(@alignOf(pool_module.Config)) = undefined;
var body: [body_len]u8 = undefined;
const body_len: usize = 64;

const https_port: u16 = 443;
/// An IPv4 host, its four octets alike. Test-only.
const ipv4_len: usize = 4;
const host_octet: u8 = 0x7f;
const loopback: [ipv4_len]u8 = @splat(host_octet);
const addresses = [_]pool_module.Address{pool_module.Address.of(&loopback, 0)};
const values: pool_module.Values = .{ .addresses = &addresses, .port = https_port };

test "decision 124: client.Pool is a pool of the default capacity, which holds QUIC" {
    try testing.expect((pool_module.Capacity{}).quic);
    try testing.expect(Pool == pool_module.PoolOf(.{ .quic = true }));
    try testing.expectEqual(quic_connection.QuicConnection, @FieldType(Pool, "quic"));
}

test "decision 124: a pool with no QUIC holds no QUIC connection and no QUIC TLS configuration" {
    inline for (.{ "quic", "quic_tls", "quic_config", "receive_pool" }) |name| {
        try testing.expectEqual(void, @FieldType(TcpAlone, name));
    }
    // The pool is smaller than the default one by at least the QUIC connection.
    try testing.expect(@sizeOf(TcpAlone) + @sizeOf(quic_connection.QuicConnection) <= @sizeOf(Pool));
}

test "RFC 9114 §3.1: a pool with no QUIC refuses versions that allow h3, in cleartext and over TLS" {
    const with_h3 = [_]protocols_module.Protocols{ .{}, .{ .h11 = false }, .{ .h2 = false }, .{ .h11 = false, .h2 = false } };
    for (with_h3) |versions| {
        config = .{ .authority = support.authority, .protocols = versions };
        try testing.expectError(error.VersionUnavailable, pool.init(&pool_memory, &config, values, .{}, null));
        config.tls = tls_support.client_values(support.authority);
        try testing.expectError(error.VersionUnavailable, pool.init(&pool_memory, &config, values, .{}, null));
    }
    // With h3 off it offers TCP, and with no version at all it offers nothing (decision 117).
    config = .{ .authority = support.authority, .protocols = .{ .h3 = false } };
    try pool.init(&pool_memory, &config, values, .{}, null);
    try testing.expect(pool.offered.tcp and !pool.offered.quic);
    config.protocols = .{ .h11 = false, .h2 = false, .h3 = false };
    try testing.expectError(error.NoVersion, pool.init(&pool_memory, &config, values, .{}, null));
}

test "decision 124: a pool with no QUIC opens TCP for an origin that names h3, and has no QUIC connection" {
    config = .{ .tls = tls_support.client_values(support.authority), .protocols = .{ .h3 = false }, .authority = support.authority };
    // RFC 9460 §7.1.2 and RFC 7838 §3: the record and Alt-Svc both name h3.
    var known = values;
    known.https = .{ .h3 = true };
    known.alternative = .{ .port = https_port, .fresh_until_ns = support.now_ns + 1 };
    try pool.init(&pool_memory, &config, known, .{}, null);
    var exchange: support.Exchange = .{ .request = .{ .method = "GET", .path = "/" }, .response = .{ .body = &body } };
    _ = try pool.request(&exchange.request, &exchange.response);
    const opened = pool.receive(.none, support.now_ns).event.?.open;
    try testing.expectEqual(pool_module.Transport.tcp, opened.transport);
    // A datagram is dropped, no datagram is owed, and nothing names a QUIC connection.
    var octets: [ipv4_len]u8 = @splat(host_octet);
    const dropped = pool.receive(.{ .datagram = .{ .bytes = &octets } }, support.now_ns);
    try testing.expectEqual(octets.len, dropped.consumed);
    try testing.expectEqual(null, dropped.event);
    try testing.expectEqual(null, pool.send_datagram(&body, support.now_ns));
    pool.transport_closed(pool_support.connection_of(pool, .quic));
    pool.on_instant(support.now_ns);
    try testing.expectEqual(null, pool.take_ticket(pool_support.connection_of(pool, .quic)));
    try testing.expectEqual(pool_module.Phase.none, pool.phase(pool_support.slot_of(pool, .quic)));
    try testing.expectEqual(null, pool.deadline_ns());
    try pool.start_tcp(pool_support.connection_of(pool, .tcp), support.stream.random(), support.now_seconds, null);
    try testing.expectEqual(pool_module.Phase.handshake, pool.phase(pool_support.slot_of(pool, .tcp)));
    try testing.expect(pool.send_stream(pool_support.connection_of(pool, .tcp), &support.to_peer, support.now_ns) > 0);
}
