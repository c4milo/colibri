//! The tests of a pool's memory (`pool.zig`, decision 125, decision 35 as amended): what
//! `memory_bytes` counts, where `init` places the TCP connections and the exchanges, and the
//! bound `receive_events_without_input_max` gives for each count.
const std = @import("std");
const support = @import("../connection/connection_test_support.zig");
const connection_module = @import("../connection/connection.zig");
const constants = @import("../constants.zig");
const pool_module = @import("pool.zig");

const testing = std.testing;
const Pool = pool_module.Pool;
const TcpAlone = pool_module.PoolOf(.{ .quic = false });
const Entry = pool_module.Entry;
const Link = pool_module.Link;
const Connection = connection_module.Connection;

/// A pool of fewer requests than one connection holds, so a request past them is refused.
const few_requests: u16 = 8;
const few: pool_module.Options = .{ .requests = few_requests };
/// A pool of several TCP connections, and of fewer requests.
const counted_tcp: u16 = 3;
const counted: pool_module.Options = .{ .tcp_connections = counted_tcp, .requests = few_requests };

/// The pool the tests drive, its memory and its configuration, outside any stack frame.
/// Test-only.
var pool: TcpAlone align(@alignOf(TcpAlone)) = undefined;
var pool_memory: [TcpAlone.memory_bytes(few)]u8 align(TcpAlone.memory_alignment) = undefined;
var config: pool_module.Config align(@alignOf(pool_module.Config)) = undefined;
var exchanges: [few.requests + 1]support.Exchange align(@alignOf(support.Exchange)) = undefined;

const http_port: u16 = 80;
/// An IPv4 host, its four octets alike. Test-only.
const ipv4_len: usize = 4;
const host_octet: u8 = 0x7f;
const loopback: [ipv4_len]u8 = @splat(host_octet);
const addresses = [_]pool_module.Address{pool_module.Address.of(&loopback, 0)};

test "decision 125: memory_bytes counts each TCP connection and each exchange, at comptime too" {
    // The function is pure, so a program sizes a static array with it.
    const default_len = comptime Pool.memory_bytes(.{});
    try testing.expectEqual(default_len, TcpAlone.memory_bytes(.{}));
    // One TCP connection, its link, and `requests_max` entries after them.
    try testing.expectEqual(@sizeOf(Connection) + @sizeOf(Link) + constants.requests_max * @sizeOf(Entry), default_len);
    // Each TCP connection and each exchange more adds its size.
    const counted_len = @as(usize, counted_tcp) * (@sizeOf(Connection) + @sizeOf(Link)) + @as(usize, few_requests) * @sizeOf(Entry);
    try testing.expectEqual(counted_len, Pool.memory_bytes(counted));
    try testing.expectEqual(default_len + @sizeOf(Entry), Pool.memory_bytes(.{ .requests = constants.requests_max + 1 }));
    // The alignment serves both parts.
    try testing.expect(Pool.memory_alignment >= @alignOf(Connection) and Pool.memory_alignment >= @alignOf(Entry));
}

test "decision 125: init keeps the TCP connection and the exchanges in the caller's memory" {
    config = .{ .authority = support.authority, .protocols = .{ .h3 = false } };
    try pool.init(&pool_memory, &config, .{ .addresses = &addresses, .port = http_port }, few, null);
    const first = @intFromPtr(&pool_memory);
    const end = first + pool_memory.len;
    try testing.expectEqual(1, pool.tcp.len);
    try testing.expectEqual(few.requests, pool.entries.len);
    try testing.expect(@intFromPtr(pool.tcp.ptr) >= first and @intFromPtr(pool.tcp.ptr + pool.tcp.len) <= end);
    try testing.expect(@intFromPtr(pool.entries.ptr) >= first and @intFromPtr(pool.entries.ptr + pool.entries.len) <= end);
    // The pool holds `exchanges` at once and refuses one more, until one is reported.
    for (exchanges[0..few.requests]) |*exchange| {
        exchange.* = .{ .request = .{ .method = "GET", .path = "/" } };
        _ = try pool.request(&exchange.request, &exchange.response);
    }
    const past = &exchanges[few.requests];
    past.* = .{ .request = .{ .method = "GET", .path = "/" } };
    try testing.expectError(error.Full, pool.request(&past.request, &past.response));
}

test "decision 125: receive_events_without_input_max counts each exchange and each transport" {
    // One `finished` for each exchange, the events of each transport, and one `closed`: the TCP
    // connections and the QUIC connection.
    const per_transport = constants.transport_events_max;
    const closed = 1;
    const default_transports = 2;
    try testing.expectEqual(constants.requests_max + default_transports * per_transport + closed, Pool.receive_events_without_input_max(.{}));
    // A pool with no QUIC has no QUIC transport.
    try testing.expectEqual(constants.requests_max + per_transport + closed, TcpAlone.receive_events_without_input_max(.{}));
    try testing.expectEqual(@as(usize, few_requests) + (@as(usize, counted_tcp) + 1) * per_transport + closed, Pool.receive_events_without_input_max(counted));
}
