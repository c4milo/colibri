//! The tests of a channel's capacity (`channel.zig`, decision 124). A channel with no QUIC holds no
//! QUIC state, refuses `versions` that allow h3, and has no QUIC connection for a call to reach. A
//! call of its `start_quic` does not compile, so no test makes one. `client.Channel` holds QUIC.
//! The tests over TCP run on both types (`channel_test_support.zig`).
const std = @import("std");
const support = @import("../connection/connection_test_support.zig");
const tls_support = @import("../connection/connection_tls_test_support.zig");
const quic_connection = @import("../quic/quic_connection.zig");
const versions_module = @import("../versions.zig");
const channel_module = @import("channel.zig");

const testing = std.testing;
const Channel = channel_module.Channel;
const TcpAlone = channel_module.ChannelOf(.{ .quic = false });

/// The channel with no QUIC the tests drive, and its configuration, outside any stack frame.
/// Test-only.
var channel: TcpAlone align(@alignOf(TcpAlone)) = undefined;
var config: channel_module.Config align(@alignOf(channel_module.Config)) = undefined;
var body: [body_len]u8 = undefined;
const body_len: usize = 64;

const https_port: u16 = 443;
/// An IPv4 host, its four octets alike. Test-only.
const ipv4_len: usize = 4;
const host_octet: u8 = 0x7f;
const loopback: [ipv4_len]u8 = @splat(host_octet);
const addresses = [_]channel_module.Address{channel_module.Address.of(&loopback, 0)};
const values: channel_module.Values = .{ .addresses = &addresses, .port = https_port };

test "decision 124: client.Channel is a channel of the default capacity, which holds QUIC" {
    try testing.expect((channel_module.Capacity{}).quic);
    try testing.expect(Channel == channel_module.ChannelOf(.{ .quic = true }));
    try testing.expectEqual(quic_connection.QuicConnection, @FieldType(Channel, "quic"));
}

test "decision 124: a channel with no QUIC holds no QUIC connection and no QUIC TLS configuration" {
    inline for (.{ "quic", "quic_tls", "quic_config", "receive_pool" }) |name| {
        try testing.expectEqual(void, @FieldType(TcpAlone, name));
    }
    // The channel is smaller than the default one by at least the QUIC connection.
    try testing.expect(@sizeOf(TcpAlone) + @sizeOf(quic_connection.QuicConnection) <= @sizeOf(Channel));
}

test "RFC 9114 §3.1: a channel with no QUIC refuses versions that allow h3, in cleartext and over TLS" {
    const with_h3 = [_]versions_module.Versions{ .{}, .{ .h11 = false }, .{ .h2 = false }, .{ .h11 = false, .h2 = false } };
    for (with_h3) |versions| {
        config = .{ .authority = support.authority, .versions = versions };
        try testing.expectError(error.VersionUnavailable, channel.init(&config, values, null));
        config.tls = tls_support.client_values(support.authority);
        try testing.expectError(error.VersionUnavailable, channel.init(&config, values, null));
    }
    // With h3 off it offers TCP, and with no version at all it offers nothing (decision 117).
    config = .{ .authority = support.authority, .versions = .{ .h3 = false } };
    try channel.init(&config, values, null);
    try testing.expect(channel.offered.tcp and !channel.offered.quic);
    config.versions = .{ .h11 = false, .h2 = false, .h3 = false };
    try testing.expectError(error.NoVersion, channel.init(&config, values, null));
}

test "decision 124: a channel with no QUIC opens TCP for an origin that names h3, and has no QUIC connection" {
    config = .{ .tls = tls_support.client_values(support.authority), .versions = .{ .h3 = false }, .authority = support.authority };
    // RFC 9460 §7.1.2 and RFC 7838 §3: the record and Alt-Svc both name h3.
    var known = values;
    known.https = .{ .h3 = true };
    known.alternative = .{ .port = https_port, .fresh_until_ns = support.now_ns + 1 };
    try channel.init(&config, known, null);
    var exchange: support.Exchange = .{ .request = .{ .method = "GET", .path = "/" }, .response = .{ .body = &body } };
    _ = try channel.request(&exchange.request, &exchange.response);
    const opened = channel.receive(.none, support.now_ns).event.?.open;
    try testing.expectEqual(channel_module.Transport.tcp, opened.transport);
    // A datagram is dropped, no datagram is owed, and nothing names a QUIC connection.
    var octets: [ipv4_len]u8 = @splat(host_octet);
    const dropped = channel.receive(.{ .datagram = .{ .octets = &octets } }, support.now_ns);
    try testing.expectEqual(octets.len, dropped.consumed);
    try testing.expectEqual(null, dropped.event);
    try testing.expectEqual(null, channel.send_datagram(&body, support.now_ns));
    channel.transport_closed(.quic);
    channel.on_instant(support.now_ns);
    try testing.expectEqual(null, channel.take_ticket(.quic));
    try testing.expectEqual(channel_module.Phase.none, channel.phase(.quic));
    try testing.expectEqual(null, channel.deadline_ns());
    try channel.start_tcp(support.stream.random(), support.now_seconds, null);
    try testing.expectEqual(channel_module.Phase.handshake, channel.phase(.tcp));
    try testing.expect(channel.send_stream(&support.to_peer, support.now_ns) > 0);
}
