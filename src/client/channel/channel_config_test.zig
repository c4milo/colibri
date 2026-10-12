//! The tests of what a channel builds from its one configuration (`channel_config.zig`, decision
//! 120, design §8 step 21c.6b): which transports it offers, what it refuses to start from, and
//! the configuration each connection borrows. The channel and the h3 server are the ones of
//! `channel_quic_test_support.zig`.
const std = @import("std");
const http = @import("http");
const tls = @import("tls");
const support = @import("../connection/connection_test_support.zig");
const coding_support = @import("../coding_test_support.zig");
const quic_support = @import("../quic/quic_test_support.zig");
const fixture = @import("channel_quic_test_support.zig");
const channel_module = @import("channel.zig");
const event = @import("../event.zig");
const versions_module = @import("../versions.zig");

const testing = std.testing;
const Transport = channel_module.Transport;
const channel = &fixture.channel;
const bodies = &fixture.bodies;
const values_at = fixture.values_at;
const get = fixture.get;
const collect = fixture.collect;
const pump = fixture.pump;
const nth = fixture.nth;
const opened = fixture.opened;
const https_port = fixture.https_port;
const rounds_before_fallback = fixture.rounds_before_fallback;
const rounds_past_probe = fixture.rounds_past_probe;

/// The versions of a client that speaks h3 alone.
const h3_alone: versions_module.Versions = .{ .h11 = false, .h2 = false };

/// Whether `init` left `built` as the fixture filled it: no octet of it written.
fn unwritten(built: anytype) bool {
    return std.mem.allEqual(u8, std.mem.asBytes(built), fixture.unstarted_octet);
}

/// Starts a channel over `given` with the fixture's pool, makes one request, and requires the
/// channel to ask for TCP first and for no QUIC once the caller's TCP connection failed.
fn expect_tcp_alone(given: channel_module.Config, pool: ?channel_module.ReceiveStorage) !void {
    try fixture.start_configured(&quic_support.alpn_h3, values_at(https_port), given, pool);
    var exchange = get(&bodies[0]);
    _ = try channel.request(&exchange);
    try collect();
    try testing.expectEqual(Transport.tcp, opened(0).?.transport);
    channel.transport_closed(.tcp);
    try collect();
    try testing.expectEqual(.refused, exchange.outcome);
    try testing.expectEqual(null, opened(1));
    try testing.expectEqual(channel_module.Phase.none, channel.phase(.quic));
}

test "RFC 9114 §3.1.2: a channel in cleartext, with no pool, or with h3 off opens no QUIC" {
    // The fixture's configuration prefers QUIC, so each channel below would open it first.
    const cleartext: channel_module.Config = .{ .authority = support.authority };
    try expect_tcp_alone(cleartext, fixture.pool());
    try expect_tcp_alone(fixture.configured(true), null);
    var without_h3 = fixture.configured(true);
    without_h3.versions.h3 = false;
    try expect_tcp_alone(without_h3, fixture.pool());
}

test "RFC 9114 §3.1: a client that speaks h3 alone opens no TCP after QUIC fails, and names no fallback instant" {
    var given = fixture.configured(true);
    given.versions = h3_alone;
    // The server speaks no h3, so the QUIC handshake fails once its datagrams cross.
    try fixture.start_configured(&quic_support.alpn_other, values_at(https_port), given, fixture.pool());
    fixture.blocked = true;
    var exchange = get(&bodies[0]);
    const id = try channel.request(&exchange);
    try collect();
    try testing.expectEqual(Transport.quic, opened(0).?.transport);
    const fallback_at = quic_support.now_ns + fixture.fallback_delay_ns;
    try pump(rounds_before_fallback);
    // QUIC's own deadline is all the channel names: no TCP opens when the delay passes.
    try testing.expect(channel.deadline_ns().? != fallback_at);
    try pump(1);
    try testing.expect(quic_support.now_ns > fallback_at);
    try testing.expectEqual(null, opened(1));
    fixture.blocked = false;
    try pump(rounds_past_probe * 4);
    try testing.expectEqual(null, opened(1));
    try testing.expectEqual(id, nth(.finished, 0).?.finished.id);
    try testing.expectEqual(.refused, exchange.outcome);
    try testing.expectEqual(channel_module.Phase.none, channel.phase(.tcp));
}

test "decision 117: init refuses a configuration that offers neither transport" {
    var given = fixture.configured(true);
    given.versions = .{ .h11 = false, .h2 = false, .h3 = false };
    try testing.expectError(error.NoVersion, fixture.start_configured(&quic_support.alpn_h3, values_at(https_port), given, fixture.pool()));
    // RFC 9114 §3.1: h3 runs over QUIC alone, which a channel with no pool does not offer.
    given.versions = h3_alone;
    try testing.expectError(error.NoVersion, fixture.start_configured(&quic_support.alpn_h3, values_at(https_port), given, null));
    try fixture.start_configured(&quic_support.alpn_h3, values_at(https_port), given, fixture.pool());
}

test "RFC 9846 §4.5.1.3: init refuses more anchors than a TLS configuration holds" {
    const many: [tls.record.ClientConfig.anchors_max + 1]tls.Anchor = @splat(support.anchors[0]);
    var given = fixture.configured(true);
    given.tls.?.trust = .{ .web_pki = .{ .anchors = &many, .server_name = support.authority } };
    // With TCP alone, and with QUIC alone, whose configuration holds as many.
    try testing.expectError(error.TooManyAnchors, fixture.start_configured(&quic_support.alpn_h3, values_at(https_port), given, null));
    given.versions = h3_alone;
    try testing.expectError(error.TooManyAnchors, fixture.start_configured(&quic_support.alpn_h3, values_at(https_port), given, fixture.pool()));
}

test "decision 120: a channel whose values allow no transport ends each exchange refused, with nothing opened" {
    // h3 alone, and neither the configuration, an HTTPS record nor Alt-Svc says to try QUIC.
    var given = fixture.configured(false);
    given.versions = h3_alone;
    try fixture.start_configured(&quic_support.alpn_h3, values_at(https_port), given, fixture.pool());
    var exchange = get(&bodies[0]);
    const id = try channel.request(&exchange);
    const first = channel.receive(.none, quic_support.now_ns);
    try testing.expectEqual(id, first.event.?.finished.id);
    try testing.expectEqual(.refused, exchange.outcome);
    try collect();
    try testing.expectEqual(null, opened(0));
}

const codings = [_]http.content_coding.Coding{ .br, .zstd, .gzip };
/// An idle timeout other than the default, in milliseconds.
const idle_timeout_ms: u64 = 10_000;

test "decision 120: a QUIC connection gets the authority, ECN, the idle timeout, the codings and each pool" {
    const storage = support.pool.storage();
    storage.reset(.none());
    coding_support.reset_pools();
    var given = fixture.configured(true);
    given.ecn = true;
    given.idle_timeout_ms = idle_timeout_ms;
    given.codings = &codings;
    given.decoders = storage;
    given.zstd_decoders = coding_support.zstd_pool.storage();
    given.br_decoders = coding_support.br_pool.storage();
    try fixture.start_configured(&quic_support.alpn_h3, values_at(https_port), given, fixture.pool());
    const built = &channel.quic_config;
    try testing.expectEqual(&channel.quic_tls, built.tls);
    try testing.expectEqualStrings(support.authority, built.authority);
    try testing.expect(built.ecn);
    try testing.expectEqual(idle_timeout_ms, built.idle_timeout_ms);
    try testing.expectEqualSlices(http.content_coding.Coding, &codings, built.codings);
    try testing.expect(built.decoders != null and built.zstd_decoders != null and built.br_decoders != null);
    // The TCP connection borrows the same, and the TLS configuration built for it.
    const tcp = &channel.tcp_config;
    try testing.expectEqual(&channel.tcp_tls, tcp.tls.?);
    try testing.expectEqualStrings(support.authority, tcp.authority);
    try testing.expectEqualSlices(http.content_coding.Coding, &codings, tcp.codings);
    try testing.expect(tcp.decoders != null and tcp.zstd_decoders != null and tcp.br_decoders != null);
    // A channel that offers br, zstd and gzip starts its QUIC connection, which carries an
    // exchange.
    var exchange = get(&bodies[0]);
    _ = try channel.request(&exchange);
    try pump(quic_support.rounds_default);
    try testing.expectEqual(event.Protocol.h3, nth(.connected, 0).?.connected);
    try testing.expectEqual(.response, exchange.outcome);
    try testing.expectEqual(idle_timeout_ms, quic_support.server.peer_parameters.?.max_idle_timeout_ms);
}

test "decision 120: init converts no TLS value for a transport the channel does not offer" {
    // In cleartext neither TLS configuration is written, and QUIC's connections borrow nothing.
    const cleartext: channel_module.Config = .{ .authority = support.authority };
    try fixture.start_configured(&quic_support.alpn_h3, values_at(https_port), cleartext, fixture.pool());
    try testing.expect(unwritten(&channel.tcp_tls) and unwritten(&channel.quic_tls) and unwritten(&channel.quic_config));
    try testing.expectEqual(null, channel.tcp_config.tls);
    // Over TLS with TCP alone, QUIC's is not written.
    try fixture.start_configured(&quic_support.alpn_h3, values_at(https_port), fixture.configured(true), null);
    try testing.expect(!unwritten(&channel.tcp_tls));
    try testing.expect(unwritten(&channel.quic_tls) and unwritten(&channel.quic_config));
    // With h3 alone, TCP's is not written.
    var given = fixture.configured(true);
    given.versions = h3_alone;
    try fixture.start_configured(&quic_support.alpn_h3, values_at(https_port), given, fixture.pool());
    try testing.expect(!unwritten(&channel.quic_tls) and !unwritten(&channel.quic_config));
    try testing.expect(unwritten(&channel.tcp_tls) and unwritten(&channel.tcp_config));
}
