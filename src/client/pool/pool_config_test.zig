//! The tests of what a pool builds from its one configuration (`pool_config.zig`, decision
//! 120, design §8 step 21c.6b): which transports it offers, what it refuses to start from, and
//! the configuration each connection borrows. The pool and the h3 server are the ones of
//! `pool_quic_test_support.zig`.
const std = @import("std");
const http = @import("http");
const tls = @import("tls");
const support = @import("../connection/connection_test_support.zig");
const coding_support = @import("../coding_test_support.zig");
const quic_support = @import("../quic/quic_test_support.zig");
const fixture = @import("pool_quic_test_support.zig");
const pool_module = @import("pool.zig");
const event = @import("../event.zig");
const versions_module = @import("../versions.zig");

const testing = std.testing;
const Transport = pool_module.Transport;
const pool = &fixture.pool;
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

/// Starts a pool over `given` with the receive pool `receive_storage`, makes one request, and
/// requires the pool to ask for TCP first and for no QUIC once the caller's TCP connection failed.
fn expect_tcp_alone(given: pool_module.Config, receive_storage: ?pool_module.ReceiveStorage) !void {
    try fixture.start_configured(&quic_support.alpn_h3, values_at(https_port), given, receive_storage);
    var exchange = get(&bodies[0]);
    _ = try pool.request(&exchange.request, &exchange.response);
    try collect();
    try testing.expectEqual(Transport.tcp, opened(0).?.transport);
    pool.transport_closed(.tcp);
    try collect();
    try testing.expectEqual(.refused, exchange.response.outcome);
    try testing.expectEqual(null, opened(1));
    try testing.expectEqual(pool_module.Phase.none, pool.phase(.quic));
}

test "RFC 9114 §3.1.2: a pool in cleartext, with no receive pool, or with h3 off opens no QUIC" {
    // The fixture's configuration prefers QUIC, so each pool below would open it first.
    const cleartext: pool_module.Config = .{ .authority = support.authority };
    try expect_tcp_alone(cleartext, fixture.receive_storage());
    try expect_tcp_alone(fixture.configured(true), null);
    var without_h3 = fixture.configured(true);
    without_h3.versions.h3 = false;
    try expect_tcp_alone(without_h3, fixture.receive_storage());
}

test "RFC 9114 §3.1: a client that speaks h3 alone opens no TCP after QUIC fails, and names no fallback instant" {
    var given = fixture.configured(true);
    given.versions = h3_alone;
    // The server speaks no h3, so the QUIC handshake fails once its datagrams cross.
    try fixture.start_configured(&quic_support.alpn_other, values_at(https_port), given, fixture.receive_storage());
    fixture.blocked = true;
    var exchange = get(&bodies[0]);
    const id = try pool.request(&exchange.request, &exchange.response);
    try collect();
    try testing.expectEqual(Transport.quic, opened(0).?.transport);
    const fallback_at = quic_support.now_ns + fixture.fallback_delay_ns;
    try pump(rounds_before_fallback);
    // QUIC's own deadline is all the pool names: no TCP opens when the delay passes.
    try testing.expect(pool.deadline_ns().? != fallback_at);
    try pump(1);
    try testing.expect(quic_support.now_ns > fallback_at);
    try testing.expectEqual(null, opened(1));
    fixture.blocked = false;
    try pump(rounds_past_probe * 4);
    try testing.expectEqual(null, opened(1));
    try testing.expectEqual(id, nth(.finished, 0).?.finished.id);
    try testing.expectEqual(.refused, exchange.response.outcome);
    try testing.expectEqual(pool_module.Phase.none, pool.phase(.tcp));
}

test "decision 117: init refuses a configuration that offers neither transport" {
    var given = fixture.configured(true);
    given.versions = .{ .h11 = false, .h2 = false, .h3 = false };
    try testing.expectError(error.NoVersion, fixture.start_configured(&quic_support.alpn_h3, values_at(https_port), given, fixture.receive_storage()));
    // RFC 9114 §3.1: h3 runs over QUIC alone, which a pool with no receive pool does not offer.
    given.versions = h3_alone;
    try testing.expectError(error.NoVersion, fixture.start_configured(&quic_support.alpn_h3, values_at(https_port), given, null));
    try fixture.start_configured(&quic_support.alpn_h3, values_at(https_port), given, fixture.receive_storage());
}

test "RFC 9846 §4.5.1.3: init refuses more anchors than a TLS configuration holds" {
    const many: [tls.record.ClientConfig.anchors_max + 1]tls.Anchor = @splat(support.anchors[0]);
    var given = fixture.configured(true);
    given.tls.?.trust = .{ .web_pki = .{ .anchors = &many, .server_name = support.authority } };
    // With TCP alone, and with QUIC alone, whose configuration holds as many.
    try testing.expectError(error.TooManyAnchors, fixture.start_configured(&quic_support.alpn_h3, values_at(https_port), given, null));
    given.versions = h3_alone;
    try testing.expectError(error.TooManyAnchors, fixture.start_configured(&quic_support.alpn_h3, values_at(https_port), given, fixture.receive_storage()));
}

test "decision 120: a pool whose values allow no transport ends each exchange refused, with nothing opened" {
    // h3 alone, and neither the configuration, an HTTPS record nor Alt-Svc says to try QUIC.
    var given = fixture.configured(false);
    given.versions = h3_alone;
    try fixture.start_configured(&quic_support.alpn_h3, values_at(https_port), given, fixture.receive_storage());
    var exchange = get(&bodies[0]);
    const id = try pool.request(&exchange.request, &exchange.response);
    const first = pool.receive(.none, quic_support.now_ns);
    try testing.expectEqual(id, first.event.?.finished.id);
    try testing.expectEqual(.refused, exchange.response.outcome);
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
    try fixture.start_configured(&quic_support.alpn_h3, values_at(https_port), given, fixture.receive_storage());
    const built = &pool.quic_config;
    try testing.expectEqual(&pool.quic_tls, built.tls);
    try testing.expectEqualStrings(support.authority, built.authority);
    try testing.expect(built.ecn);
    try testing.expectEqual(idle_timeout_ms, built.idle_timeout_ms);
    try testing.expectEqualSlices(http.content_coding.Coding, &codings, built.codings);
    try testing.expect(built.decoders != null and built.zstd_decoders != null and built.br_decoders != null);
    // The TCP connection borrows the same, and the TLS configuration built for it.
    const tcp = &pool.tcp_config;
    try testing.expectEqual(&pool.tcp_tls, tcp.tls.?);
    try testing.expectEqualStrings(support.authority, tcp.authority);
    try testing.expectEqualSlices(http.content_coding.Coding, &codings, tcp.codings);
    try testing.expect(tcp.decoders != null and tcp.zstd_decoders != null and tcp.br_decoders != null);
    // A pool that offers br, zstd and gzip starts its QUIC connection, which carries an
    // exchange.
    var exchange = get(&bodies[0]);
    _ = try pool.request(&exchange.request, &exchange.response);
    try pump(quic_support.rounds_default);
    try testing.expectEqual(event.Protocol.h3, nth(.connected, 0).?.connected);
    try testing.expectEqual(.response, exchange.response.outcome);
    try testing.expectEqual(idle_timeout_ms, quic_support.server.peer_parameters.?.max_idle_timeout_ms);
}

test "decision 120: init converts no TLS value for a transport the pool does not offer" {
    // In cleartext neither TLS configuration is written, and QUIC's connections borrow nothing.
    const cleartext: pool_module.Config = .{ .authority = support.authority };
    try fixture.start_configured(&quic_support.alpn_h3, values_at(https_port), cleartext, fixture.receive_storage());
    try testing.expect(unwritten(&pool.tcp_tls) and unwritten(&pool.quic_tls) and unwritten(&pool.quic_config));
    try testing.expectEqual(null, pool.tcp_config.tls);
    // Over TLS with TCP alone, QUIC's is not written.
    try fixture.start_configured(&quic_support.alpn_h3, values_at(https_port), fixture.configured(true), null);
    try testing.expect(!unwritten(&pool.tcp_tls));
    try testing.expect(unwritten(&pool.quic_tls) and unwritten(&pool.quic_config));
    // With h3 alone, TCP's is not written.
    var given = fixture.configured(true);
    given.versions = h3_alone;
    try fixture.start_configured(&quic_support.alpn_h3, values_at(https_port), given, fixture.receive_storage());
    try testing.expect(!unwritten(&pool.quic_tls) and !unwritten(&pool.quic_config));
    try testing.expect(unwritten(&pool.tcp_tls) and unwritten(&pool.tcp_config));
}
