//! The tests of the pool to one origin (`pool.zig`, `pool_events.zig`) with QUIC offered:
//! QUIC goes first, TCP opens after it fails or the fallback delay passes, the first handshake to
//! complete takes the exchanges, and an exchange refused by a draining connection moves. The h3
//! server of `quic_test_support.zig` answers in the same process, through
//! `pool_quic_test_support.zig`.
const std = @import("std");
const quic = @import("quic");
const h3 = @import("h3");
const connection_support = @import("../connection/connection_test_support.zig");
const quic_support = @import("../quic/quic_test_support.zig");
const quic_connection = @import("../quic/quic_connection.zig");
const fixture = @import("pool_quic_test_support.zig");
const pool_module = @import("pool.zig");
const pool_support = @import("pool_test_support.zig");
const pool_events = @import("pool_events.zig");
const event = @import("../event.zig");
const constants = @import("../constants.zig");

const testing = std.testing;
const Transport = pool_module.Transport;
const pool = &fixture.pool;
const bodies = &fixture.bodies;
const start = fixture.start;
const values_at = fixture.values_at;
const get = fixture.get;
const collect = fixture.collect;
const pump = fixture.pump;
const deliver = fixture.deliver;
const nth = fixture.nth;
const opened = fixture.opened;
const addresses = fixture.addresses;
const https_port = fixture.https_port;
const other_port = fixture.other_port;
const alternative_port = fixture.alternative_port;
const fallback_delay_ns = fixture.fallback_delay_ns;
const rounds_before_fallback = fixture.rounds_before_fallback;
const rounds_past_probe = fixture.rounds_past_probe;
const datagrams_per_round_max = fixture.datagrams_per_round_max;

test "RFC 9114 §3.1: with h3 offered, QUIC opens first and carries the exchange, and TCP never opens" {
    try start(&quic_support.alpn_h3, values_at(https_port), true);
    var exchange = get(&bodies[0]);
    const id = try pool.request(&exchange.request, &exchange.response);
    try collect();
    try testing.expectEqual(Transport.quic, opened(0).?.transport);
    try testing.expectEqual(https_port, opened(0).?.to.port);
    // RFC 9000 §9: the connection's datagrams go to the address and port the pool opened.
    const first = pool.send_datagram(&fixture.datagram, quic_support.now_ns).?;
    try testing.expect(first.to.eql(&opened(0).?.to));
    try quic_support.server_receive(@constCast(first.octets));
    try pump(quic_support.rounds_default);
    try testing.expectEqual(event.Protocol.h3, nth(.connected, 0).?.connected.protocol);
    try testing.expectEqual(id, nth(.finished, 0).?.finished.id);
    try testing.expectEqualStrings("hello", exchange.response.content_received());
    try testing.expectEqual(null, opened(1));
}

test "RFC 9114 §3.1: a QUIC handshake whose server speaks no h3 fails, and TCP opens" {
    try start(&quic_support.alpn_other, values_at(https_port), true);
    var exchange = get(&bodies[0]);
    _ = try pool.request(&exchange.request, &exchange.response);
    try collect();
    try pump(quic_support.rounds_default);
    try testing.expectEqual(Transport.tcp, opened(1).?.transport);
    try testing.expectEqual(pool_module.Phase.handshake, pool.phase(.tcp));
    try testing.expectEqual(.pending, exchange.response.outcome);
    // The fallback delay counts only while QUIC's handshake runs, and QUIC's failed.
    try pump(rounds_before_fallback);
    try testing.expect(!pool.fallback);
}

test "RFC 9114 §3.1: TCP opens beside a QUIC handshake once the fallback delay passes, and not before" {
    try start(&quic_support.alpn_h3, values_at(https_port), true);
    fixture.blocked = true;
    var exchange = get(&bodies[0]);
    _ = try pool.request(&exchange.request, &exchange.response);
    try collect();
    const fallback_at = quic_support.now_ns + fallback_delay_ns;
    try testing.expect(pool.deadline_ns().? <= fallback_at);
    try pump(rounds_before_fallback);
    try testing.expectEqual(fallback_at, pool.deadline_ns().?);
    quic_support.now_ns = fallback_at - 1;
    try collect();
    try testing.expectEqual(null, opened(1));
    quic_support.now_ns = fallback_at;
    pool.on_instant(fallback_at);
    try collect();
    try testing.expectEqual(Transport.tcp, opened(1).?.transport);
}

test "the first handshake to complete takes the exchange, and the transport still opening closes" {
    try start(&quic_support.alpn_h3, values_at(https_port), true);
    fixture.blocked = true;
    var exchange = get(&bodies[0]);
    _ = try pool.request(&exchange.request, &exchange.response);
    try collect();
    try pump(rounds_before_fallback + 1);
    try testing.expectEqual(Transport.tcp, opened(1).?.transport);
    // QUIC's datagrams get through before the test starts TCP, so QUIC's handshake completes first.
    fixture.blocked = false;
    try pump(rounds_past_probe);
    try testing.expectEqual(event.Protocol.h3, nth(.connected, 0).?.connected.protocol);
    try testing.expectEqual(pool_support.slot_of(pool, .tcp), nth(.close, 0).?.close.slot);
    try testing.expectEqual(pool_module.Phase.closed, pool.phase(.tcp));
    try testing.expectEqual(.response, exchange.response.outcome);
}

test "RFC 9114 §5.2: an exchange a GOAWAY left unprocessed moves, and TCP opens for it" {
    try start(&quic_support.alpn_h3, values_at(https_port), true);
    quic_support.server_answers = false;
    quic_support.server_streams_bidi = 1;
    var first = get(&bodies[0]);
    var second = get(&bodies[1]);
    _ = try pool.request(&first.request, &first.response);
    const second_id = try pool.request(&second.request, &second.response);
    try pump(quic_support.rounds_default);
    // The server took stream 0 alone, and the second exchange waits for its stream limit.
    try quic_support.server_h3.shutdown(&quic_support.server, quic_support.now_ns);
    try pump(quic_support.rounds_default);
    try testing.expectEqual(pool_module.Phase.draining, pool.phase(.quic));
    try testing.expectEqual(Transport.tcp, opened(1).?.transport);
    // RFC 9114 §4.1.1: the refused exchange is made again as though never sent, so no event
    // reports it, and its outcome is pending once more.
    for (fixture.events[0..fixture.events_len]) |reported| {
        if (reported == .finished) try testing.expect(reported.finished.id != second_id);
    }
    try testing.expectEqual(.pending, second.response.outcome);
    quic_support.server_answers = true;
    try pump(quic_support.rounds_default);
    try testing.expectEqual(.response, first.response.outcome);
}

test "RFC 9114 §4.1.1: a request an open connection rejects reaches the caller refused" {
    try start(&quic_support.alpn_h3, values_at(https_port), true);
    quic_support.server_answers = false;
    var exchange = get(&bodies[0]);
    _ = try pool.request(&exchange.request, &exchange.response);
    try pump(quic_support.rounds_default);
    quic_support.server_h3.cancel(&quic_support.server, 0, h3.constants.error_request_rejected);
    try pump(quic_support.rounds_default);
    try testing.expectEqual(.refused, exchange.response.outcome);
    try testing.expectEqual(&exchange.response, nth(.finished, 0).?.finished.response);
    try testing.expectEqual(&exchange.request, nth(.finished, 0).?.finished.request);
    try testing.expectEqual(null, opened(1));
}

test "RFC 9460 §7.1.2, §7.2: an HTTPS record's ALPN set chooses the transport, and its port applies" {
    const without_h3: pool_module.Values = .{ .addresses = &addresses, .port = https_port, .https = .{ .h3 = false, .port = other_port } };
    try start(&quic_support.alpn_h3, without_h3, true);
    var exchange = get(&bodies[0]);
    _ = try pool.request(&exchange.request, &exchange.response);
    try collect();
    try testing.expectEqual(Transport.tcp, opened(0).?.transport);
    try testing.expectEqual(other_port, opened(0).?.to.port);
    const with_h3: pool_module.Values = .{ .addresses = &addresses, .port = https_port, .https = .{ .h3 = true, .port = other_port } };
    try start(&quic_support.alpn_h3, with_h3, false);
    _ = try pool.request(&exchange.request, &exchange.response);
    try collect();
    try testing.expectEqual(Transport.quic, opened(0).?.transport);
    try testing.expectEqual(other_port, opened(0).?.to.port);
}

test "RFC 7838 §2.2: a fresh Alt-Svc alternative sends QUIC to its port first, and a stale one does not" {
    const fresh: pool_module.Values = .{ .addresses = &addresses, .port = https_port, .alternative = .{ .port = alternative_port, .fresh_until_ns = quic_support.start_ns + 1 } };
    try start(&quic_support.alpn_h3, fresh, false);
    var exchange = get(&bodies[0]);
    _ = try pool.request(&exchange.request, &exchange.response);
    try collect();
    try testing.expectEqual(Transport.quic, opened(0).?.transport);
    try testing.expectEqual(alternative_port, opened(0).?.to.port);
    const stale: pool_module.Values = .{ .addresses = &addresses, .port = https_port, .alternative = .{ .port = alternative_port, .fresh_until_ns = quic_support.start_ns } };
    try start(&quic_support.alpn_h3, stale, false);
    _ = try pool.request(&exchange.request, &exchange.response);
    try collect();
    try testing.expectEqual(Transport.tcp, opened(0).?.transport);
}

test "RFC 7838 §3.1: what Alt-Svc says replaces what the pool knew, fresh for its max-age" {
    try start(&quic_support.alpn_h3, values_at(https_port), false);
    const now_ns = quic_support.now_ns;
    const max_age_s: u64 = 60;
    pool_events.learn(pool, .{ .h3 = .{ .port = alternative_port, .max_age_s = max_age_s } }, now_ns);
    try testing.expectEqual(alternative_port, pool.alternative().?.port);
    try testing.expectEqual(now_ns + max_age_s * 1_000_000_000, pool.alternative().?.fresh_until_ns);
    try testing.expect(pool_events.quic_allowed(pool, now_ns));
    pool_events.learn(pool, .none, now_ns);
    try testing.expectEqual(null, pool.alternative());
    pool_events.learn(pool, .{ .h3 = .{ .port = alternative_port, .max_age_s = max_age_s } }, now_ns);
    pool_events.learn(pool, .clear, now_ns);
    try testing.expectEqual(null, pool.alternative());
}

test "decision 100: once every transport failed, each waiting exchange ends refused" {
    try start(&quic_support.alpn_other, values_at(https_port), true);
    var exchange = get(&bodies[0]);
    const id = try pool.request(&exchange.request, &exchange.response);
    try collect();
    try pump(quic_support.rounds_default);
    try testing.expectEqual(Transport.tcp, opened(1).?.transport);
    // The caller's TCP connection failed before its handshake began.
    pool.transport_closed(pool_support.connection_of(pool, .tcp));
    // RFC 9000 §10.2: the QUIC connection's closing or draining period runs before its transport
    // closes, and the pool gives up once both transports closed.
    try pump(rounds_past_probe * 4);
    try testing.expectEqual(id, nth(.finished, 0).?.finished.id);
    try testing.expectEqual(.refused, exchange.response.outcome);
}

/// The octets `start_quic` draws before the session's first draw: the grease value, then the two
/// connection IDs.
const grease_len: usize = @sizeOf(u64);
const id_len: usize = constants.quic_id_len;
const start_draw_len: usize = grease_len + id_len + id_len;

/// Requires `held` to be the next octets of `twin`, in the order decision 120 rules: the grease
/// value, its least significant octet first, then the source ID, then the original destination ID.
fn expect_drawn(twin: *connection_support.Stream, held: quic_connection.Start) !void {
    var drawn: [start_draw_len]u8 = undefined;
    twin.random().bytes(&drawn);
    try testing.expectEqual(std.mem.readInt(u64, drawn[0..grease_len], .little), held.grease);
    try testing.expectEqualSlices(u8, drawn[grease_len..][0..id_len], &held.source_id);
    try testing.expectEqualSlices(u8, drawn[grease_len + id_len ..], &held.original_destination_id);
}

test "decision 120: start_quic draws the grease value and the two IDs, anew for each connection" {
    try start(&quic_support.alpn_h3, values_at(https_port), true);
    var first = get(&bodies[0]);
    _ = try pool.request(&first.request, &first.response);
    // A twin of the source the pool draws from, at the state its first draw starts from.
    var twin: connection_support.Stream = .{ .state = connection_support.stream.state };
    try collect();
    const first_start = pool.quic.start_values;
    try expect_drawn(&twin, first_start);
    try pump(quic_support.rounds_default);
    try testing.expectEqual(.response, first.response.outcome);
    // The caller's flow closed, so the next exchange opens a second QUIC connection.
    pool.transport_closed(pool_support.connection_of(pool, .quic));
    try collect();
    var second = get(&bodies[1]);
    _ = try pool.request(&second.request, &second.response);
    twin.state = connection_support.stream.state;
    try collect();
    try testing.expectEqual(Transport.quic, opened(1).?.transport);
    const second_start = pool.quic.start_values;
    try expect_drawn(&twin, second_start);
    // RFC 9000 §5.1: a connection ID is not issued twice, so each connection draws its own.
    try testing.expect(!std.mem.eql(u8, &first_start.source_id, &second_start.source_id));
    try testing.expect(!std.mem.eql(u8, &first_start.original_destination_id, &second_start.original_destination_id));
    try pump(quic_support.rounds_default);
    try testing.expectEqual(.response, second.response.outcome);
}
