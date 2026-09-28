//! The tests of the channel to one origin (`channel.zig`, `channel_events.zig`) with QUIC offered:
//! QUIC goes first, TCP opens after it fails or the fallback delay passes, the first handshake to
//! complete takes the exchanges, and an exchange refused by a draining connection moves. The h3
//! server of `quic_test_support.zig` answers in the same process, through
//! `channel_quic_test_support.zig`.
const std = @import("std");
const quic = @import("quic");
const h3 = @import("h3");
const quic_support = @import("quic_test_support.zig");
const fixture = @import("channel_quic_test_support.zig");
const channel_module = @import("channel.zig");
const event = @import("event.zig");

const testing = std.testing;
const Transport = channel_module.Transport;
const channel = &fixture.channel;
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
    const id = try channel.request(&exchange);
    try collect();
    try testing.expectEqual(Transport.quic, opened(0).?.transport);
    try testing.expectEqual(https_port, opened(0).?.to.port);
    // RFC 9000 §9: the connection's datagrams go to the address and port the channel opened.
    const first = channel.send_datagram(&fixture.datagram, quic_support.now_ns).?;
    try testing.expect(first.to.eql(&opened(0).?.to));
    try quic_support.server_receive(@constCast(first.octets));
    try pump(quic_support.rounds_default);
    try testing.expectEqual(event.Protocol.h3, nth(.connected, 0).?.connected);
    try testing.expectEqual(id, nth(.finished, 0).?.finished.id);
    try testing.expectEqualStrings("hello", exchange.content_received());
    try testing.expectEqual(null, opened(1));
}

test "RFC 9114 §3.1: a QUIC handshake that selects no h3 fails, and TCP opens" {
    const offered = [_][]const u8{ "hq-interop", "h3" };
    try start(&quic_support.alpn_other, values_at(https_port), true);
    try quic_support.prepare(&offered, &quic_support.alpn_other, false);
    var exchange = get(&bodies[0]);
    _ = try channel.request(&exchange);
    try collect();
    try pump(quic_support.rounds_default);
    try testing.expectEqual(Transport.tcp, opened(1).?.transport);
    try testing.expectEqual(channel_module.Phase.handshake, channel.phase(.tcp));
    try testing.expectEqual(.pending, exchange.outcome);
    // The fallback delay counts only while QUIC's handshake runs, and QUIC's failed.
    try pump(rounds_before_fallback);
    try testing.expect(!channel.fallback);
}

test "RFC 9114 §3.1: TCP opens beside a QUIC handshake once the fallback delay passes, and not before" {
    try start(&quic_support.alpn_h3, values_at(https_port), true);
    fixture.blocked = true;
    var exchange = get(&bodies[0]);
    _ = try channel.request(&exchange);
    try collect();
    const fallback_at = quic_support.now_ns + fallback_delay_ns;
    try testing.expect(channel.deadline_ns().? <= fallback_at);
    try pump(rounds_before_fallback);
    try testing.expectEqual(fallback_at, channel.deadline_ns().?);
    quic_support.now_ns = fallback_at - 1;
    try collect();
    try testing.expectEqual(null, opened(1));
    quic_support.now_ns = fallback_at;
    channel.on_instant(fallback_at);
    try collect();
    try testing.expectEqual(Transport.tcp, opened(1).?.transport);
}

test "the first handshake to complete takes the exchange, and the transport still opening closes" {
    try start(&quic_support.alpn_h3, values_at(https_port), true);
    fixture.blocked = true;
    var exchange = get(&bodies[0]);
    _ = try channel.request(&exchange);
    try collect();
    try pump(rounds_before_fallback + 1);
    try testing.expectEqual(Transport.tcp, opened(1).?.transport);
    // QUIC's datagrams get through before the test starts TCP, so QUIC's handshake completes first.
    fixture.blocked = false;
    try pump(rounds_past_probe);
    try testing.expectEqual(event.Protocol.h3, nth(.connected, 0).?.connected);
    try testing.expectEqual(Transport.tcp, nth(.close, 0).?.close);
    try testing.expectEqual(channel_module.Phase.closed, channel.phase(.tcp));
    try testing.expectEqual(.response, exchange.outcome);
}

test "RFC 9114 §5.2: an exchange a GOAWAY left unprocessed moves, and TCP opens for it" {
    try start(&quic_support.alpn_h3, values_at(https_port), true);
    quic_support.server_answers = false;
    quic_support.server_streams_bidi = 1;
    var first = get(&bodies[0]);
    var second = get(&bodies[1]);
    _ = try channel.request(&first);
    const second_id = try channel.request(&second);
    try pump(quic_support.rounds_default);
    // The server took stream 0 alone, and the second exchange waits for its stream limit.
    try quic_support.server_h3.shutdown(&quic_support.server, quic_support.now_ns);
    try pump(quic_support.rounds_default);
    try testing.expectEqual(channel_module.Phase.draining, channel.phase(.quic));
    try testing.expectEqual(Transport.tcp, opened(1).?.transport);
    // RFC 9114 §4.1.1: the refused exchange is made again as though never sent, so no event
    // reports it, and its outcome is pending once more.
    for (fixture.events[0..fixture.events_len]) |reported| {
        if (reported == .finished) try testing.expect(reported.finished.id != second_id);
    }
    try testing.expectEqual(.pending, second.outcome);
    quic_support.server_answers = true;
    try pump(quic_support.rounds_default);
    try testing.expectEqual(.response, first.outcome);
}

test "RFC 9114 §4.1.1: a request an open connection rejects reaches the caller refused" {
    try start(&quic_support.alpn_h3, values_at(https_port), true);
    quic_support.server_answers = false;
    var exchange = get(&bodies[0]);
    _ = try channel.request(&exchange);
    try pump(quic_support.rounds_default);
    quic_support.server_h3.cancel(&quic_support.server, 0, h3.constants.error_request_rejected);
    try pump(quic_support.rounds_default);
    try testing.expectEqual(.refused, exchange.outcome);
    try testing.expectEqual(&exchange, nth(.finished, 0).?.finished.exchange);
    try testing.expectEqual(null, opened(1));
}

test "RFC 9460 §7.1.2, §7.2: an HTTPS record's ALPN set chooses the transport, and its port applies" {
    const without_h3: channel_module.Values = .{ .addresses = &addresses, .port = https_port, .https = .{ .h3 = false, .port = other_port } };
    try start(&quic_support.alpn_h3, without_h3, true);
    var exchange = get(&bodies[0]);
    _ = try channel.request(&exchange);
    try collect();
    try testing.expectEqual(Transport.tcp, opened(0).?.transport);
    try testing.expectEqual(other_port, opened(0).?.to.port);
    const with_h3: channel_module.Values = .{ .addresses = &addresses, .port = https_port, .https = .{ .h3 = true, .port = other_port } };
    try start(&quic_support.alpn_h3, with_h3, false);
    _ = try channel.request(&exchange);
    try collect();
    try testing.expectEqual(Transport.quic, opened(0).?.transport);
    try testing.expectEqual(other_port, opened(0).?.to.port);
}

test "RFC 7838 §2.2: a fresh Alt-Svc alternative sends QUIC to its port first, and a stale one does not" {
    const fresh: channel_module.Values = .{ .addresses = &addresses, .port = https_port, .alternative = .{ .port = alternative_port, .fresh_until_ns = quic_support.start_ns + 1 } };
    try start(&quic_support.alpn_h3, fresh, false);
    var exchange = get(&bodies[0]);
    _ = try channel.request(&exchange);
    try collect();
    try testing.expectEqual(Transport.quic, opened(0).?.transport);
    try testing.expectEqual(alternative_port, opened(0).?.to.port);
    const stale: channel_module.Values = .{ .addresses = &addresses, .port = https_port, .alternative = .{ .port = alternative_port, .fresh_until_ns = quic_support.start_ns } };
    try start(&quic_support.alpn_h3, stale, false);
    _ = try channel.request(&exchange);
    try collect();
    try testing.expectEqual(Transport.tcp, opened(0).?.transport);
}

test "RFC 7838 §3.1: what Alt-Svc says replaces what the channel knew, fresh for its max-age" {
    try start(&quic_support.alpn_h3, values_at(https_port), false);
    const now_ns = quic_support.now_ns;
    const max_age_s: u64 = 60;
    channel.learn(.{ .h3 = .{ .port = alternative_port, .max_age_s = max_age_s } }, now_ns);
    try testing.expectEqual(alternative_port, channel.alternative().?.port);
    try testing.expectEqual(now_ns + max_age_s * 1_000_000_000, channel.alternative().?.fresh_until_ns);
    try testing.expect(channel.quic_allowed(now_ns));
    channel.learn(.none, now_ns);
    try testing.expectEqual(null, channel.alternative());
    channel.learn(.{ .h3 = .{ .port = alternative_port, .max_age_s = max_age_s } }, now_ns);
    channel.learn(.clear, now_ns);
    try testing.expectEqual(null, channel.alternative());
}

test "decision 100: once every transport failed, each waiting exchange ends refused" {
    const offered = [_][]const u8{ "hq-interop", "h3" };
    try start(&quic_support.alpn_other, values_at(https_port), true);
    try quic_support.prepare(&offered, &quic_support.alpn_other, false);
    var exchange = get(&bodies[0]);
    const id = try channel.request(&exchange);
    try collect();
    try pump(quic_support.rounds_default);
    try testing.expectEqual(Transport.tcp, opened(1).?.transport);
    // The caller's TCP connection failed before its handshake began.
    channel.transport_closed(.tcp);
    try pump(quic_support.rounds_default);
    try testing.expectEqual(id, nth(.finished, 0).?.finished.id);
    try testing.expectEqual(.refused, exchange.outcome);
}
