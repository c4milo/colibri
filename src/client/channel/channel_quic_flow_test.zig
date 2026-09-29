//! More tests of the channel to one origin with QUIC offered (`channel.zig`, `channel_events.zig`):
//! what a cancel, a transport the caller closed, a second refusal, a ticket and a shutdown leave.
//! Split out of `channel_quic_test.zig` for length.
const std = @import("std");
const quic = @import("quic");
const h3 = @import("h3");
const quic_support = @import("../quic/quic_test_support.zig");
const fixture = @import("channel_quic_test_support.zig");
const channel_module = @import("channel.zig");
const event = @import("../event.zig");
const constants = @import("../constants.zig");

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

test "RFC 9114 §4.1.1: a cancelled exchange a connection carries reports nothing, though its server answers" {
    try start(&quic_support.alpn_h3, values_at(https_port), true);
    quic_support.server_answers = false;
    var exchange = get(&bodies[0]);
    const id = try channel.request(&exchange);
    try pump(quic_support.rounds_default);
    channel.cancel(id);
    quic_support.server_answers = true;
    try pump(quic_support.rounds_default);
    try testing.expectEqual(null, nth(.finished, 0));
    try testing.expectEqual(.pending, exchange.outcome);
}

test "RFC 9000 §10: a QUIC transport the caller closed ends its written exchange closed, and asks for no close" {
    try start(&quic_support.alpn_h3, values_at(https_port), true);
    quic_support.server_answers = false;
    var exchange = get(&bodies[0]);
    _ = try channel.request(&exchange);
    try pump(quic_support.rounds_default);
    channel.transport_closed(.quic);
    try collect();
    try testing.expectEqual(.closed, exchange.outcome);
    try testing.expectEqual(&exchange, nth(.finished, 0).?.finished.exchange);
    try testing.expectEqual(null, nth(.close, 0));
    try testing.expectEqual(channel_module.Phase.closed, channel.phase(.quic));
}

test "RFC 9114 §4.1.1: a QUIC transport the caller closed moves the exchange it had not written" {
    try start(&quic_support.alpn_h3, values_at(https_port), true);
    quic_support.server_answers = false;
    quic_support.server_streams_bidi = 1;
    var first = get(&bodies[0]);
    var second = get(&bodies[1]);
    _ = try channel.request(&first);
    _ = try channel.request(&second);
    try pump(quic_support.rounds_default);
    // The second exchange waits for the server's stream limit, unwritten, when the flow closes.
    channel.transport_closed(.quic);
    try collect();
    try testing.expectEqual(.closed, first.outcome);
    try testing.expectEqual(&first, nth(.finished, 0).?.finished.exchange);
    try testing.expectEqual(null, nth(.finished, 1));
    try testing.expectEqual(.pending, second.outcome);
    try testing.expectEqual(Transport.tcp, opened(1).?.transport);
}

test "RFC 9114 §4.1.1: an exchange a second draining connection refuses has moved once, and reaches the caller" {
    try start(&quic_support.alpn_h3, values_at(https_port), true);
    quic_support.server_answers = false;
    quic_support.server_streams_bidi = 1;
    var first = get(&bodies[0]);
    var second = get(&bodies[1]);
    _ = try channel.request(&first);
    const second_id = try channel.request(&second);
    try pump(quic_support.rounds_default);
    // The GOAWAY refuses the second exchange, waiting for its stream, which moves once. TCP opens
    // for it, and the caller's TCP connection fails before it starts.
    try quic_support.server_h3.shutdown(&quic_support.server, quic_support.now_ns);
    try pump(quic_support.rounds_default);
    try testing.expectEqual(Transport.tcp, opened(1).?.transport);
    channel.transport_closed(.tcp);
    // The first exchange ends, and its connection closes. A second QUIC connection opens, whose
    // server grants no stream, so the second exchange waits on it too.
    quic_support.server_answers = true;
    quic_support.server_streams_bidi = 0;
    try pump(rounds_past_probe);
    try testing.expectEqual(.response, first.outcome);
    try testing.expectEqual(Transport.quic, opened(2).?.transport);
    try testing.expectEqual(channel_module.Phase.open, channel.phase(.quic));
    // RFC 9113 §8.7: a second refusal goes to the caller, who may make the request again.
    try quic_support.server_h3.shutdown(&quic_support.server, quic_support.now_ns);
    try pump(quic_support.rounds_default);
    try testing.expectEqual(second_id, nth(.finished, 1).?.finished.id);
    try testing.expectEqual(.refused, second.outcome);
}

test "RFC 9846 §4.6.1: a QUIC ticket is reported for its transport, and take_ticket hands it over once" {
    try start(&quic_support.alpn_h3, values_at(https_port), true);
    try quic_support.prepare(&quic_support.alpn_h3, &quic_support.alpn_h3, true);
    var exchange = get(&bodies[0]);
    _ = try channel.request(&exchange);
    try pump(quic_support.rounds_default);
    try testing.expectEqual(Transport.quic, nth(.ticket, 0).?.ticket);
    var ticket = channel.take_ticket(.quic) orelse return error.TestUnexpectedResult;
    defer ticket.wipe();
    try testing.expectEqual(null, channel.take_ticket(.quic));
    try testing.expectEqual(null, channel.take_ticket(.tcp));
}

test "RFC 7838 §3: TCP goes to the origin's port though QUIC went to the alternative's" {
    const offered = [_][]const u8{ "hq-interop", "h3" };
    const fresh: channel_module.Values = .{ .addresses = &addresses, .port = https_port, .alternative = .{ .port = alternative_port, .fresh_until_ns = std.math.maxInt(u64) } };
    try start(&quic_support.alpn_other, fresh, false);
    try quic_support.prepare(&offered, &quic_support.alpn_other, false);
    var exchange = get(&bodies[0]);
    _ = try channel.request(&exchange);
    try collect();
    try testing.expectEqual(alternative_port, opened(0).?.to.port);
    try pump(quic_support.rounds_default);
    try testing.expectEqual(Transport.tcp, opened(1).?.transport);
    try testing.expectEqual(https_port, opened(1).?.to.port);
}

test "a shut-down channel ends a handshake no exchange waits for, and closes" {
    try start(&quic_support.alpn_h3, values_at(https_port), true);
    fixture.blocked = true;
    var exchange = get(&bodies[0]);
    const id = try channel.request(&exchange);
    try collect();
    try testing.expectEqual(channel_module.Phase.handshake, channel.phase(.quic));
    channel.cancel(id);
    channel.shutdown();
    try collect();
    // RFC 9000 §10.2: the abandoned connection owes its CONNECTION_CLOSE, then runs its closing
    // period, and the channel closes after it.
    try testing.expectEqual(channel_module.Phase.failed, channel.phase(.quic));
    try pump(rounds_past_probe * 4);
    try testing.expectEqual(Transport.quic, nth(.close, 0).?.close);
    try testing.expect(nth(.closed, 0) != null);
}

test "a shut-down channel keeps a handshake while it holds an exchange, which could come back refused" {
    try start(&quic_support.alpn_h3, values_at(https_port), true);
    quic_support.server_answers = false;
    var first = get(&bodies[0]);
    _ = try channel.request(&first);
    try pump(quic_support.rounds_default);
    // RFC 9114 §5.2: the GOAWAY names stream 4, so the first exchange stays, and the connection
    // takes no second one, which waits for TCP.
    try quic_support.server_h3.shutdown(&quic_support.server, quic_support.now_ns);
    try pump(quic_support.rounds_default);
    var second = get(&bodies[1]);
    const second_id = try channel.request(&second);
    try collect();
    try testing.expectEqual(Transport.tcp, opened(1).?.transport);
    channel.shutdown();
    channel.cancel(second_id);
    try collect();
    try testing.expectEqual(channel_module.Phase.handshake, channel.phase(.tcp));
    // Once the first exchange ends, the channel holds none, and the handshake ends.
    quic_support.server_answers = true;
    try pump(quic_support.rounds_default);
    try testing.expectEqual(.response, first.outcome);
    try testing.expectEqual(Transport.tcp, nth(.close, 0).?.close);
}

/// The server's datagrams a test holds back before it delivers them. Test-only.
var withheld: [withheld_max][quic.constants.datagram_len_max]u8 = undefined;
var withheld_lens: [withheld_max]usize = undefined;
const withheld_max: usize = 8;

test "RFC 9000 §10.2: a handshake the channel abandoned carries nothing, though datagrams in flight complete it" {
    try start(&quic_support.alpn_h3, values_at(https_port), true);
    var exchange = get(&bodies[0]);
    const id = try channel.request(&exchange);
    try collect();
    // The client's Initial reaches the server, and the server's flight is held back.
    for (0..datagrams_per_round_max) |_| {
        const sent = channel.send_datagram(&fixture.datagram, quic_support.now_ns) orelse break;
        @memcpy(fixture.crossing[0..sent.octets.len], sent.octets);
        try quic_support.server_receive(fixture.crossing[0..sent.octets.len]);
    }
    var withheld_count: usize = 0;
    for (0..withheld_max) |_| {
        const len = (try quic_support.server_send(&withheld[withheld_count])) orelse break;
        withheld_lens[withheld_count] = len;
        withheld_count += 1;
    }
    try testing.expect(withheld_count > 0);
    // The shut-down channel holds nothing, so it abandons the handshake, which owes its
    // CONNECTION_CLOSE and has not sent it.
    channel.cancel(id);
    channel.shutdown();
    try collect();
    try testing.expectEqual(channel_module.Phase.failed, channel.phase(.quic));
    for (withheld[0..withheld_count], withheld_lens[0..withheld_count]) |*octets, len| try deliver(octets[0..len]);
    try collect();
    try testing.expect(channel.quic.transport.handshake_complete);
    try testing.expectEqual(null, nth(.connected, 0));
}

test "a cancelled exchange leaves nothing to open" {
    try start(&quic_support.alpn_h3, values_at(https_port), true);
    var exchange = get(&bodies[0]);
    const id = try channel.request(&exchange);
    channel.cancel(id);
    try collect();
    try testing.expectEqual(null, opened(0));
}

/// Rounds that run past a closing period, three times the Probe Timeout (RFC 9000 §10.2).
const closing_rounds: usize = 128;

test "RFC 9114 §5.1: a QUIC connection idle near its timeout closes, and the next exchange opens a new one" {
    try start(&quic_support.alpn_h3, values_at(https_port), true);
    var first = get(&bodies[0]);
    _ = try channel.request(&first);
    try collect();
    try pump(quic_support.rounds_default);
    try testing.expectEqual(.response, first.outcome);
    // Holding no exchange, the connection retires at its idle deadline less the 1 s margin.
    const acts_at = quic.connection_idle.deadline_ns(&channel.quic.transport).? - constants.quic_idle_margin_ns_min;
    try testing.expect(channel.deadline_ns().? <= acts_at);
    quic_support.now_ns = acts_at;
    channel.on_instant(acts_at);
    try collect();
    try testing.expect(channel.quic.retired);
    try testing.expectEqual(.draining, channel.phase(.quic));
    // It closes with H3_NO_ERROR, and once its closing period has run the channel asks the caller
    // to close its flow.
    try pump(closing_rounds);
    try testing.expectEqual(Transport.quic, nth(.close, 0).?.close);
    try testing.expectEqual(.closed, channel.phase(.quic));
    // The next exchange opens a new QUIC connection, which carries it, and TCP never opens.
    var second = get(&bodies[1]);
    _ = try channel.request(&second);
    try collect();
    try testing.expectEqual(Transport.quic, opened(1).?.transport);
    try pump(quic_support.rounds_default);
    try testing.expectEqual(.response, second.outcome);
    try testing.expectEqual(null, opened(2));
}
