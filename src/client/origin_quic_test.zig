//! The tests of the client for one origin (`origin.zig`, `origin_events.zig`) with QUIC offered:
//! QUIC goes first, TCP opens after it fails or the fallback delay passes, the first handshake to
//! complete takes the exchanges, and an exchange refused by a draining connection moves. The h3
//! server of `quic_test_support.zig` answers in the same process, and no TCP connection is started
//! unless a test starts it.
const std = @import("std");
const quic = @import("quic");
const h3 = @import("h3");
const tls = @import("tls");
const support = @import("connection_test_support.zig");
const quic_support = @import("quic_test_support.zig");
const origin_module = @import("origin.zig");
const connection_module = @import("connection.zig");
const event = @import("event.zig");

const testing = std.testing;
const Origin = origin_module.Origin;
const Exchange = event.Exchange;
const Event = origin_module.Event;
const Transport = origin_module.Transport;

/// The origin the tests drive, its configurations and the events it reported, outside any stack
/// frame. Test-only.
var origin: Origin align(@alignOf(Origin)) = undefined;
var tcp_tls: tls.record.ClientConfig align(@alignOf(tls.record.ClientConfig)) = undefined;
var tcp_config: connection_module.Config align(@alignOf(connection_module.Config)) = undefined;
var config: origin_module.Config align(@alignOf(origin_module.Config)) = undefined;
var events: [support.events_max]Event align(@alignOf(Event)) = undefined;
var events_len: usize = 0;
var bodies: [bodies_count][body_len]u8 = undefined;
const bodies_count: usize = 2;
const body_len: usize = 1024;
/// Where a datagram crosses from one side to the other. Test-only.
var datagram: [quic.constants.datagram_len_max]u8 = undefined;
var crossing: [quic.constants.datagram_len_max]u8 = undefined;
/// Whether the datagrams the origin sends are lost, as on a network that blocks UDP.
var blocked: bool = false;

const unstarted_octet: u8 = 0x01;
const https_port: u16 = 443;
const other_port: u16 = 8443;
const alternative_port: u16 = 50781;
/// The fallback delay, and how far each round of `pump` moves time: 250 ms, past which the ninth
/// round of 30 ms goes.
const fallback_delay_ns: u64 = 250_000_000;
const round_ns: u64 = 30_000_000;
const rounds_before_fallback: usize = 8;
/// Rounds past the first probe timeout of a handshake whose Initial was lost: RFC 9002 §6.2.2's
/// initial RTT of 333 ms makes it about a second.
const rounds_past_probe: usize = 48;
const datagrams_per_round_max: usize = 64;
/// An IPv4 host, its four octets alike. Test-only.
const ipv4_len: usize = 4;
const host_octet: u8 = 0x7f;
const loopback: [ipv4_len]u8 = @splat(host_octet);
const addresses = [_]origin_module.Address{origin_module.Address.of(&loopback, 0)};

/// An origin offering h3 and h2 over TLS, whose QUIC server selects from `server_protocols`.
fn start(server_protocols: []const []const u8, values: origin_module.Values, quic_first: bool) !void {
    try quic_support.prepare(&quic_support.alpn_h3, server_protocols, false);
    try tcp_tls.init(.{
        .trust = .{ .web_pki = .{ .anchors = &support.anchors, .server_name = support.authority } },
        .alpn = &support.protocols_both,
    });
    tcp_config = .{ .authority = support.authority, .tls = &tcp_tls };
    config = .{ .tcp = &tcp_config, .quic = &quic_support.config, .quic_first = quic_first, .fallback_delay_ns = fallback_delay_ns };
    // Every octet 1, so each flag of a connection the origin never started reads as set, and a
    // read of one shows.
    @memset(std.mem.asBytes(&origin), unstarted_octet);
    origin.init(&config, values);
    events_len = 0;
    blocked = false;
}

fn values_at(port: u16) origin_module.Values {
    return .{ .addresses = &addresses, .port = port };
}

fn get(body: []u8) Exchange {
    return .{ .method = "GET", .path = "/dns-query", .body = body };
}

/// Reports every event the origin owes, with no datagram, and keeps them.
fn collect() !void {
    for (0..support.events_max) |_| {
        const received = origin.receive(.none, quic_support.now_ns);
        try keep(received.event orelse return);
    }
    return error.TestUnexpectedResult;
}

/// Keeps `reported`, and starts QUIC when an `open` event asks for it. The tests start no TCP.
fn keep(reported: Event) !void {
    if (events_len == events.len) return error.TestUnexpectedResult;
    events[events_len] = reported;
    events_len += 1;
    if (reported == .open and reported.open.transport == .quic) {
        try origin.start_quic(quic_support.client_start, support.stream.random(), support.now_seconds, quic_support.now_ns, null);
    }
}

/// Moves datagrams both ways for `rounds` rounds, moving time on and firing each side's timers.
fn pump(rounds: usize) !void {
    for (0..rounds) |_| {
        quic_support.now_ns += round_ns;
        for (0..datagrams_per_round_max) |_| {
            const sent = origin.send_datagram(&datagram, quic_support.now_ns) orelse break;
            if (blocked) continue;
            @memcpy(crossing[0..sent.octets.len], sent.octets);
            try quic_support.server_receive(crossing[0..sent.octets.len]);
        }
        try quic_support.answer_due();
        for (0..datagrams_per_round_max) |_| {
            const len = (try quic_support.server_send(&datagram)) orelse break;
            @memcpy(crossing[0..len], datagram[0..len]);
            try deliver(crossing[0..len]);
        }
        origin.on_instant(quic_support.now_ns);
        quic_support.server_on_instant();
        try collect();
    }
}

/// Passes a datagram the server sent to the origin. RFC 9000 §9: a client discards a datagram from
/// an address other than its server's, so it comes from the address the origin opened.
fn deliver(octets: []u8) !void {
    const from = origin.links.get(.quic).to;
    // Bounded: each pass consumes the datagram or reports one of the origin's events.
    for (0..support.events_max) |_| {
        const received = origin.receive(.{ .datagram = .{ .octets = octets, .from = from } }, quic_support.now_ns);
        if (received.event) |reported| try keep(reported);
        if (received.consumed > 0) return;
    }
    return error.TestUnexpectedResult;
}

/// The events of `tag`, in order. Test-only.
fn nth(tag: std.meta.Tag(Event), index: usize) ?Event {
    var seen: usize = 0;
    for (events[0..events_len]) |reported| {
        if (reported != tag) continue;
        if (seen == index) return reported;
        seen += 1;
    }
    return null;
}

fn opened(index: usize) ?origin_module.Open {
    const held = nth(.open, index) orelse return null;
    return held.open;
}

test "RFC 9114 §3.1: with h3 offered, QUIC opens first and carries the exchange, and TCP never opens" {
    try start(&quic_support.alpn_h3, values_at(https_port), true);
    var exchange = get(&bodies[0]);
    const id = try origin.request(&exchange);
    try collect();
    try testing.expectEqual(Transport.quic, opened(0).?.transport);
    try testing.expectEqual(https_port, opened(0).?.to.port);
    // RFC 9000 §9: the connection's datagrams go to the address and port the origin opened.
    const first = origin.send_datagram(&datagram, quic_support.now_ns).?;
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
    _ = try origin.request(&exchange);
    try collect();
    try pump(quic_support.rounds_default);
    try testing.expectEqual(Transport.tcp, opened(1).?.transport);
    try testing.expectEqual(origin_module.Phase.handshake, origin.phase(.tcp));
    try testing.expectEqual(.pending, exchange.outcome);
}

test "RFC 9114 §3.1: TCP opens beside a QUIC handshake once the fallback delay passes, and not before" {
    try start(&quic_support.alpn_h3, values_at(https_port), true);
    blocked = true;
    var exchange = get(&bodies[0]);
    _ = try origin.request(&exchange);
    try collect();
    const fallback_at = quic_support.now_ns + fallback_delay_ns;
    try testing.expect(origin.deadline_ns().? <= fallback_at);
    try pump(rounds_before_fallback);
    try testing.expectEqual(fallback_at, origin.deadline_ns().?);
    quic_support.now_ns = fallback_at - 1;
    try collect();
    try testing.expectEqual(null, opened(1));
    quic_support.now_ns = fallback_at;
    origin.on_instant(fallback_at);
    try collect();
    try testing.expectEqual(Transport.tcp, opened(1).?.transport);
}

test "the first handshake to complete takes the exchange, and the transport still opening closes" {
    try start(&quic_support.alpn_h3, values_at(https_port), true);
    blocked = true;
    var exchange = get(&bodies[0]);
    _ = try origin.request(&exchange);
    try collect();
    try pump(rounds_before_fallback + 1);
    try testing.expectEqual(Transport.tcp, opened(1).?.transport);
    // QUIC's datagrams get through before the test starts TCP, so QUIC's handshake completes first.
    blocked = false;
    try pump(rounds_past_probe);
    try testing.expectEqual(event.Protocol.h3, nth(.connected, 0).?.connected);
    try testing.expectEqual(Transport.tcp, nth(.close, 0).?.close);
    try testing.expectEqual(origin_module.Phase.closed, origin.phase(.tcp));
    try testing.expectEqual(.response, exchange.outcome);
}

test "RFC 9114 §5.2: an exchange a GOAWAY left unprocessed moves, and TCP opens for it" {
    try start(&quic_support.alpn_h3, values_at(https_port), true);
    quic_support.server_answers = false;
    quic_support.server_streams_bidi = 1;
    var first = get(&bodies[0]);
    var second = get(&bodies[1]);
    _ = try origin.request(&first);
    const second_id = try origin.request(&second);
    try pump(quic_support.rounds_default);
    // The server took stream 0 alone, and the second exchange waits for its stream limit.
    try quic_support.server_h3.shutdown(&quic_support.server, quic_support.now_ns);
    try pump(quic_support.rounds_default);
    try testing.expectEqual(origin_module.Phase.draining, origin.phase(.quic));
    try testing.expectEqual(Transport.tcp, opened(1).?.transport);
    // RFC 9114 §4.1.1: the refused exchange is made again as though never sent, so no event
    // reports it, and its outcome is pending once more.
    for (events[0..events_len]) |reported| {
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
    _ = try origin.request(&exchange);
    try pump(quic_support.rounds_default);
    quic_support.server_h3.cancel(&quic_support.server, 0, h3.constants.error_request_rejected);
    try pump(quic_support.rounds_default);
    try testing.expectEqual(.refused, exchange.outcome);
    try testing.expectEqual(&exchange, nth(.finished, 0).?.finished.exchange);
    try testing.expectEqual(null, opened(1));
}

test "RFC 9460 §7.1.2, §7.2: an HTTPS record's ALPN set chooses the transport, and its port applies" {
    const without_h3: origin_module.Values = .{ .addresses = &addresses, .port = https_port, .https = .{ .h3 = false, .port = other_port } };
    try start(&quic_support.alpn_h3, without_h3, true);
    var exchange = get(&bodies[0]);
    _ = try origin.request(&exchange);
    try collect();
    try testing.expectEqual(Transport.tcp, opened(0).?.transport);
    try testing.expectEqual(other_port, opened(0).?.to.port);
    const with_h3: origin_module.Values = .{ .addresses = &addresses, .port = https_port, .https = .{ .h3 = true, .port = other_port } };
    try start(&quic_support.alpn_h3, with_h3, false);
    _ = try origin.request(&exchange);
    try collect();
    try testing.expectEqual(Transport.quic, opened(0).?.transport);
    try testing.expectEqual(other_port, opened(0).?.to.port);
}

test "RFC 7838 §2.2: a fresh Alt-Svc alternative sends QUIC to its port first, and a stale one does not" {
    const fresh: origin_module.Values = .{ .addresses = &addresses, .port = https_port, .alternative = .{ .port = alternative_port, .fresh_until_ns = quic_support.start_ns + 1 } };
    try start(&quic_support.alpn_h3, fresh, false);
    var exchange = get(&bodies[0]);
    _ = try origin.request(&exchange);
    try collect();
    try testing.expectEqual(Transport.quic, opened(0).?.transport);
    try testing.expectEqual(alternative_port, opened(0).?.to.port);
    const stale: origin_module.Values = .{ .addresses = &addresses, .port = https_port, .alternative = .{ .port = alternative_port, .fresh_until_ns = quic_support.start_ns } };
    try start(&quic_support.alpn_h3, stale, false);
    _ = try origin.request(&exchange);
    try collect();
    try testing.expectEqual(Transport.tcp, opened(0).?.transport);
}

test "RFC 7838 §3.1: what Alt-Svc says replaces what the origin knew, fresh for its max-age" {
    try start(&quic_support.alpn_h3, values_at(https_port), false);
    const now_ns = quic_support.now_ns;
    const max_age_s: u64 = 60;
    origin.learn(.{ .h3 = .{ .port = alternative_port, .max_age_s = max_age_s } }, now_ns);
    try testing.expectEqual(alternative_port, origin.alternative().?.port);
    try testing.expectEqual(now_ns + max_age_s * 1_000_000_000, origin.alternative().?.fresh_until_ns);
    try testing.expect(origin.quic_allowed(now_ns));
    origin.learn(.none, now_ns);
    try testing.expectEqual(null, origin.alternative());
    origin.learn(.{ .h3 = .{ .port = alternative_port, .max_age_s = max_age_s } }, now_ns);
    origin.learn(.clear, now_ns);
    try testing.expectEqual(null, origin.alternative());
}

test "decision 100: once every transport failed, each waiting exchange ends refused" {
    const offered = [_][]const u8{ "hq-interop", "h3" };
    try start(&quic_support.alpn_other, values_at(https_port), true);
    try quic_support.prepare(&offered, &quic_support.alpn_other, false);
    var exchange = get(&bodies[0]);
    const id = try origin.request(&exchange);
    try collect();
    try pump(quic_support.rounds_default);
    try testing.expectEqual(Transport.tcp, opened(1).?.transport);
    // The caller's TCP connection failed before its handshake began.
    origin.transport_closed(.tcp);
    try pump(quic_support.rounds_default);
    try testing.expectEqual(id, nth(.finished, 0).?.finished.id);
    try testing.expectEqual(.refused, exchange.outcome);
}

test "RFC 9114 §4.1.1: a cancelled exchange a connection carries reports nothing, though its server answers" {
    try start(&quic_support.alpn_h3, values_at(https_port), true);
    quic_support.server_answers = false;
    var exchange = get(&bodies[0]);
    const id = try origin.request(&exchange);
    try pump(quic_support.rounds_default);
    origin.cancel(id);
    quic_support.server_answers = true;
    try pump(quic_support.rounds_default);
    try testing.expectEqual(null, nth(.finished, 0));
    try testing.expectEqual(.pending, exchange.outcome);
}

test "RFC 9000 §10: a QUIC transport the caller closed ends its written exchange closed, and asks for no close" {
    try start(&quic_support.alpn_h3, values_at(https_port), true);
    quic_support.server_answers = false;
    var exchange = get(&bodies[0]);
    _ = try origin.request(&exchange);
    try pump(quic_support.rounds_default);
    origin.transport_closed(.quic);
    try collect();
    try testing.expectEqual(.closed, exchange.outcome);
    try testing.expectEqual(&exchange, nth(.finished, 0).?.finished.exchange);
    try testing.expectEqual(null, nth(.close, 0));
    try testing.expectEqual(origin_module.Phase.closed, origin.phase(.quic));
}

test "RFC 9114 §4.1.1: a QUIC transport the caller closed moves the exchange it had not written" {
    try start(&quic_support.alpn_h3, values_at(https_port), true);
    quic_support.server_answers = false;
    quic_support.server_streams_bidi = 1;
    var first = get(&bodies[0]);
    var second = get(&bodies[1]);
    _ = try origin.request(&first);
    _ = try origin.request(&second);
    try pump(quic_support.rounds_default);
    // The second exchange waits for the server's stream limit, unwritten, when the flow closes.
    origin.transport_closed(.quic);
    try collect();
    try testing.expectEqual(.closed, first.outcome);
    try testing.expectEqual(&first, nth(.finished, 0).?.finished.exchange);
    try testing.expectEqual(null, nth(.finished, 1));
    try testing.expectEqual(.pending, second.outcome);
    try testing.expectEqual(Transport.tcp, opened(1).?.transport);
}

test "RFC 9846 §4.6.1: a QUIC ticket is reported for its transport, and take_ticket hands it over once" {
    try start(&quic_support.alpn_h3, values_at(https_port), true);
    try quic_support.prepare(&quic_support.alpn_h3, &quic_support.alpn_h3, true);
    var exchange = get(&bodies[0]);
    _ = try origin.request(&exchange);
    try pump(quic_support.rounds_default);
    try testing.expectEqual(Transport.quic, nth(.ticket, 0).?.ticket);
    var ticket = origin.take_ticket(.quic) orelse return error.TestUnexpectedResult;
    defer ticket.wipe();
    try testing.expectEqual(null, origin.take_ticket(.quic));
    try testing.expectEqual(null, origin.take_ticket(.tcp));
}

test "RFC 7838 §3: TCP goes to the origin's port though QUIC went to the alternative's" {
    const offered = [_][]const u8{ "hq-interop", "h3" };
    const fresh: origin_module.Values = .{ .addresses = &addresses, .port = https_port, .alternative = .{ .port = alternative_port, .fresh_until_ns = std.math.maxInt(u64) } };
    try start(&quic_support.alpn_other, fresh, false);
    try quic_support.prepare(&offered, &quic_support.alpn_other, false);
    var exchange = get(&bodies[0]);
    _ = try origin.request(&exchange);
    try collect();
    try testing.expectEqual(alternative_port, opened(0).?.to.port);
    try pump(quic_support.rounds_default);
    try testing.expectEqual(Transport.tcp, opened(1).?.transport);
    try testing.expectEqual(https_port, opened(1).?.to.port);
}

test "a cancelled exchange leaves nothing to open" {
    try start(&quic_support.alpn_h3, values_at(https_port), true);
    var exchange = get(&bodies[0]);
    const id = try origin.request(&exchange);
    origin.cancel(id);
    try collect();
    try testing.expectEqual(null, opened(0));
}
