//! More tests of the pool to one origin with QUIC offered (`pool.zig`, `pool_events.zig`):
//! what a cancel, a transport the caller closed, a second refusal, a ticket, a shutdown and a
//! server that takes no request from its first datagram leave, and when a request goes out again
//! after a close (decision 124).
//! Split out of `pool_quic_test.zig` for length.
const std = @import("std");
const quic = @import("quic");
const h3 = @import("h3");
const quic_support = @import("../quic/quic_test_support.zig");
const connection_support = @import("../connection/connection_test_support.zig");
const fixture = @import("pool_quic_test_support.zig");
const pool_module = @import("pool.zig");
const event = @import("../event.zig");
const constants = @import("../constants.zig");

const testing = std.testing;
const Transport = pool_module.Transport;
const pool = &fixture.pool;
const bodies = &fixture.bodies;
const start = fixture.start;
const values_at = fixture.values_at;
const get = fixture.get;
const post = fixture.post;
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
    const id = try pool.request(&exchange.request, &exchange.response);
    try pump(quic_support.rounds_default);
    pool.cancel(id);
    quic_support.server_answers = true;
    try pump(quic_support.rounds_default);
    try testing.expectEqual(null, nth(.finished, 0));
    try testing.expectEqual(.pending, exchange.response.outcome);
}

test "RFC 9000 §10: a QUIC transport the caller closed ends its written POST closed, and asks for no close" {
    try start(&quic_support.alpn_h3, values_at(https_port), true);
    quic_support.server_answers = false;
    var exchange = post(&bodies[0]);
    _ = try pool.request(&exchange.request, &exchange.response);
    try pump(quic_support.rounds_default);
    pool.transport_closed(.quic);
    try collect();
    try testing.expectEqual(.closed, exchange.response.outcome);
    try testing.expectEqual(&exchange.response, nth(.finished, 0).?.finished.response);
    try testing.expectEqual(&exchange.request, nth(.finished, 0).?.finished.request);
    try testing.expectEqual(null, nth(.close, 0));
    try testing.expectEqual(pool_module.Phase.closed, pool.phase(.quic));
    // RFC 9110 §9.2.2: a POST is not idempotent, so the pool opens no connection to send it
    // again.
    try testing.expectEqual(null, opened(1));
}

test "RFC 9114 §4.1.1: a QUIC transport the caller closed moves the exchange it had not written" {
    try start(&quic_support.alpn_h3, values_at(https_port), true);
    quic_support.server_answers = false;
    quic_support.server_streams_bidi = 1;
    var first = post(&bodies[0]);
    var second = get(&bodies[1]);
    _ = try pool.request(&first.request, &first.response);
    _ = try pool.request(&second.request, &second.response);
    try pump(quic_support.rounds_default);
    // The second exchange waits for the server's stream limit, unwritten, when the flow closes.
    pool.transport_closed(.quic);
    try collect();
    try testing.expectEqual(.closed, first.response.outcome);
    try testing.expectEqual(&first.response, nth(.finished, 0).?.finished.response);
    try testing.expectEqual(&first.request, nth(.finished, 0).?.finished.request);
    try testing.expectEqual(null, nth(.finished, 1));
    try testing.expectEqual(.pending, second.response.outcome);
    try testing.expectEqual(Transport.tcp, opened(1).?.transport);
}

test "RFC 9114 §4.1.1: an exchange a second draining connection refuses has moved once, and reaches the caller" {
    try start(&quic_support.alpn_h3, values_at(https_port), true);
    quic_support.server_answers = false;
    quic_support.server_streams_bidi = 1;
    var first = get(&bodies[0]);
    var second = get(&bodies[1]);
    _ = try pool.request(&first.request, &first.response);
    const second_id = try pool.request(&second.request, &second.response);
    try pump(quic_support.rounds_default);
    // The GOAWAY refuses the second exchange, waiting for its stream, which moves once. TCP opens
    // for it, and the caller's TCP connection fails before it starts.
    try quic_support.server_h3.shutdown(&quic_support.server, quic_support.now_ns);
    try pump(quic_support.rounds_default);
    try testing.expectEqual(Transport.tcp, opened(1).?.transport);
    pool.transport_closed(.tcp);
    // The first exchange ends, and its connection closes. A second QUIC connection opens, whose
    // server grants no stream, so the second exchange waits on it too.
    quic_support.server_answers = true;
    quic_support.server_streams_bidi = 0;
    try pump(rounds_past_probe);
    try testing.expectEqual(.response, first.response.outcome);
    try testing.expectEqual(Transport.quic, opened(2).?.transport);
    try testing.expectEqual(pool_module.Phase.open, pool.phase(.quic));
    // RFC 9113 §8.7: a second refusal goes to the caller, who may make the request again.
    try quic_support.server_h3.shutdown(&quic_support.server, quic_support.now_ns);
    try pump(quic_support.rounds_default);
    try testing.expectEqual(second_id, nth(.finished, 1).?.finished.id);
    try testing.expectEqual(.refused, second.response.outcome);
}

test "RFC 9846 §4.6.1: a QUIC ticket is reported for its transport, and take_ticket hands it over once" {
    try start(&quic_support.alpn_h3, values_at(https_port), true);
    try quic_support.prepare(&quic_support.alpn_h3, &quic_support.alpn_h3, true);
    var exchange = get(&bodies[0]);
    _ = try pool.request(&exchange.request, &exchange.response);
    try pump(quic_support.rounds_default);
    try testing.expectEqual(Transport.quic, nth(.ticket, 0).?.ticket);
    var ticket = pool.take_ticket(.quic) orelse return error.TestUnexpectedResult;
    defer ticket.wipe();
    try testing.expectEqual(null, pool.take_ticket(.quic));
    try testing.expectEqual(null, pool.take_ticket(.tcp));
}

test "RFC 7838 §3: TCP goes to the origin's port though QUIC went to the alternative's" {
    const fresh: pool_module.Values = .{ .addresses = &addresses, .port = https_port, .alternative = .{ .port = alternative_port, .fresh_until_ns = std.math.maxInt(u64) } };
    try start(&quic_support.alpn_other, fresh, false);
    var exchange = get(&bodies[0]);
    _ = try pool.request(&exchange.request, &exchange.response);
    try collect();
    try testing.expectEqual(alternative_port, opened(0).?.to.port);
    try pump(quic_support.rounds_default);
    try testing.expectEqual(Transport.tcp, opened(1).?.transport);
    try testing.expectEqual(https_port, opened(1).?.to.port);
}

test "a shut-down pool ends a handshake no exchange waits for, and closes" {
    try start(&quic_support.alpn_h3, values_at(https_port), true);
    fixture.blocked = true;
    var exchange = get(&bodies[0]);
    const id = try pool.request(&exchange.request, &exchange.response);
    try collect();
    try testing.expectEqual(pool_module.Phase.handshake, pool.phase(.quic));
    pool.cancel(id);
    pool.shutdown();
    try collect();
    // RFC 9000 §10.2: the abandoned connection owes its CONNECTION_CLOSE, then runs its closing
    // period, and the pool closes after it.
    try testing.expectEqual(pool_module.Phase.failed, pool.phase(.quic));
    try pump(rounds_past_probe * 4);
    try testing.expectEqual(Transport.quic, nth(.close, 0).?.close);
    try testing.expect(nth(.closed, 0) != null);
}

test "a shut-down pool keeps a handshake while it holds an exchange, which could come back refused" {
    try start(&quic_support.alpn_h3, values_at(https_port), true);
    quic_support.server_answers = false;
    var first = get(&bodies[0]);
    _ = try pool.request(&first.request, &first.response);
    try pump(quic_support.rounds_default);
    // RFC 9114 §5.2: the GOAWAY names stream 4, so the first exchange stays, and the connection
    // takes no second one, which waits for TCP.
    try quic_support.server_h3.shutdown(&quic_support.server, quic_support.now_ns);
    try pump(quic_support.rounds_default);
    var second = get(&bodies[1]);
    const second_id = try pool.request(&second.request, &second.response);
    try collect();
    try testing.expectEqual(Transport.tcp, opened(1).?.transport);
    pool.shutdown();
    pool.cancel(second_id);
    try collect();
    try testing.expectEqual(pool_module.Phase.handshake, pool.phase(.tcp));
    // Once the first exchange ends, the pool holds none, and the handshake ends.
    quic_support.server_answers = true;
    try pump(quic_support.rounds_default);
    try testing.expectEqual(.response, first.response.outcome);
    try testing.expectEqual(Transport.tcp, nth(.close, 0).?.close);
}

/// The server's datagrams a test holds back before it delivers them. Test-only.
var withheld: [withheld_max][quic.constants.datagram_len_max]u8 = undefined;
var withheld_lens: [withheld_max]usize = undefined;
const withheld_max: usize = 8;

test "RFC 9000 §10.2: a handshake the pool abandoned carries nothing, though datagrams in flight complete it" {
    try start(&quic_support.alpn_h3, values_at(https_port), true);
    var exchange = get(&bodies[0]);
    const id = try pool.request(&exchange.request, &exchange.response);
    try collect();
    // The client's Initial reaches the server, and the server's flight is held back.
    for (0..datagrams_per_round_max) |_| {
        const sent = pool.send_datagram(&fixture.datagram, quic_support.now_ns) orelse break;
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
    // The shut-down pool holds nothing, so it abandons the handshake, which owes its
    // CONNECTION_CLOSE and has not sent it.
    pool.cancel(id);
    pool.shutdown();
    try collect();
    try testing.expectEqual(pool_module.Phase.failed, pool.phase(.quic));
    for (withheld[0..withheld_count], withheld_lens[0..withheld_count]) |*octets, len| try deliver(octets[0..len]);
    try collect();
    try testing.expect(pool.quic.transport.handshake_complete);
    try testing.expectEqual(null, nth(.connected, 0));
}

test "a cancelled exchange leaves nothing to open" {
    try start(&quic_support.alpn_h3, values_at(https_port), true);
    var exchange = get(&bodies[0]);
    const id = try pool.request(&exchange.request, &exchange.response);
    pool.cancel(id);
    try collect();
    try testing.expectEqual(null, opened(0));
}

/// Rounds that run past a closing period, three times the Probe Timeout (RFC 9000 §10.2).
const closing_rounds: usize = 128;

test "RFC 9114 §5.1: a QUIC connection idle near its timeout closes, and the next exchange opens a new one" {
    try start(&quic_support.alpn_h3, values_at(https_port), true);
    var first = get(&bodies[0]);
    _ = try pool.request(&first.request, &first.response);
    try collect();
    try pump(quic_support.rounds_default);
    try testing.expectEqual(.response, first.response.outcome);
    // Holding no exchange, the connection retires at its idle deadline less the 1 s margin.
    const acts_at = quic.connection_idle.deadline_ns(&pool.quic.transport).? - constants.quic_idle_margin_ns_min;
    try testing.expect(pool.deadline_ns().? <= acts_at);
    quic_support.now_ns = acts_at;
    pool.on_instant(acts_at);
    try collect();
    try testing.expect(pool.quic.retired);
    try testing.expectEqual(.draining, pool.phase(.quic));
    // It closes with H3_NO_ERROR, and once its closing period has run the pool asks the caller
    // to close its flow.
    try pump(closing_rounds);
    try testing.expectEqual(Transport.quic, nth(.close, 0).?.close);
    try testing.expectEqual(.closed, pool.phase(.quic));
    // The next exchange opens a new QUIC connection, which carries it, and TCP never opens.
    var second = get(&bodies[1]);
    _ = try pool.request(&second.request, &second.response);
    try collect();
    try testing.expectEqual(Transport.quic, opened(1).?.transport);
    try pump(quic_support.rounds_default);
    try testing.expectEqual(.response, second.response.outcome);
    try testing.expectEqual(null, opened(2));
}

/// Passes the server each datagram the pool owes. Time stays where it is.
fn to_server() !void {
    for (0..datagrams_per_round_max) |_| {
        const sent = pool.send_datagram(&fixture.datagram, quic_support.now_ns) orelse return;
        @memcpy(fixture.crossing[0..sent.octets.len], sent.octets);
        try quic_support.server_receive(fixture.crossing[0..sent.octets.len]);
    }
}

/// Passes the pool each datagram the server owes.
fn to_pool() !void {
    for (0..datagrams_per_round_max) |_| {
        const len = (try quic_support.server_send(&fixture.datagram)) orelse return;
        @memcpy(fixture.crossing[0..len], fixture.datagram[0..len]);
        try deliver(fixture.crossing[0..len]);
    }
}

/// A second IPv4 host after the fixture's, its four octets alike. Test-only.
const ipv4_len: usize = 4;
const other_octet: u8 = 0x7e;
const other_host: [ipv4_len]u8 = @splat(other_octet);
const two_addresses = [_]pool_module.Address{ addresses[0], pool_module.Address.of(&other_host, 0) };

test "RFC 9114 §5.2: a connection whose server says GOAWAY as h3 starts carries nothing, and its attempt goes on" {
    try start(&quic_support.alpn_h3, .{ .addresses = &two_addresses, .port = https_port }, true);
    var exchange = get(&bodies[0]);
    _ = try pool.request(&exchange.request, &exchange.response);
    try collect();
    try to_server();
    // The server's SETTINGS and GOAWAY go out in 1-RTT packets behind its Finished (RFC 9001
    // §5.7), so the datagram that completes the client's handshake also says the server takes no
    // request.
    try quic_support.start_server_h3_early();
    try quic_support.server_h3.shutdown(&quic_support.server, quic_support.now_ns);
    try to_pool();
    try collect();
    try testing.expect(pool.quic.started and pool.quic.draining);
    try testing.expectEqual(null, nth(.connected, 0));
    // The pool abandons the connection, and the attempt that opened it opens TCP.
    try testing.expectEqual(pool_module.Phase.failed, pool.phase(.quic));
    try testing.expectEqual(Transport.tcp, opened(1).?.transport);
    // The caller's TCP connection fails before it starts, so the attempt has no transport left:
    // QUIC stays counted in it, and the exchange ends refused with no third open.
    pool.transport_closed(.tcp);
    try pump(rounds_past_probe);
    try testing.expectEqual(.refused, exchange.response.outcome);
    try testing.expectEqual(null, opened(2));
    // The connection the pool abandoned was no failed attempt, so the next request's QUIC
    // connection goes to the same address.
    _ = try pool.request(&exchange.request, &exchange.response);
    try collect();
    try testing.expectEqual(Transport.quic, opened(2).?.transport);
    try testing.expect(opened(2).?.to.same_host(&two_addresses[0]));
}

/// A pool that speaks h3 alone, so a request it sends again waits for the next QUIC connection:
/// it opens no TCP (decision 120).
fn start_h3_alone() !void {
    var given = fixture.configured(true);
    given.versions = .{ .h11 = false, .h2 = false };
    try fixture.start_configured(&quic_support.alpn_h3, values_at(https_port), given, fixture.receive_storage());
}

test "RFC 9110 §9.2.2: a GET whose QUIC transport closed before any of its response goes out again, and is answered" {
    try start_h3_alone();
    quic_support.server_answers = false;
    var exchange = get(&bodies[0]);
    const id = try pool.request(&exchange.request, &exchange.response);
    try pump(quic_support.rounds_default);
    try testing.expectEqual(1, quic_support.answers_len);
    pool.transport_closed(.quic);
    quic_support.server_answers = true;
    try collect();
    // RFC 9112 §9.3.1: the pool opens another connection for the request, and reports nothing.
    try testing.expectEqual(null, nth(.finished, 0));
    try testing.expectEqual(Transport.quic, opened(1).?.transport);
    try pump(quic_support.rounds_default);
    try testing.expectEqual(id, nth(.finished, 0).?.finished.id);
    try testing.expectEqual(null, nth(.finished, 1));
    try testing.expectEqual(.response, exchange.response.outcome);
    try testing.expectEqualStrings("hello", exchange.response.content_received());
    try testing.expectEqual(null, opened(2));
}

/// The content of a PUT the pool sends again. Test-only.
var upload: [upload_len]u8 = undefined;
const upload_len: usize = 2048;

test "RFC 9110 §9.2.2: a PUT sent again over QUIC sends its whole content again" {
    try start_h3_alone();
    quic_support.server_answers = false;
    @memset(&upload, 'u');
    var put: connection_support.Exchange = .{ .request = .{ .method = "PUT", .path = "/object", .content = &upload }, .response = .{ .body = &bodies[0] } };
    _ = try pool.request(&put.request, &put.response);
    try pump(quic_support.rounds_default);
    try testing.expectEqual(upload_len, quic_support.answers[0].received);
    pool.transport_closed(.quic);
    quic_support.server_answers = true;
    try collect();
    try pump(quic_support.rounds_default);
    // The second connection's server read the whole content and the stream's end.
    try testing.expectEqual(1, quic_support.answers_len);
    try testing.expectEqual(upload_len, quic_support.answers[0].received);
    try testing.expect(quic_support.answers[0].ended);
    try testing.expectEqual(.response, put.response.outcome);
    try testing.expectEqual(upload_len, put.response.content_sent);
}

test "RFC 9110 §9.2.2: a GET whose second QUIC transport also closed before any of its response ends closed" {
    try start_h3_alone();
    quic_support.server_answers = false;
    var exchange = get(&bodies[0]);
    _ = try pool.request(&exchange.request, &exchange.response);
    try pump(quic_support.rounds_default);
    pool.transport_closed(.quic);
    try collect();
    try pump(quic_support.rounds_default);
    try testing.expectEqual(1, quic_support.answers_len);
    // RFC 9110 §9.2.2: "A client SHOULD NOT automatically retry a failed automatic retry."
    pool.transport_closed(.quic);
    try collect();
    try testing.expectEqual(.closed, exchange.response.outcome);
    try testing.expectEqual(null, nth(.finished, 1));
    try testing.expectEqual(null, opened(2));
}

test "RFC 9110 §9.2.2: a GET whose QUIC transport closed after a HEADERS frame of its response ends closed" {
    try start_h3_alone();
    // The server sends the head alone, and never ends the stream.
    quic_support.answer_open = true;
    quic_support.answer_content = "";
    var exchange = get(&bodies[0]);
    _ = try pool.request(&exchange.request, &exchange.response);
    try pump(quic_support.rounds_default);
    try testing.expectEqual(200, exchange.response.status);
    pool.transport_closed(.quic);
    try collect();
    try testing.expectEqual(.closed, exchange.response.outcome);
    try testing.expectEqual(null, opened(1));
}

/// A HEADERS frame (RFC 9114 §7.2.2) whose field section names entry 127 of QPACK's static table,
/// which has 99 (RFC 9204 Appendix A): its type and length, a section prefix of no dynamic entry,
/// and an indexed field line (RFC 9204 §4.5.2). Test-only.
const undecodable_headers = "\x01\x04\x00\x00\xff\x40";
/// The first octets of a HEADERS frame whose payload would be 16 octets long. Test-only.
const headers_start = "\x01\x10\x00";

/// The server answers its first request with `octets` and leaves the stream open.
fn answer_raw(octets: []const u8) !void {
    const answer = &quic_support.answers[0];
    @memcpy(answer.prefix[0..octets.len], octets);
    answer.prefix_len = octets.len;
    answer.content = "";
    answer.answered = true;
    try quic.connection_stream_send.supply(&quic_support.server, .{ .value = answer.id }, octets.len, false);
}

test "decision 124: a GET whose h3 HEADERS frame fails to decode ends closed, not sent again" {
    try start_h3_alone();
    quic_support.server_answers = false;
    var exchange = get(&bodies[0]);
    _ = try pool.request(&exchange.request, &exchange.response);
    try pump(quic_support.rounds_default);
    // RFC 9204 §3.1: an invalid static table index is a connection error of type
    // QPACK_DECOMPRESSION_FAILED, which fails the connection.
    try answer_raw(undecodable_headers);
    try pump(quic_support.rounds_default);
    try testing.expectEqual(.closed, exchange.response.outcome);
    try testing.expectEqual(null, opened(1));
}

test "decision 124: a GET whose QUIC transport closed inside an h3 HEADERS frame ends closed, not sent again" {
    try start_h3_alone();
    quic_support.server_answers = false;
    var exchange = get(&bodies[0]);
    _ = try pool.request(&exchange.request, &exchange.response);
    try pump(quic_support.rounds_default);
    try answer_raw(headers_start);
    try pump(quic_support.rounds_default);
    pool.transport_closed(.quic);
    try collect();
    try testing.expectEqual(.closed, exchange.response.outcome);
    try testing.expectEqual(null, opened(1));
}

test "decision 124: a request a GOAWAY moved, whose next QUIC connection closed before any response, ends closed" {
    try start_h3_alone();
    quic_support.server_answers = false;
    quic_support.server_streams_bidi = 1;
    var first = get(&bodies[0]);
    var second = get(&bodies[1]);
    _ = try pool.request(&first.request, &first.response);
    _ = try pool.request(&second.request, &second.response);
    try pump(quic_support.rounds_default);
    // The GOAWAY refuses the second exchange, waiting for its stream, which moves once.
    try quic_support.server_h3.shutdown(&quic_support.server, quic_support.now_ns);
    quic_support.server_answers = true;
    // The first exchange ends, and its connection closes. A second QUIC connection carries the
    // second exchange, and its server reads it and answers nothing.
    for (0..rounds_past_probe) |_| {
        if (opened(1) != null) break;
        try pump(1);
    }
    try testing.expectEqual(.response, first.response.outcome);
    try testing.expectEqual(Transport.quic, opened(1).?.transport);
    quic_support.server_answers = false;
    try pump(quic_support.rounds_default);
    try testing.expectEqual(1, quic_support.answers_len);
    // The refusal spent the one move (`moves_max`), so the close sends nothing again.
    pool.transport_closed(.quic);
    try collect();
    try testing.expectEqual(.closed, second.response.outcome);
    try testing.expectEqual(null, opened(2));
}

test "decision 124: a cancelled exchange a QUIC connection carried is never sent again" {
    try start_h3_alone();
    quic_support.server_answers = false;
    var exchange = get(&bodies[0]);
    const id = try pool.request(&exchange.request, &exchange.response);
    try pump(quic_support.rounds_default);
    pool.cancel(id);
    pool.transport_closed(.quic);
    try collect();
    try testing.expectEqual(null, nth(.finished, 0));
    try testing.expectEqual(null, opened(1));
}
