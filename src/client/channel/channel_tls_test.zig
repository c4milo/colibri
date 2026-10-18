//! The tests of the channel over TCP and TLS (`channel.zig`, `channel_events.zig`), against the
//! TLS server of `connection_tls_test_support.zig` in the same process. A connection that is over
//! may still hold octets it owes the server, and the channel asks for its transport's close only
//! once `send_stream` wrote them (design §8 step 21c.4). A connection that fails, or takes no new
//! exchange, in the call that completes its handshake carries nothing, and its transport stays
//! counted in the attempt that opened it (design §8 step 21c.5).
const std = @import("std");
const tls = @import("tls");
const support = @import("../connection/connection_test_support.zig");
const tls_support = @import("../connection/connection_tls_test_support.zig");
const channel_module = @import("channel.zig");
const channel_support = @import("channel_test_support.zig");
const versions_module = @import("../versions.zig");
const event = @import("../event.zig");

const testing = std.testing;
const Exchange = support.Exchange;
const Event = channel_module.Event;
const Transport = channel_module.Transport;

/// The channel's configuration and the events it reported, outside any stack frame. Test-only.
var config: channel_module.Config align(@alignOf(channel_module.Config)) = undefined;
var events: [support.events_max]Event align(@alignOf(Event)) = undefined;
var events_len: usize = 0;
var bodies: [bodies_count][body_len]u8 = undefined;
const bodies_count: usize = 2;
const body_len: usize = 1024;

const ok: u16 = 200;
const https_port: u16 = 443;
/// Two IPv4 hosts, the four octets of each alike. Test-only.
const ipv4_len: usize = 4;
const host_octet: u8 = 0x7f;
const loopback: [ipv4_len]u8 = @splat(host_octet);
const other_octet: u8 = 0x7e;
const other_host: [ipv4_len]u8 = @splat(other_octet);
const addresses = [_]channel_module.Address{ channel_module.Address.of(&loopback, 0), channel_module.Address.of(&other_host, 0) };

/// Passes the channel what the server sent, in calls until one takes nothing and reports nothing,
/// with `.none` once no octet is left. Starts the connection an `open` event asks for, and keeps
/// the events.
fn collect(channel: anytype) !void {
    // Bounded: each pass consumes an octet or reports an event, and both are finite.
    for (0..support.buffer_len + support.events_max) |_| {
        const input: channel_module.Input = if (support.to_client_len > 0) .{ .stream = support.to_client[0..support.to_client_len] } else .none;
        const received = channel.receive(input, support.now_ns);
        std.mem.copyForwards(u8, &support.to_client, support.to_client[received.consumed..support.to_client_len]);
        support.to_client_len -= received.consumed;
        const reported = received.event orelse {
            if (received.consumed == 0) return;
            continue;
        };
        if (events_len == events.len) return error.TestUnexpectedResult;
        events[events_len] = reported;
        events_len += 1;
        if (reported == .open) try channel.start_tcp(support.stream.random(), support.now_seconds, null);
    }
    return error.TestUnexpectedResult;
}

/// The first event of `tag` the channel reported, or null.
fn find(tag: std.meta.Tag(Event)) ?Event {
    for (events[0..events_len]) |reported| {
        if (reported == tag) return reported;
    }
    return null;
}

fn count(tag: std.meta.Tag(Event)) usize {
    var counted: usize = 0;
    for (events[0..events_len]) |reported| counted += @intFromBool(reported == tag);
    return counted;
}

fn get(body: []u8) Exchange {
    return .{ .request = .{ .method = "GET", .path = "/" }, .response = .{ .body = body } };
}

/// The h2 server reads what the TLS server opened, and answers stream 1 with `content`.
fn answer(content: []const u8) !void {
    try answer_with(content, true);
}

/// As `answer`, with the head alone when `whole` is false: no DATA, and no END_STREAM.
fn answer_with(content: []const u8, whole: bool) !void {
    try peer_h2_read();
    const out = &tls_support.peer_out;
    var written = support.peer_h2.write_pending(out, support.now_ns);
    written += try support.peer_h2.write_response(out[written..], 1, ok, &.{}, false);
    if (whole) written += (try support.peer_h2.write_data(out[written..], 1, content, true)).written;
    try tls_support.server_seal(out[0..written]);
}

/// The h2 server reads every frame the TLS server opened.
fn peer_h2_read() !void {
    try tls_support.server_open();
    var consumed: usize = 0;
    for (0..tls_support.peer_plain_len + 1) |_| {
        const received = try support.peer_h2.receive(tls_support.peer_plain[consumed..tls_support.peer_plain_len], support.now_ns);
        if (received.consumed == 0) break;
        consumed += received.consumed;
    }
}

/// Puts a record no key sealed after what the server sealed, in the same octets (RFC 9846 §5.2).
fn forge() void {
    const forged = tls_support.forged_record;
    @memcpy(support.to_client[support.to_client_len..][0..forged.len], forged);
    support.to_client_len += forged.len;
}

/// The ALPN extension of a ClientHello that offers `list`, each name behind its length: the
/// extension's type, 16, its length and the list's, each in two octets (RFC 7301 §3.1).
fn alpn_extension(comptime list: []const u8) []const u8 {
    const lengths = [_]u8{ 0, alpn_extension_type, 0, @intCast(list.len + alpn_list_len_octets), 0, @intCast(list.len) };
    return &lengths ++ list;
}

const alpn_extension_type: u8 = 16;
const alpn_list_len_octets: usize = 2;
const alpn_h2 = "\x02h2";
const alpn_h11 = "\x08http/1.1";

const h11_request = "GET / HTTP/1.1\r\n";
const h11_response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";

/// A response whose head nears h11's limit, then its content, which the server seals in records
/// of an odd size. After two records, 24,000 octets of the head wait in the connection, and the
/// head ends in the third record. That record opens only while the connection holds the head's
/// first two records beside room for a whole record (RFC 9112 §2.1, RFC 9846 §5.2). Test-only.
const long_head_len: usize = 30_000;
const long_content_len: usize = 6_000;
const odd_record_len: usize = 12_000;
var long_response: [long_head_len + long_content_len]u8 = undefined;
var long_body: [long_content_len]u8 = undefined;

/// The response of `long_head_len` octets of head and `long_content_len` of content. The
/// whitespace before its last field value fills the head: RFC 9112 §5 lets OWS stand there, and
/// RFC 9110 §5.6.3 lets OWS hold any number of SP.
fn long_response_octets() []const u8 {
    const status_and_fields = "HTTP/1.1 200 OK\r\nContent-Length: 6000\r\nPadding:";
    const end = "a\r\n\r\n";
    @memcpy(long_response[0..status_and_fields.len], status_and_fields);
    @memset(long_response[status_and_fields.len .. long_head_len - end.len], ' ');
    @memcpy(long_response[long_head_len - end.len .. long_head_len], end);
    @memset(long_response[long_head_len..], 'c');
    return &long_response;
}

/// The TLS server seals `plaintext` for the client in records of `record_len` octets of plaintext,
/// the last one shorter.
fn seal_in_records(plaintext: []const u8, record_len: usize) !void {
    // Bounded: each pass seals one record.
    for (0..plaintext.len / record_len + 1) |index| {
        const first = index * record_len;
        if (first == plaintext.len) return;
        try tls_support.server_seal(plaintext[first..@min(plaintext.len, first + record_len)]);
    }
}

test {
    // Decision 124: each test below runs on the default channel and on one with no QUIC.
    inline for (channel_support.channels) |Channel| _ = Tests(Channel);
}

/// The tests over a channel of type `Channel`, and the helpers that name the channel itself.
fn Tests(comptime Channel: type) type {
    return struct {
        /// The channel the tests drive, outside any stack frame. Test-only.
        var channel: Channel align(@alignOf(Channel)) = undefined;

        /// A channel with no receive pool, whose TCP connection runs over TLS and offers h2 and
        /// h11, to a server that selects h2. Its client trusts the root for `server_name`, and the
        /// server's certificate names localhost. `exchange` waits, and the connection the channel
        /// asked for is started, to the first address, with nothing sent. Returns the exchange's
        /// id.
        fn start(server_name: []const u8, exchange: *Exchange) !channel_module.Id {
            return start_with(.{}, &support.protocols_h2, server_name, exchange);
        }

        /// As `start`, with a client that speaks `versions` and a server that selects from
        /// `server_protocols`.
        fn start_with(versions: versions_module.Versions, server_protocols: []const []const u8, server_name: []const u8, exchange: *Exchange) !channel_module.Id {
            try tls_support.prepare_server(server_protocols, false);
            config = .{ .tls = tls_support.client_values(server_name), .versions = channel_support.versions_for(&channel, versions), .authority = support.authority };
            try channel.init(&config, .{ .addresses = &addresses, .port = https_port }, null);
            try tls_support.start_server();
            events_len = 0;
            const id = try channel.request(&exchange.request, &exchange.response);
            try collect(&channel);
            try testing.expectEqual(Transport.tcp, find(.open).?.open.transport);
            try testing.expect(find(.open).?.open.to.same_host(&addresses[0]));
            return id;
        }

        /// Writes what the channel's connection owes into the server's buffer.
        fn send() void {
            support.to_peer_len += channel.send_stream(support.to_peer[support.to_peer_len..], support.now_ns);
        }

        test "RFC 9846 §6.2: a channel asks for its transport's close once the alert of a refused handshake is written" {
            var exchange = get(&bodies[0]);
            // The certificate names localhost, and the client asks for another name.
            _ = try start("example.com", &exchange);
            send();
            // The server reads the ClientHello and writes its flight, which the client refuses.
            try testing.expectEqual(false, tls_support.server_flight().?);
            try collect(&channel);
            try testing.expect(channel.tcp.failed);
            // The caller reads the channel once more with no octets, as it does after each send.
            // The connection reported its close and holds the alert, so the channel asks for no
            // close yet.
            const polled = channel.receive(.none, support.now_ns);
            try testing.expectEqual(0, polled.consumed);
            try testing.expectEqual(null, polled.event);
            try testing.expectEqual(null, find(.close));
            try testing.expectEqual(0, support.to_peer_len);
            send();
            try testing.expectEqual(tls.record.alert_record_len, support.to_peer_len);
            // The server reads the record as the client's fatal alert, which ends its handshake.
            try testing.expectEqual(null, tls_support.server_flight());
            const provider = tls_support.server.provider();
            try testing.expectEqual(.peer, provider.vtable.take_alert(provider.context).?.origin);
            try collect(&channel);
            try testing.expectEqual(Transport.tcp, find(.close).?.close);
            // No connection carried the exchange, and the attempt has no other transport to open.
            try testing.expectEqual(.refused, exchange.response.outcome);
            try testing.expectEqual(1, count(.open));
        }

        /// The server's flight reaches the client with a record no key sealed after it, in the same
        /// octets, so the client completes its handshake and fails in one call (RFC 9846 §5.2).
        fn fail_at_completion(exchange: *Exchange) !void {
            _ = try start("localhost", exchange);
            send();
            try testing.expectEqual(false, tls_support.server_flight().?);
            forge();
            try collect(&channel);
            try testing.expect(channel.tcp.failed);
        }

        test "design §8 step 21c.5: a connection that fails in the call that completes its handshake carries nothing" {
            var exchange = get(&bodies[0]);
            try fail_at_completion(&exchange);
            try testing.expectEqual(null, find(.connected));
            try testing.expectEqual(null, find(.close));
            send();
            // The server reads the client's Finished, so the client's handshake did complete, and
            // then the alert that says why the connection ended.
            try testing.expectEqual(true, tls_support.server_flight().?);
            try testing.expectEqual(tls.record.alert_record_len, support.to_peer_len);
            const provider = tls_support.server.provider();
            try testing.expectError(error.TlsFailed, provider.vtable.decrypt_record(provider.context, support.to_peer[0..support.to_peer_len], &tls_support.peer_plain));
            try testing.expectEqual(.bad_record_mac, provider.vtable.take_alert(provider.context).?.description);
            try collect(&channel);
            try testing.expectEqual(Transport.tcp, find(.close).?.close);
            // The attempt went on with TCP counted in it, so it opened no second connection.
            try testing.expectEqual(null, find(.connected));
            try testing.expectEqual(.refused, exchange.response.outcome);
            try testing.expectEqual(&exchange.response, find(.finished).?.finished.response);
            try testing.expectEqual(&exchange.request, find(.finished).?.finished.request);
            try testing.expectEqual(1, count(.open));
        }

        test "design §8 step 21c.5: after a connection that carried nothing, the next request opens the next address" {
            var exchange = get(&bodies[0]);
            try fail_at_completion(&exchange);
            send();
            try collect(&channel);
            try testing.expectEqual(.refused, exchange.response.outcome);
            // The connection counts as a failed attempt, and a new request starts a new one.
            events_len = 0;
            _ = try channel.request(&exchange.request, &exchange.response);
            try collect(&channel);
            try testing.expectEqual(1, count(.open));
            try testing.expect(find(.open).?.open.to.same_host(&addresses[1]));
        }

        test "design §8 step 21c.5: a handshake that completes with no exchange waiting takes the next one" {
            var cancelled = get(&bodies[0]);
            const id = try start("localhost", &cancelled);
            channel.cancel(id);
            send();
            try testing.expectEqual(false, tls_support.server_flight().?);
            try collect(&channel);
            try testing.expectEqual(event.Protocol.h2, find(.connected).?.connected);
            send();
            try testing.expectEqual(true, tls_support.server_flight().?);
            support.peer_h2.init(.server);
            try support.peer_h2.attach_tls(tls_support.server.provider());
            // A later request goes out on that connection, and the channel opens no second one.
            var exchange = get(&bodies[1]);
            _ = try channel.request(&exchange.request, &exchange.response);
            try collect(&channel);
            send();
            try answer("hello");
            try collect(&channel);
            try testing.expectEqual(.response, exchange.response.outcome);
            try testing.expectEqualStrings("hello", exchange.response.content_received());
            try testing.expectEqual(1, count(.open));
        }

        /// The ClientHello a channel that speaks `versions` writes first, which no key seals.
        fn client_hello(versions: versions_module.Versions) ![]const u8 {
            var exchange = get(&bodies[0]);
            _ = try start_with(versions, &support.protocols_both, "localhost", &exchange);
            send();
            return support.to_peer[0..support.to_peer_len];
        }

        test "decision 120: versions gives the ALPN list a channel offers over TCP, h2 before h11" {
            // RFC 9113 §3.2 and decision 88: h2 goes first, which only the ClientHello's octets
            // show, since the server selects in its own order.
            const both = try client_hello(.{});
            try testing.expect(std.mem.indexOf(u8, both, alpn_extension(alpn_h2 ++ alpn_h11)) != null);
            const h2_alone = try client_hello(.{ .h11 = false });
            try testing.expect(std.mem.indexOf(u8, h2_alone, alpn_extension(alpn_h2)) != null);
            try testing.expectEqual(null, std.mem.indexOf(u8, h2_alone, alpn_h11));
            const h11_alone = try client_hello(.{ .h2 = false });
            try testing.expect(std.mem.indexOf(u8, h11_alone, alpn_extension(alpn_h11)) != null);
            try testing.expectEqual(null, std.mem.indexOf(u8, h11_alone, alpn_extension(alpn_h2)));
            // h3 is no protocol of a TCP connection (RFC 9114 §3.1), so turning it off changes
            // nothing.
            const without_h3 = try client_hello(.{ .h3 = false });
            try testing.expect(std.mem.indexOf(u8, without_h3, alpn_extension(alpn_h2 ++ alpn_h11)) != null);
        }

        test "decision 117: a channel whose versions turn h2 off runs h11 over TLS" {
            var exchange = get(&bodies[0]);
            // The server would select h2, and the client offers http/1.1 alone.
            _ = try start_with(.{ .h2 = false }, &support.protocols_both, "localhost", &exchange);
            send();
            try testing.expectEqual(false, tls_support.server_flight().?);
            try collect(&channel);
            try testing.expectEqual(event.Protocol.h11, find(.connected).?.connected);
            send();
            try testing.expectEqual(true, tls_support.server_flight().?);
            send();
            try tls_support.server_open();
            try testing.expect(std.mem.startsWith(u8, tls_support.peer_plain[0..tls_support.peer_plain_len], h11_request));
            try tls_support.server_seal(h11_response);
            try collect(&channel);
            try testing.expectEqual(.response, exchange.response.outcome);
            try testing.expectEqualStrings("hello", exchange.response.content_received());
            try testing.expectEqual(1, count(.open));
        }

        test "decision 88: a server that selects no protocol is spoken to in h11 while versions allows it" {
            var exchange = get(&bodies[0]);
            // The server holds no ALPN list, so it selects neither `h2` nor `http/1.1` of the
            // client's.
            _ = try start_with(.{}, &.{}, "localhost", &exchange);
            send();
            try testing.expectEqual(false, tls_support.server_flight().?);
            try collect(&channel);
            try testing.expectEqual(event.Protocol.h11, find(.connected).?.connected);
            try testing.expectEqual(null, find(.close));
        }

        test "RFC 9113 §3.3: with h11 off, a handshake that selected no protocol closes, and its exchange ends refused" {
            var exchange = get(&bodies[0]);
            _ = try start_with(.{ .h11 = false }, &.{}, "localhost", &exchange);
            send();
            try testing.expectEqual(false, tls_support.server_flight().?);
            try collect(&channel);
            // h2 over TLS runs only where ALPN selected it, so no protocol took the handshake.
            try testing.expectEqual(null, find(.connected));
            // The connection still holds the client's Finished, so the channel asks for no close
            // yet.
            try testing.expectEqual(null, find(.close));
            send();
            // The server reads the Finished, which completes its handshake, and no alert follows
            // it.
            try testing.expectEqual(true, tls_support.server_flight().?);
            try testing.expectEqual(0, support.to_peer_len);
            try collect(&channel);
            try testing.expectEqual(Transport.tcp, find(.close).?.close);
            // No connection carried the exchange, and the attempt has no other transport to open.
            try testing.expectEqual(.refused, exchange.response.outcome);
            try testing.expectEqual(1, count(.open));
        }

        /// A channel whose TCP connection speaks `protocol` over TLS, its handshake complete and
        /// `exchange` written. An h2 server reads what follows.
        fn start_open(protocol: event.Protocol, exchange: *Exchange) !void {
            const versions: versions_module.Versions = if (protocol == .h11) .{ .h2 = false } else .{};
            _ = try start_with(versions, &support.protocols_both, "localhost", exchange);
            send();
            try testing.expectEqual(false, tls_support.server_flight().?);
            try collect(&channel);
            try testing.expectEqual(protocol, find(.connected).?.connected);
            send();
            try testing.expectEqual(true, tls_support.server_flight().?);
            if (protocol == .h11) return;
            support.peer_h2.init(.server);
            try support.peer_h2.attach_tls(tls_support.server.provider());
        }

        test "decision 124: a record that fails after part of an h11 response ends the GET closed, not sent again" {
            var exchange = get(&bodies[0]);
            try start_open(.h11, &exchange);
            try tls_support.server_seal("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhel");
            forge();
            try collect(&channel);
            // h11 read the record before the one that failed (RFC 9846 §6), so some of the response
            // arrived, and the GET is not sent again (RFC 9110 §9.2.2).
            try testing.expectEqual(.closed, exchange.response.outcome);
            try testing.expectEqual(ok, exchange.response.status);
            try testing.expectEqual(1, count(.open));
        }

        test "decision 124: a record that fails after an h2 response's HEADERS ends the GET closed, not sent again" {
            var exchange = get(&bodies[0]);
            try start_open(.h2, &exchange);
            try answer_with("", false);
            forge();
            try collect(&channel);
            try testing.expectEqual(.closed, exchange.response.outcome);
            try testing.expectEqual(ok, exchange.response.status);
            try testing.expectEqual(1, count(.open));
        }

        test "decision 124: a record that fails after the HEADERS of a second h2 response ends that GET closed" {
            var first = get(&bodies[0]);
            var second = get(&bodies[1]);
            try start_open(.h2, &first);
            _ = try channel.request(&second.request, &second.response);
            send();
            try peer_h2_read();
            // One record holds the first response whole and the second's head, and the record
            // after it fails. The protocol reads both before the failure.
            const out = &tls_support.peer_out;
            var written = support.peer_h2.write_pending(out, support.now_ns);
            written += try support.peer_h2.write_response(out[written..], 1, ok, &.{}, true);
            written += try support.peer_h2.write_response(out[written..], 3, ok, &.{}, false);
            try tls_support.server_seal(out[0..written]);
            forge();
            try collect(&channel);
            try testing.expectEqual(.response, first.response.outcome);
            try testing.expectEqual(.closed, second.response.outcome);
            try testing.expectEqual(1, count(.open));
        }

        test "RFC 9112 §2.1: over TLS, a head near h11's limit in records of an odd size ends, and its content too" {
            var exchange: Exchange = .{ .request = .{ .method = "GET", .path = "/" }, .response = .{ .body = &long_body } };
            _ = try start_with(.{ .h2 = false }, &support.protocols_both, "localhost", &exchange);
            send();
            try testing.expectEqual(false, tls_support.server_flight().?);
            try collect(&channel);
            try testing.expectEqual(event.Protocol.h11, find(.connected).?.connected);
            send();
            try testing.expectEqual(true, tls_support.server_flight().?);
            try seal_in_records(long_response_octets(), odd_record_len);
            try collect(&channel);
            try testing.expectEqual(.response, exchange.response.outcome);
            try testing.expectEqual(ok, exchange.response.status);
            try testing.expectEqual(long_content_len, exchange.response.body_len);
            try testing.expectEqual(0, support.to_client_len);
        }
    };
}
