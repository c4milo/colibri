//! The tests of the client's TLS half (`connection_tls.zig`): the handshake runs against a colibri
//! TLS server in memory, ALPN's choice serves h2 or h11, and the server's records carry the
//! answers, a resumption ticket and its close_notify.
const std = @import("std");
const h11 = @import("h11");
const h2 = @import("h2");
const tls = @import("tls");
const tls_provider = @import("tls_provider");
const support = @import("connection_test_support.zig");
const event = @import("event.zig");

const testing = std.testing;
const connection = &support.connection;
const Exchange = support.Exchange;

const ok: u16 = 200;

/// The server the tests run against, its configuration, and the client's, outside any stack
/// frame. Test-only.
var server: tls.record.Server align(@alignOf(tls.record.Server)) = undefined;
var server_config: tls.record.ServerConfig align(@alignOf(tls.record.ServerConfig)) = undefined;
var client_config: tls.record.ClientConfig align(@alignOf(tls.record.ClientConfig)) = undefined;
/// The protocol's octets the server opened and has not read, and the ones it writes to seal.
var peer_plain: [support.buffer_len]u8 = undefined;
var peer_plain_len: usize = 0;
var peer_out: [support.buffer_len]u8 = undefined;
var bodies: [bodies_count][body_len]u8 = undefined;
const bodies_count: usize = 2;
const body_len: usize = 1024;

/// Rounds a handshake in memory takes at most. Test-only.
const handshake_rounds_max: usize = 8;
/// RFC 9846 §5.1: the content type of a plaintext handshake record. Test-only.
const content_handshake: u8 = 22;

/// A TLS connection whose client offers `client_protocols` to a server selecting from
/// `server_protocols`, trusting the root for `server_name`, with the handshake run until both
/// sides stop. With `tickets` the server issues resumption tickets (RFC 9846 §4.6.1).
fn start_tls(server_protocols: []const []const u8, client_protocols: []const []const u8, server_name: []const u8, tickets: bool) !void {
    try prepare_tls(server_protocols, client_protocols, server_name, tickets);
    try run_handshake();
}

/// The connection and the server of `start_tls`, before the handshake runs.
fn prepare_tls(server_protocols: []const []const u8, client_protocols: []const []const u8, server_name: []const u8, tickets: bool) !void {
    try server_config.init(.{
        .ecdsa_p256 = .{ .chain = &support.chain, .public_key = support.public_key, .private_key = support.private_key },
        .cookie_key = &support.cookie_key,
        .ticket_key = if (tickets) &support.ticket_key else null,
        .alpn = server_protocols,
    });
    try client_config.init(.{
        .trust = .{ .web_pki = .{ .anchors = &support.anchors, .server_name = server_name } },
        .alpn = client_protocols,
    });
    support.config = .{ .authority = support.authority, .tls = &client_config };
    try connection.init(&support.config, support.stream.random(), support.now_seconds, null);
    try server.start(&server_config, support.stream.random(), support.now_seconds);
    support.to_peer_len = 0;
    support.to_client_len = 0;
    support.events_len = 0;
    peer_plain_len = 0;
}

/// Moves the flights between the client and the server until the server completes, or the client
/// gives up.
fn run_handshake() !void {
    var complete = false;
    for (0..handshake_rounds_max) |_| {
        support.client_send();
        if (!complete) {
            const progress = server.handshake(support.to_peer[0..support.to_peer_len], support.to_client[support.to_client_len..]) catch {
                return;
            };
            take_to_peer(progress.consumed);
            support.to_client_len += progress.written;
            complete = progress.complete;
        }
        try support.client_receive();
        if (complete and connection.protocol() != null) return;
        if (support.find(.closed) != null) return;
    }
    return error.TestUnexpectedResult;
}

fn take_to_peer(consumed: usize) void {
    std.mem.copyForwards(u8, &support.to_peer, support.to_peer[consumed..support.to_peer_len]);
    support.to_peer_len -= consumed;
}

/// The server opens every whole record the client sent into `peer_plain`.
fn server_open() !void {
    const provider = server.provider();
    for (0..support.buffer_len) |_| {
        const record = try provider.vtable.decrypt_record(provider.context, support.to_peer[0..support.to_peer_len], peer_plain[peer_plain_len..]);
        if (record.content == .incomplete) return;
        take_to_peer(record.consumed);
        if (record.content == .application_data) peer_plain_len += record.plaintext_len;
    }
}

/// The server seals `plaintext` into records for the client.
fn server_seal(plaintext: []const u8) !void {
    const provider = server.provider();
    var taken: usize = 0;
    for (0..plaintext.len) |_| {
        if (taken == plaintext.len) return;
        const sealed = try provider.vtable.encrypt_record(provider.context, plaintext[taken..], support.to_client[support.to_client_len..]);
        taken += sealed.consumed;
        support.to_client_len += sealed.written;
    }
}

/// The h2 peer reads what the server opened, and answers stream 1 with `content`.
fn peer_h2_answer(content: []const u8) !?h2.connection.Request {
    return peer_h2_answer_with(&.{}, content);
}

/// `peer_h2_answer`, with `fields` in the response's header section.
fn peer_h2_answer_with(fields: []const h2.hpack.Field, content: []const u8) !?h2.connection.Request {
    var consumed: usize = 0;
    var request: ?h2.connection.Request = null;
    for (0..peer_plain_len + 1) |_| {
        const received = try support.peer_h2.receive(peer_plain[consumed..peer_plain_len], support.now_ns);
        if (received.consumed == 0) break;
        consumed += received.consumed;
        const peer_event = received.event orelse continue;
        if (peer_event == .request) request = peer_event.request;
    }
    var written = support.peer_h2.write_pending(&peer_out, support.now_ns);
    written += try support.peer_h2.write_response(peer_out[written..], 1, ok, fields, false);
    written += (try support.peer_h2.write_data(peer_out[written..], 1, content, true)).written;
    try server_seal(peer_out[0..written]);
    return request;
}

test "RFC 7301 §3.2: ALPN's h2 serves the connection, and an exchange goes out sealed" {
    try start_tls(&support.protocols_h2, &support.protocols_both, "localhost", false);
    try testing.expectEqual(event.Protocol.h2, support.find(.connected).?.connected);
    support.peer_h2.init(.server);
    try support.peer_h2.attach_tls(server.provider());
    var exchange: Exchange = .{ .method = "GET", .path = "/", .body = &bodies[0] };
    _ = try connection.request(&exchange);
    support.client_send();
    try server_open();
    const request = (try peer_h2_answer("hello")).?;
    // RFC 9110 §4.2.2: a request over TLS names the https scheme.
    try testing.expectEqualStrings("https", request.request.scheme.?);
    try support.client_receive();
    try testing.expectEqual(.response, exchange.outcome);
    try testing.expectEqualStrings("hello", exchange.content_received());
}

test "decision 88: ALPN's http/1.1 serves h11, and the client's close_notify follows the close" {
    try start_tls(&support.protocols_h11, &support.protocols_both, "localhost", false);
    try testing.expectEqual(event.Protocol.h11, support.find(.connected).?.connected);
    support.peer_h11.init(.server, .{});
    try support.peer_h11.attach_tls(server.provider());
    var exchange: Exchange = .{ .method = "GET", .path = "/", .body = &bodies[0] };
    _ = try connection.request(&exchange);
    support.client_send();
    try server_open();
    const received = try support.peer_h11.receive(peer_plain[0..peer_plain_len], &.{});
    try testing.expect(received.event.? == .request);
    const fields = [_]support.Field{ .{ .name = "Content-Length", .value = "2" }, .{ .name = "Connection", .value = "close" } };
    var written = try support.peer_h11.write_response(&peer_out, ok, "", &fields);
    written += try support.peer_h11.write_body(peer_out[written..], "hi");
    written += try support.peer_h11.write_end(peer_out[written..], &.{});
    try server_seal(peer_out[0..written]);
    try support.client_receive();
    try testing.expectEqualStrings("hi", exchange.content_received());
    try testing.expect(support.find(.closed) != null);
    support.to_peer_len = 0;
    support.client_send();
    // RFC 9846 §6.1: the client's close_notify goes out before it closes. RFC 9846 §5.2: the
    // record hides its type, so the server opens it to see an alert.
    const provider = server.provider();
    const record = try provider.vtable.decrypt_record(provider.context, support.to_peer[0..support.to_peer_len], &peer_plain);
    try testing.expectEqual(tls_provider.provider.Content.alert, record.content);
    try testing.expect(connection.should_close());
}

test "RFC 7838 §3: a final response's Alt-Svc over TLS names h3 once, for take_alt_svc" {
    try start_tls(&support.protocols_h11, &support.protocols_both, "localhost", false);
    support.peer_h11.init(.server, .{});
    try support.peer_h11.attach_tls(server.provider());
    var exchange: Exchange = .{ .method = "GET", .path = "/", .body = &bodies[0] };
    _ = try connection.request(&exchange);
    support.client_send();
    try server_open();
    _ = try support.peer_h11.receive(peer_plain[0..peer_plain_len], &.{});
    const fields = [_]support.Field{ .{ .name = "Content-Length", .value = "0" }, .{ .name = "Alt-Svc", .value = "h3=\":8443\"; ma=60" } };
    // A Content-Length of 0 ends the response with its head (RFC 9112 §6.3).
    const written = try support.peer_h11.write_response(&peer_out, ok, "", &fields);
    try server_seal(peer_out[0..written]);
    try support.client_receive();
    try testing.expectEqual(.response, exchange.outcome);
    const advert = connection.take_alt_svc() orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(u16, 8443), advert.h3.port);
    try testing.expectEqual(@as(u64, 60), advert.h3.max_age_s);
    try testing.expectEqual(null, connection.take_alt_svc());
}

test "RFC 7838 §3: an h2 response's Alt-Svc over TLS names h3 for take_alt_svc" {
    try start_tls(&support.protocols_h2, &support.protocols_both, "localhost", false);
    support.peer_h2.init(.server);
    try support.peer_h2.attach_tls(server.provider());
    var exchange: Exchange = .{ .method = "GET", .path = "/", .body = &bodies[0] };
    _ = try connection.request(&exchange);
    support.client_send();
    try server_open();
    const fields = [_]h2.hpack.Field{.{ .name = "alt-svc", .value = "h3=\":443\"" }};
    _ = try peer_h2_answer_with(&fields, "hello");
    try support.client_receive();
    try testing.expectEqual(.response, exchange.outcome);
    const advert = connection.take_alt_svc() orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(u16, 443), advert.h3.port);
}

test "RFC 9846 §4.6.1: a ticket the server issues is reported, and take_ticket hands it over once" {
    try start_tls(&support.protocols_h2, &support.protocols_both, "localhost", true);
    support.client_send();
    try support.client_receive();
    try testing.expect(support.find(.ticket) != null);
    var ticket = connection.take_ticket().?;
    defer ticket.wipe();
    try testing.expect(ticket.identity_len > 0);
    try testing.expectEqual(null, connection.take_ticket());
}

test "RFC 9846 §6.2: a handshake the client refuses ends the connection, and its exchange is refused" {
    var exchange: Exchange = .{ .method = "GET", .path = "/", .body = &bodies[0] };
    // The certificate names localhost, and the client asks for another name.
    try prepare_tls(&support.protocols_h2, &support.protocols_both, "example.com", false);
    _ = try connection.request(&exchange);
    try run_handshake();
    try support.client_receive();
    try testing.expectEqual(null, support.find(.connected));
    try testing.expect(connection.failed);
    // The server never saw the request, so it may go on another connection.
    try testing.expectEqual(.refused, exchange.outcome);
    try testing.expectError(error.ConnectionClosed, connection.request(&exchange));
    try testing.expect(support.find(.closed) != null);
    // The alert that says why goes out before the caller closes (RFC 9846 §6.2).
    try testing.expect(!connection.should_close());
    support.client_send();
    try testing.expect(connection.should_close());
}

test "RFC 9846 §6.1: the server's close_notify ends the exchange awaiting its response" {
    try start_tls(&support.protocols_h2, &support.protocols_both, "localhost", false);
    var exchange: Exchange = .{ .method = "GET", .path = "/", .body = &bodies[0] };
    _ = try connection.request(&exchange);
    support.client_send();
    const provider = server.provider();
    support.to_client_len += try provider.vtable.send_close_notify(provider.context, support.to_client[support.to_client_len..]);
    try support.client_receive();
    try testing.expectEqual(.closed, exchange.outcome);
    try testing.expect(support.find(.closed) != null);
}

test "RFC 9846 §4.1.2: the ClientHello goes out on the first send, before any receive" {
    try client_config.init(.{
        .trust = .{ .web_pki = .{ .anchors = &support.anchors, .server_name = "localhost" } },
        .alpn = &support.protocols_both,
    });
    support.config = .{ .authority = support.authority, .tls = &client_config };
    try connection.init(&support.config, support.stream.random(), support.now_seconds, null);
    support.to_peer_len = 0;
    support.client_send();
    try testing.expect(support.to_peer_len > tls_provider.constants.record_header_len);
    try testing.expectEqual(content_handshake, support.to_peer[0]);
    connection.transport_closed();
    _ = h11;
}
