//! The tests of what a failed record-mode handshake owes the peer (`record.zig`): the alert that
//! says why, which chapulin writes in the clear before the failing side's write key is installed and
//! sealed after it, and which the caller sends from `failure_written` (RFC 9846 §6.2). Split out of
//! `record_test.zig` for length.
const std = @import("std");
const tls_provider = @import("tls_provider");
const record = @import("record.zig");
const values = @import("../values.zig");
const support = @import("record_test_support.zig");

const testing = std.testing;
const client = &support.client;
const server = &support.server;
const to_server = &support.to_server;
const to_client = &support.to_client;

const record_header_len = tls_provider.constants.record_header_len;
/// RFC 9846 §5.1: the content type of an alert record.
const content_type_alert: u8 = 21;
/// RFC 9846 §6: an alert is its level and its description, and every error alert is fatal.
const alert_body_len: usize = 2;
const level_fatal: u8 = 2;
/// An alert record in the clear: the record header, then the alert.
const clear_alert_len = record_header_len + alert_body_len;
/// RFC 9846 §4: a handshake message's type is the octet after the record header, and 2 is a
/// ServerHello, which a server never reads.
const server_hello_type: u8 = 2;

/// Starts both sides and writes the ClientHello into `to_server`.
fn start_and_hello() !void {
    to_server.* = .{};
    to_client.* = .{};
    try client.start(&support.client_config, support.random(), support.now_seconds, null);
    try server.start(&support.server_config, support.random(), support.now_seconds);
    to_server.len += (try client.handshake(&.{}, to_server.free())).written;
}

/// Moves the server's flight, which answers the ClientHello, into `to_client`.
fn server_flight() !void {
    const flight = try server.handshake(to_server.held(), to_client.free());
    to_server.take(flight.consumed);
    to_client.len += flight.written;
}

/// Checks that `provider`'s side read the peer's fatal alert `description`.
fn expect_peer_alert(provider: tls_provider.Provider, description: ?u8) !void {
    const report = provider.vtable.take_alert(provider.context).?;
    try testing.expectEqual(tls_provider.AlertReport.Origin.peer, report.origin);
    try testing.expectEqual(description.?, @intFromEnum(report.description));
}

test "RFC 9846 §6.2: a server that refuses its first message sends the alert in the clear" {
    try support.configure(support.web_pki, .{});
    try start_and_hello();
    to_server.held()[record_header_len] = server_hello_type;
    try testing.expectError(error.HandshakeFailed, server.handshake(to_server.held(), to_client.free()));
    const alert = to_client.free()[0..server.failure_written()];
    try testing.expectEqual(clear_alert_len, alert.len);
    try testing.expectEqual(content_type_alert, alert[0]);
    try testing.expectEqual(level_fatal, alert[record_header_len]);
    try testing.expectEqual(server.alert().?, alert[clear_alert_len - 1]);
    to_client.len += alert.len;
    // The client reads it as the server's fatal alert, which nothing answers.
    try testing.expectError(error.HandshakeFailed, client.handshake(to_client.held(), to_server.free()));
    try testing.expectEqual(0, client.failure_written());
    try testing.expectEqual(null, client.alert());
    try expect_peer_alert(client.provider(), server.alert());
}

test "RFC 9846 §6.2: a client that refuses the server's chain sends the alert sealed" {
    // The leaf's own key is no anchor of the chain.
    const impostor = [_]values.Anchor{.{ .subject = support.root_name, .spki = support.public_key }};
    try support.configure(.{ .trust = .{ .web_pki = .{ .anchors = &impostor, .server_name = "localhost" } }, .alpn = &support.protocols, .cpu = support.cpu }, .{});
    try start_and_hello();
    try server_flight();
    try testing.expectError(error.HandshakeFailed, client.handshake(to_client.held(), to_server.free()));
    // The client's write key is installed after the ServerHello, so the alert is sealed.
    try testing.expectEqual(record.alert_record_len, client.failure_written());
    to_server.len += client.failure_written();
    // The server reads it as the client's fatal alert, which nothing answers.
    try testing.expectError(error.HandshakeFailed, server.handshake(to_server.held(), to_client.free()));
    try testing.expectEqual(0, server.failure_written());
    try expect_peer_alert(server.provider(), client.alert());
}

test "RFC 9846 §6.2: a server that refuses the client's Finished sends the alert sealed" {
    try support.configure(support.web_pki, .{});
    try start_and_hello();
    try server_flight();
    const finished = try client.handshake(to_client.held(), to_server.free());
    to_client.take(finished.consumed);
    to_server.len += finished.written;
    try testing.expect(finished.complete);
    // RFC 9846 §5.2: a record changed in its last octet fails authentication.
    to_server.held()[to_server.len - 1] ^= 1;
    try testing.expectError(error.HandshakeFailed, server.handshake(to_server.held(), to_client.free()));
    try testing.expectEqual(record.alert_record_len, server.failure_written());
    to_client.len += server.failure_written();
    // The client, whose handshake completed, opens it as the server's fatal alert.
    const provider = client.provider();
    try testing.expectError(error.TlsFailed, provider.vtable.decrypt_record(provider.context, to_client.held(), &support.scratch));
    try expect_peer_alert(provider, server.alert());
}

test "a client reads nothing while its output cannot take a whole alert" {
    try support.configure(support.web_pki, .{});
    try start_and_hello();
    try server_flight();
    var short: [record.alert_record_len - 1]u8 = undefined;
    const waited = try client.handshake(to_client.held(), &short);
    try testing.expectEqual(0, waited.consumed + waited.written);
    // With room for the alert, it reads the flight and writes its Finished.
    const finished = try client.handshake(to_client.held(), to_server.free());
    try testing.expectEqual(to_client.len, finished.consumed);
    try testing.expect(finished.complete);
}
