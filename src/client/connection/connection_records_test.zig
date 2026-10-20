//! The tests of the client's record paths (`connection_tls.zig`) over a provider that protects
//! nothing (`plain_provider_test_support.zig`), which stands in for a finished handshake. It makes
//! what chapulin's server never sends: a KeyUpdate that asks for an answer.
const std = @import("std");
const tls_provider = @import("tls_provider");
const support = @import("connection_test_support.zig");
const tls_support = @import("connection_tls_test_support.zig");
const plain_support = @import("plain_provider_test_support.zig");
const connection_tls = @import("connection_tls.zig");

const testing = std.testing;
const connection = &support.connection;
const header_len = tls_provider.constants.record_header_len;

/// The provider the tests attach in place of a handshake's session. Test-only.
var plain: plain_support.PlainProvider align(@alignOf(plain_support.PlainProvider)) = undefined;

const response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
const ok: u16 = 200;

/// Where each response's content goes: the test makes two exchanges. Test-only.
const exchanges_count = 2;
var bodies: [exchanges_count][response.len]u8 = undefined;

/// A connection over `plain` that selected http/1.1, as one whose handshake just completed. The
/// ClientHello that `init` staged never goes out. Test-only.
fn attach_plain() !void {
    try tls_support.prepare_tls(&support.protocols_h11, &support.protocols_h11, support.authority, false);
    connection.output_len = 0;
    connection.records_len = 0;
    plain = .{ .alpn = "http/1.1" };
    try testing.expect(connection_tls.attach_provider(connection, plain.provider()));
    support.to_peer_len = 0;
    support.to_client_len = 0;
}

/// Seals `content` as one record of `content_type` after what the peer already wrote. Test-only.
fn peer_record(content_type: u8, content: []const u8) !void {
    support.to_client_len += (try plain_support.seal(content_type, content, support.to_client[support.to_client_len..])).len;
}

/// Seals `count` KeyUpdates that ask for an answer, each in its own record, after what the peer
/// already wrote. Test-only.
fn peer_key_updates(count: usize) !void {
    for (0..count) |_| try peer_record(plain_support.content_handshake, &plain_support.key_update_requested);
}

test "RFC 9846 §4.7.3: a record opens while a KeyUpdate's answer is owed, and the answer comes first" {
    try attach_plain();
    var first: support.Exchange = .{ .request = .{ .method = "GET", .path = "/a" }, .response = .{ .body = &bodies[0] } };
    _ = try connection.request(&first.request, &first.response);
    support.client_send();
    support.to_peer_len = 0;
    // The server asks for a KeyUpdate, then answers in the next record.
    try peer_record(plain_support.content_handshake, &plain_support.key_update_requested);
    try peer_record(plain_support.content_application_data, response);
    try support.client_receive();
    // The response behind the KeyUpdate opens with the answer still owed.
    try testing.expectEqual(0, support.to_client_len);
    try testing.expectEqual(.response, first.response.outcome);
    try testing.expectEqual(ok, first.response.status);
    try testing.expectEqualStrings("hi", first.response.content_received());
    // RFC 9846 §4.7.3: the answer is sent "prior to sending its next Application Data record".
    // Alone it is no debt, so no `send` comes for it (decision 125): the provider writes it in
    // front of the next record of data.
    try testing.expect(!connection.owes_octets());
    var second: support.Exchange = .{ .request = .{ .method = "GET", .path = "/b" }, .response = .{ .body = &bodies[1] } };
    _ = try connection.request(&second.request, &second.response);
    support.client_send();
    const sent = support.to_peer[0..support.to_peer_len];
    const answer = plain_support.open(sent).?;
    try testing.expectEqual(plain_support.content_handshake, answer.content_type);
    try testing.expectEqualSlices(u8, &plain_support.key_update_not_requested, answer.content);
    const next = plain_support.open(sent[header_len + answer.content.len ..]).?;
    try testing.expectEqual(plain_support.content_application_data, next.content_type);
    try testing.expect(std.mem.startsWith(u8, next.content, "GET /b HTTP/1.1"));
    try testing.expect(!connection.owes_octets());
}

test "a record of data ends a run of KeyUpdates, so the next run has the whole limit" {
    try attach_plain();
    var first: support.Exchange = .{ .request = .{ .method = "GET", .path = "/a" }, .response = .{ .body = &bodies[0] } };
    _ = try connection.request(&first.request, &first.response);
    support.client_send();
    support.to_peer_len = 0;
    // A full run, the response, and a second full run: no run passes the provider's limit.
    try peer_key_updates(plain_support.key_update_run_max);
    try peer_record(plain_support.content_application_data, response);
    try peer_key_updates(plain_support.key_update_run_max);
    try support.client_receive();
    try testing.expectEqual(0, support.to_client_len);
    try testing.expectEqual(.response, first.response.outcome);
    try testing.expect(!connection.failed);
    // No record of data followed the second run, so one more KeyUpdate passes the limit.
    try peer_key_updates(1);
    try support.client_receive();
    try testing.expect(connection.failed);
    // RFC 9846 §6: the connection sends the alert alone, with no answer and no data around it.
    support.client_send();
    const sent = support.to_peer[0..support.to_peer_len];
    const alert = plain_support.open(sent).?;
    try testing.expectEqual(sent.len, header_len + alert.content.len);
    try testing.expectEqual(plain_support.content_alert, alert.content_type);
    // `take_alert` names the alert that this side sent, as the provider's contract says.
    const view = plain.provider();
    const report = view.vtable.take_alert(view.context).?;
    try testing.expectEqual(tls_provider.Alert.unexpected_message, report.description);
    try testing.expectEqual(tls_provider.AlertReport.Origin.local, report.origin);
}
