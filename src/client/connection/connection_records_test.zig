//! The tests of the client's record paths (`connection_tls.zig`) over a provider that protects
//! nothing (`plain_provider_test_support.zig`), which stands in for a finished handshake. It makes
//! what chapulin's server never sends: a KeyUpdate that asks for a reply.
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

test "RFC 9846 §4.7.3: records keep opening while a KeyUpdate's reply is owed, which goes out first" {
    try attach_plain();
    var first: support.Exchange = .{ .request = .{ .method = "GET", .path = "/a" }, .response = .{ .body = &bodies[0] } };
    _ = try connection.request(&first.request, &first.response);
    support.client_send();
    support.to_peer_len = 0;
    // The server asks for a KeyUpdate, then answers in the next record.
    try peer_record(plain_support.content_handshake, &plain_support.key_update_requested);
    try peer_record(plain_support.content_application_data, response);
    try support.client_receive();
    // The answer behind the KeyUpdate opens with the reply still owed.
    try testing.expectEqual(0, support.to_client_len);
    try testing.expectEqual(.response, first.response.outcome);
    try testing.expectEqual(ok, first.response.status);
    try testing.expectEqualStrings("hi", first.response.content_received());
    // RFC 9846 §4.7.3: the reply goes out "prior to sending its next Application Data record".
    var second: support.Exchange = .{ .request = .{ .method = "GET", .path = "/b" }, .response = .{ .body = &bodies[1] } };
    _ = try connection.request(&second.request, &second.response);
    support.client_send();
    const sent = support.to_peer[0..support.to_peer_len];
    const reply = plain_support.open(sent).?;
    try testing.expectEqual(plain_support.content_handshake, reply.content_type);
    try testing.expectEqualSlices(u8, &plain_support.key_update_not_requested, reply.content);
    const next = plain_support.open(sent[header_len + reply.content.len ..]).?;
    try testing.expectEqual(plain_support.content_application_data, next.content_type);
    try testing.expect(std.mem.startsWith(u8, next.content, "GET /b HTTP/1.1"));
}
