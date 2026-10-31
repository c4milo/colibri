//! The tests of the client's record paths (`connection_tls.zig`) over a provider that protects
//! nothing (`plain_provider_test_support.zig`), which stands in for a finished handshake. It makes
//! what chapulin's server never sends: a KeyUpdate that asks for an answer.
const std = @import("std");
const tls_provider = @import("tls_provider");
const support = @import("connection_test_support.zig");
const tls_support = @import("connection_tls_test_support.zig");
const plain_support = @import("plain_provider_test_support.zig");
const connection_tls = @import("connection_tls.zig");
const constants = @import("../constants.zig");

const testing = std.testing;
const connection = &support.connection;
const header_len = tls_provider.constants.protocol.record_header_len;
const record_len_max = tls_provider.constants.protocol.record_plaintext_len_max;

/// The provider the tests attach in place of a handshake's session. Test-only.
var plain: plain_support.PlainProvider align(@alignOf(plain_support.PlainProvider)) = undefined;

const response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
const ok: u16 = 200;

/// Where each response's content goes: the test makes two exchanges. Test-only.
const requests_count = 2;
var bodies: [requests_count][response.len]u8 = undefined;

/// A request's content longer than the connection's own output, which `send` seals from the
/// caller's memory (https://github.com/c4milo/colibri/issues/105). Test-only.
var upload: [upload_len]u8 = undefined;
const upload_len: usize = outputs_per_upload * constants.limits.output_len;
const outputs_per_upload: usize = 2;

/// A connection over `plain` that selected http/1.1, as one whose handshake just completed. The
/// ClientHello that `init` staged never goes out. Test-only.
fn attach_plain() !void {
    try attach_plain_as(&support.protocols_h11);
}

/// `attach_plain`, for a connection whose handshake selected the one protocol `protocols` names.
/// Test-only.
fn attach_plain_as(protocols: []const []const u8) !void {
    try tls_support.prepare_tls(protocols, protocols, support.authority, false);
    connection.output_len = 0;
    connection.records_len = 0;
    plain = .{ .alpn = protocols[0] };
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
    try testing.expectEqual(.response, first.response.result);
    try testing.expectEqual(ok, first.response.status);
    try testing.expectEqualStrings("hi", first.response.body_received());
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
    try testing.expectEqual(.response, first.response.result);
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

/// A PUT of `upload`. Test-only.
fn put_upload() support.Exchange {
    @memset(&upload, 'x');
    return .{ .request = .{ .method = "PUT", .path = "/object", .body = &upload }, .response = .{ .body = &bodies[0] } };
}

test "a small request content goes out in the record of its head" {
    try attach_plain();
    var post: support.Exchange = .{ .request = .{ .method = "POST", .path = "/", .body = "query" }, .response = .{ .body = &bodies[0] } };
    _ = try connection.request(&post.request, &post.response);
    support.client_send();
    const sent = support.to_peer[0..support.to_peer_len];
    const record = plain_support.open(sent).?;
    try testing.expectEqual(sent.len, header_len + record.content.len);
    try testing.expect(std.mem.endsWith(u8, record.content, "\r\n\r\nquery"));
}

test "a content longer than the connection's output is sealed from the caller's memory in one send" {
    try attach_plain();
    var put = put_upload();
    _ = try connection.request(&put.request, &put.response);
    support.client_send();
    try testing.expectEqual(upload_len, put.response.body_sent);
    // The head and the start of the content fill the first record, and the rest follows whole.
    const sent = support.to_peer[0..support.to_peer_len];
    var offset: usize = 0;
    var plaintext_len: usize = 0;
    // Bounded: each pass reads one record.
    for (0..sent.len) |_| {
        const record = plain_support.open(sent[offset..]) orelse break;
        if (offset == 0) try testing.expectEqual(record_len_max, record.content.len);
        @memcpy(tls_support.peer_plain[plaintext_len..][0..record.content.len], record.content);
        plaintext_len += record.content.len;
        offset += header_len + record.content.len;
    }
    try testing.expectEqual(sent.len, offset);
    const plaintext = tls_support.peer_plain[0..plaintext_len];
    try testing.expect(std.mem.startsWith(u8, plaintext, "PUT /object HTTP/1.1"));
    const head_len = std.mem.indexOf(u8, plaintext, "\r\n\r\n").? + 4;
    try testing.expectEqualSlices(u8, &upload, plaintext[head_len..]);
}

test "RFC 9846 §6: a record refused while the content is sealed ends the connection" {
    try attach_plain();
    var put = put_upload();
    _ = try connection.request(&put.request, &put.response);
    // The output holds one record: the head and the start of the content.
    const one_record = header_len + record_len_max;
    support.to_peer_len = connection.send(support.to_peer[0..one_record], support.now_ns);
    try testing.expectEqual(one_record, support.to_peer_len);
    try testing.expect(put.response.body_sent < upload_len);
    plain.refuse_seal = true;
    support.client_send();
    // No data goes out after the failure, and the exchange ends with the connection.
    try testing.expect(connection.failed);
    try testing.expectEqual(one_record, support.to_peer_len);
    try support.client_receive();
    // RFC 9112 §9.6: the request went out in part, so it ends with the connection.
    try testing.expectEqual(.closed, put.response.result);
    try testing.expect(support.find(.closed) != null);
}

test "RFC 9846 §6: a record refused while an h2 frame is sealed ends the connection" {
    try attach_plain_as(&support.protocols_h2);
    var put = put_upload();
    _ = try connection.request(&put.request, &put.response);
    // The output holds one record: the preface, the SETTINGS, the head and the start of the content.
    const one_record = header_len + record_len_max;
    support.to_peer_len = connection.send(support.to_peer[0..one_record], support.now_ns);
    try testing.expectEqual(one_record, support.to_peer_len);
    try testing.expect(put.response.body_sent < upload_len);
    plain.refuse_seal = true;
    support.client_send();
    // Decision 139: no frame goes out after the failure, and the exchange ends with the connection.
    try testing.expect(connection.failed);
    try testing.expectEqual(one_record, support.to_peer_len);
    try support.client_receive();
    try testing.expectEqual(.closed, put.response.result);
}
