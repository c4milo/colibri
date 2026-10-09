//! The tests of the server's record paths (`connection_tls.zig`) over a provider that protects
//! nothing (`plain_provider_test_support.zig`), which stands in for a finished handshake. It
//! reaches what chapulin's records never make happen: a peer's KeyUpdate, a seal the provider
//! refuses, and a handshake below TLS 1.3.
const std = @import("std");
const h11 = @import("h11");
const h2 = @import("h2");
const tls_provider = @import("tls_provider");
const support = @import("connection_test_support.zig");
const plain_support = @import("../plain_provider_test_support.zig");
const connection_tls = @import("connection_tls.zig");
const connection_owed = @import("connection_owed.zig");

const testing = std.testing;
const connection = &support.connection;
const header_len = tls_provider.constants.record_header_len;

/// The provider the tests attach in place of a handshake's session. Test-only.
var plain: plain_support.PlainProvider align(@alignOf(plain_support.PlainProvider)) = undefined;

const request = "GET / HTTP/1.1\r\nHost: a\r\n\r\n";
const ok: u16 = 200;

/// A connection over `plain` that selected http/1.1, as one whose handshake just completed. The
/// configuration names a TLS configuration the connection never reads once its protocol is open.
/// Test-only.
fn attach_plain() !void {
    support.config = .{ .versions = support.only(.h11) };
    try attach_plain_with(.{ .alpn = "http/1.1" });
}

/// `attach_plain` with `chosen` as the provider, under `support.config`. Test-only.
fn attach_plain_with(chosen: plain_support.PlainProvider) !void {
    try connection.init(&support.config, support.stream.random(), 0, 0);
    support.config.tls = &support.server_config;
    plain = chosen;
    connection.phase = .handshake;
    try connection_tls.attach(connection, plain.provider());
}

/// Seals `content` as one record of `content_type` at `offset` of the test input. Test-only.
fn record_at(offset: usize, content_type: u8, content: []const u8) !usize {
    return (try plain_support.seal(content_type, content, support.input[offset..])).len;
}

test "RFC 9846 §4.7.3: a peer's KeyUpdate is answered before the next record opens" {
    try attach_plain();
    const update_len = try record_at(0, plain_support.content_handshake, &plain_support.key_update_requested);
    const request_len = try record_at(update_len, plain_support.content_application_data, request);
    var received = try connection.receive(support.input[0 .. update_len + request_len], support.now_ns);
    try testing.expectEqual(update_len, received.consumed);
    try testing.expectEqual(null, received.event);
    // Decision 119: the reply is octets `send` owes, which a server's endpoint reports as `send`.
    try testing.expect(connection_owed.owes_octets(connection));
    // The reply goes out alone, and the next record opens after it.
    const sent = support.drain();
    try testing.expect(!connection_owed.owes_octets(connection));
    const reply = plain_support.open(sent).?;
    try testing.expectEqual(plain_support.content_handshake, reply.content_type);
    try testing.expectEqualSlices(u8, &plain_support.key_update_not_requested, reply.content);
    try testing.expectEqual(header_len + reply.content.len, sent.len);
    received = try connection.receive(support.input[update_len .. update_len + request_len], support.now_ns);
    try testing.expectEqual(request_len, received.consumed);
    try testing.expectEqual(1, received.event.?.request.id.number);
}

test "RFC 9846 §6.1: a record after the peer's close_notify is not read" {
    try attach_plain();
    const close_len = try record_at(0, plain_support.content_alert, &plain_support.close_notify);
    const request_len = try record_at(close_len, plain_support.content_application_data, request);
    const received = try connection.receive(support.input[0 .. close_len + request_len], support.now_ns);
    try testing.expectEqual(close_len, received.consumed);
    try testing.expectEqual(null, received.event);
}

test "decision 110: a run of records carrying no data ends the connection, and the limit is named" {
    for ([_][]const u8{ "http/1.1", "h2" }) |alpn| {
        support.config = .{ .versions = support.only(.h11) };
        try attach_plain_with(.{ .alpn = alpn });
        // An empty record of application data carries no data, as a ticket does.
        var sealed: usize = 0;
        for (0..h2.core.constants.records_without_data_max + 1) |_| {
            sealed += try record_at(sealed, plain_support.content_application_data, "");
        }
        try testing.expectError(error.ConnectionFailed, connection.receive(support.input[0..sealed], support.now_ns));
        try testing.expectEqual(.records_without_data, connection.close_reason().?.limit);
    }
}

test "RFC 9846 §6: a record the provider will not seal ends the connection, and no data follows" {
    try attach_plain();
    const request_len = try record_at(0, plain_support.content_application_data, request);
    _ = try connection.receive(support.input[0..request_len], support.now_ns);
    try connection.respond(1, .{ .status = ok, .end = true });
    plain.refuse_seal = true;
    try testing.expectEqual(0, connection.send(&support.output, support.now_ns));
    try testing.expectEqual(0, connection.output_len);
    try testing.expect(connection.should_close());
    try testing.expectError(error.ConnectionClosed, connection.respond(1, .{ .status = ok, .end = true }));
}

test "RFC 9113 §9.2: a handshake below TLS 1.3 serves no HTTP, and the connection closes" {
    support.config = .{ .versions = support.only(.h11) };
    try testing.expectError(error.ConnectionFailed, attach_plain_with(.{ .alpn = "h2", .version = tls_provider.constants.version_tls_1_2 }));
    try testing.expect(connection.should_close());
    // Nothing is sealed after the connection closed.
    try testing.expectEqual(0, connection.send(&support.output, support.now_ns));
}

test "RFC 9846 §5.1: what the protocol has not read waits, and the next record opens after it" {
    try attach_plain();
    // Two requests in one record: h11 reads the second only after the first is answered.
    const both = "GET /one HTTP/1.1\r\nHost: a\r\n\r\nGET /two HTTP/1.1\r\nHost: a\r\n\r\n";
    const record_len = try record_at(0, plain_support.content_application_data, both);
    var received = try connection.receive(support.input[0..record_len], support.now_ns);
    try testing.expectEqual(record_len, received.consumed);
    try testing.expectEqualStrings("/one", received.event.?.request.path.?);
    received = try connection.receive(&.{}, support.now_ns);
    try testing.expectEqual(null, received.event);
    try connection.respond(1, .{ .status = ok, .end = true });
    try support.expect_done(1);
    received = try connection.receive(&.{}, support.now_ns);
    try testing.expectEqual(2, received.event.?.request.id.number);
    try testing.expectEqualStrings("/two", received.event.?.request.path.?);
}

test "RFC 9846 §5.1: a record that has not all arrived waits for its last octets" {
    try attach_plain();
    const request_len = try record_at(0, plain_support.content_application_data, request);
    const received = try connection.receive(support.input[0 .. request_len - 1], support.now_ns);
    try testing.expectEqual(0, received.consumed);
    try testing.expectEqual(null, received.event);
}

/// A request whose content is more than `plaintext_in_len` holds at once: three records of the
/// largest plaintext. Test-only.
const upload_head = "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 49152\r\n\r\n";
const upload_records: usize = 3;
var upload_content: [tls_provider.constants.record_plaintext_len_max]u8 = @splat('u');

test "RFC 9846 §5.1: records open while the protocol's octets have room, and the rest wait" {
    try attach_plain();
    var sealed = try record_at(0, plain_support.content_application_data, upload_head);
    for (0..upload_records) |_| sealed += try record_at(sealed, plain_support.content_application_data, &upload_content);
    const received = try connection.receive(support.input[0..sealed], support.now_ns);
    try testing.expect(received.consumed > 0 and received.consumed < sealed);
    try testing.expectEqual(1, received.event.?.request.id.number);
}

/// The decoder pool and buffer of the coded-body test (decisions 91 and 98). Test-only.
var decoders: h11.coding.Pool(1) align(@alignOf(h11.coding.Pool(1))) = undefined;
var decoded: [decoded_len]u8 = undefined;
const decoded_len: usize = 1024;

/// A gzip body of "hello" whose first chunk holds only the gzip header (RFC 1952 §2.3), so that
/// chunk decodes to nothing. Test-only.
const coded_request = "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: gzip, chunked\r\n\r\n" ++
    "a\r\n\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff\r\n" ++
    "f\r\n\xcb\x48\xcd\xc9\xc9\x07\x00\x86\xa6\x10\x36\x05\x00\x00\x00\r\n0\r\n\r\n";

test "RFC 9112 §7.2: content after a chunk that decodes to nothing is read in the same call" {
    decoders.storage().reset(h11.coding.Features.target());
    support.config = .{ .versions = support.only(.h11), .decoders = decoders.storage(), .decoded = &decoded };
    try attach_plain_with(.{ .alpn = "http/1.1" });
    const record_len = try record_at(0, plain_support.content_application_data, coded_request);
    const head = try connection.receive(support.input[0..record_len], support.now_ns);
    try testing.expectEqual(1, head.event.?.request.id.number);
    // Every record is open, so the rest arrives with nothing more consumed.
    const body = try connection.receive(&.{}, support.now_ns);
    try testing.expectEqualStrings("hello", body.event.?.body.octets);
}

test "decision 91: a transport that closed gives back the decoder its coded body held" {
    decoders.storage().reset(h11.coding.Features.target());
    // The pool holds one decoder, which the first connection's body takes.
    for (0..2) |_| {
        support.config = .{ .versions = support.only(.h11), .decoders = decoders.storage(), .decoded = &decoded };
        try attach_plain_with(.{ .alpn = "http/1.1" });
        const head_len = coded_request.len - "0\r\n\r\n".len;
        const record_len = try record_at(0, plain_support.content_application_data, coded_request[0..head_len]);
        const received = try connection.receive(support.input[0..record_len], support.now_ns);
        try testing.expectEqual(1, received.event.?.request.id.number);
        connection.transport_closed();
    }
}
