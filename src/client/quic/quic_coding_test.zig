//! The tests of content codings at the client over h3 (`coding.zig`, decision 101): the request
//! offers gzip first with a decoder taken, and a coded response decodes into the exchange's body.
const std = @import("std");
const gzip = @import("gzip");
const support = @import("quic_test_support.zig");
const tcp_support = @import("../connection/connection_test_support.zig");

const testing = std.testing;
const connection = &support.connection;
const HttpExchange = support.HttpExchange;

const decoders_all: usize = 2;
const text = "colibri decodes an h3 response the server coded. " ** text_repeats;
const text_repeats: usize = 8;

/// Where the test codes content and where the exchange puts its response. Test-only.
threadlocal var gzip_encoder: gzip.Encoder(.{ .level = 1 }) align(@alignOf(gzip.Encoder(.{ .level = 1 }))) = undefined;
threadlocal var coded_room: [room_factor * text.len]u8 = undefined;
threadlocal var body: [room_factor * text.len]u8 = undefined;
/// Room for the text coded, which stored blocks never double, and for it decoded.
const room_factor: usize = 2;

/// A client that offers the codings of the TCP tests' pool, every decoder free, and its server.
fn start_coding() !void {
    try support.prepare(&support.alpn_h3, &support.alpn_h3, false);
    const storage = tcp_support.pool.storage();
    storage.reset(.none());
    support.config.codings = &tcp_support.codings;
    support.config.decoders = storage;
    try connection.init(&support.config, support.client_pool.storage(), support.client_start, tcp_support.stream.random(), tcp_support.now_seconds, support.now_ns, null);
}

test "decision 101: an h3 request offers gzip first, and the coded response decodes into the body" {
    try start_coding();
    gzip_encoder.init(.none());
    const coded = coded_room[0..try gzip_encoder.encode_all(text, &coded_room)];
    support.answer_content = coded;
    support.answer_coding = "gzip";
    var exchange: HttpExchange = .{ .method = "GET", .path = "/", .body = &body };
    _ = try connection.request(&exchange);
    try support.pump(support.rounds_default);
    try testing.expect(support.answers[0].offers_gzip);
    try testing.expectEqual(.response, exchange.outcome);
    try testing.expectEqual(.gzip, exchange.coding.?);
    try testing.expectEqualStrings(text, exchange.content_received());
    try testing.expectEqual(decoders_all, tcp_support.pool.storage().free_count());
}

test "decision 101: an h3 response whose coded stream is cut short ends malformed" {
    try start_coding();
    gzip_encoder.init(.none());
    const coded = coded_room[0..try gzip_encoder.encode_all(text, &coded_room)];
    // RFC 1952 §2.3: the member's last octet, of its trailer, never arrives.
    support.answer_content = coded[0 .. coded.len - 1];
    support.answer_coding = "gzip";
    var exchange: HttpExchange = .{ .method = "GET", .path = "/", .body = &body };
    _ = try connection.request(&exchange);
    try support.pump(support.rounds_default);
    try testing.expectEqual(.malformed, exchange.outcome);
    try testing.expectEqual(decoders_all, tcp_support.pool.storage().free_count());
}
