//! The tests of content codings at the client over h3 (`coding.zig`, decision 101 as amended): the
//! request offers gzip first with a decoder taken, and a response coded in gzip, zstd or br decodes
//! into the exchange's body.
const std = @import("std");
const gzip = @import("gzip");
const http = @import("http");
const support = @import("quic_test_support.zig");
const tcp_support = @import("../connection/connection_test_support.zig");
const coding_support = @import("../coding_test_support.zig");

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
/// Where an exchange puts the text the `zstd` and `br` fixtures code. Test-only.
threadlocal var plain_body: [coding_support.plain.len]u8 = undefined;
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

/// A client that offers `zstd` and `br`, each pool of one decoder free, and its server.
fn start_zstd_br() !void {
    try support.prepare(&support.alpn_h3, &support.alpn_h3, false);
    coding_support.reset_pools();
    support.config.codings = &zstd_br;
    support.config.zstd_decoders = coding_support.zstd_pool.storage();
    support.config.br_decoders = coding_support.br_pool.storage();
    try connection.init(&support.config, support.client_pool.storage(), support.client_start, tcp_support.stream.random(), tcp_support.now_seconds, support.now_ns, null);
}

const zstd_br = [_]http.content_coding.Coding{ .zstd, .br };

test "decision 101 as amended: an h3 response in zstd, and one in br, decode into the body" {
    const names = [_][]const u8{ "zstd", "br" };
    const coded = [_][]const u8{ coding_support.plain_zst, coding_support.plain_br };
    for (names, coded) |name, content| {
        try start_zstd_br();
        support.answer_content = content;
        support.answer_coding = name;
        var exchange: HttpExchange = .{ .method = "GET", .path = "/", .body = &plain_body };
        _ = try connection.request(&exchange);
        try support.pump(support.rounds_default);
        try testing.expectEqual(.response, exchange.outcome);
        try testing.expectEqualStrings(name, exchange.coding.?.name());
        try testing.expectEqualStrings(coding_support.plain, exchange.content_received());
        try testing.expectEqual(1, coding_support.zstd_pool.storage().free_count());
        try testing.expectEqual(1, coding_support.br_pool.storage().free_count());
    }
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
