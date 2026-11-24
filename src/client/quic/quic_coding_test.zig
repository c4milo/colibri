//! The tests of content codings at the client over h3 (`coding.zig`, decision 101 as amended): the
//! request offers gzip first with a decoder taken, and a response coded in gzip, zstd or br decodes
//! into the response's body.
const std = @import("std");
const gzip = @import("gzip");
const http = @import("http");
const support = @import("quic_test_support.zig");
const tcp_support = @import("../connection/connection_test_support.zig");
const coding_support = @import("../coding_test_support.zig");

const testing = std.testing;
const connection = &support.connection;
const Exchange = support.Exchange;

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
    tcp_support.pool.init();
    const storage = tcp_support.pool.storage();
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
        var exchange: Exchange = .{ .request = .{ .method = "GET", .path = "/" }, .response = .{ .body = &plain_body } };
        _ = try connection.request(&exchange.request, &exchange.response);
        try support.pump(support.rounds_default);
        try testing.expectEqual(.response, exchange.response.result);
        try testing.expectEqualStrings(name, exchange.response.coding.?.name());
        try testing.expectEqualStrings(coding_support.plain, exchange.response.body_received());
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
    var exchange: Exchange = .{ .request = .{ .method = "GET", .path = "/" }, .response = .{ .body = &body } };
    _ = try connection.request(&exchange.request, &exchange.response);
    try support.pump(support.rounds_default);
    try testing.expect(support.answers[0].offers_gzip);
    try testing.expectEqual(.response, exchange.response.result);
    try testing.expectEqual(.gzip, exchange.response.coding.?);
    try testing.expectEqualStrings(text, exchange.response.body_received());
    try testing.expectEqual(decoders_all, tcp_support.pool.storage().free_count());
}

test "decision 101: an h3 response whose coded stream is cut short ends malformed" {
    try start_coding();
    gzip_encoder.init(.none());
    const coded = coded_room[0..try gzip_encoder.encode_all(text, &coded_room)];
    // RFC 1952 §2.3: the member's last octet, of its trailer, never arrives.
    support.answer_content = coded[0 .. coded.len - 1];
    support.answer_coding = "gzip";
    var exchange: Exchange = .{ .request = .{ .method = "GET", .path = "/" }, .response = .{ .body = &body } };
    _ = try connection.request(&exchange.request, &exchange.response);
    try support.pump(support.rounds_default);
    try testing.expectEqual(.malformed, exchange.response.result);
    try testing.expectEqual(decoders_all, tcp_support.pool.storage().free_count());
}

test "decision 169: an h3 response's decoder, each gzip member of it, runs on the configuration's CPU features" {
    const CpuFeatures = @TypeOf(support.config.cpu_features);
    // The CRC-32 path of a gzip decoder shows the features it started with.
    const sets = [_]CpuFeatures{ .none(), .target() };
    for (sets, [_]CpuFeatures{ sets[1], sets[0] }) |cpu_features, other| {
        try support.prepare(&support.alpn_h3, &support.alpn_h3, false);
        tcp_support.pool.init();
        const storage = tcp_support.pool.storage();
        support.config.codings = &tcp_support.codings;
        support.config.decoders = storage;
        support.config.cpu_features = cpu_features;
        // The exchange takes the pool's first decoder, which holds the other set's path.
        const decoder: *gzip.Decoder = @ptrCast(@alignCast(&storage.slots[0].decoder));
        decoder.init(cpu_features);
        const expected = decoder.crc32_path;
        decoder.init(other);
        try connection.init(&support.config, support.client_pool.storage(), support.client_start, tcp_support.stream.random(), tcp_support.now_seconds, support.now_ns, null);
        gzip_encoder.init(.none());
        // RFC 1952 §2.2: two members, which decode to the text twice.
        const member_len = try gzip_encoder.encode_all(text, &coded_room);
        @memcpy(coded_room[member_len..][0..member_len], coded_room[0..member_len]);
        support.answer_content = coded_room[0 .. member_len * 2];
        support.answer_coding = "gzip";
        var exchange: Exchange = .{ .request = .{ .method = "GET", .path = "/" }, .response = .{ .body = &body } };
        _ = try connection.request(&exchange.request, &exchange.response);
        try support.pump(support.rounds_default);
        try testing.expectEqual(.response, exchange.response.result);
        try testing.expectEqual(text.len * 2, exchange.response.body_received().len);
        try testing.expectEqual(expected, decoder.crc32_path);
    }
}
