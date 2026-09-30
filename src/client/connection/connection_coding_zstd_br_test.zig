//! The tests of the client's `zstd` and `br` decoding over h11 and h2 (decision 101 as amended,
//! design §8 step 17h): the offer names each coding whose pool has a decoder free, a response in
//! either decodes from the reference programs' fixtures, and the decoders it did not need go back
//! with its head. Split out of `connection_coding_test.zig` for length.
const std = @import("std");
const h2 = @import("h2");
const gzip = @import("gzip");
const support = @import("connection_test_support.zig");
const coding_support = @import("../coding_test_support.zig");
const coding_pool = @import("../coding_pool.zig");

const testing = std.testing;
const connection = &support.connection;
const HttpExchange = support.HttpExchange;
const Field = support.Field;

const ok: u16 = 200;
/// Where exchanges put their responses: room for the text, decoded. Test-only.
threadlocal var body: [coding_support.plain.len]u8 = undefined;
threadlocal var first_body: [coding_support.plain.len]u8 = undefined;
/// Where a test codes the text in gzip, which stored blocks never double. Test-only.
threadlocal var gzip_encoder: GzipEncoder align(@alignOf(GzipEncoder)) = undefined;
threadlocal var gzip_room: [room_factor * coding_support.plain.len]u8 = undefined;
const GzipEncoder = gzip.Encoder(.{ .level = 1 });
const room_factor: usize = 2;

/// Whether the octets the client sent and the peer has not read hold `wanted`. Test-only.
fn sent(wanted: []const u8) bool {
    return std.mem.indexOf(u8, support.to_peer[0..support.to_peer_len], wanted) != null;
}

/// Decimal digits of a fixture's length, which holds fewer. Test-only.
const length_digits_max: usize = 8;

/// Answers the request the client sent over h11 with `coded` in `coding_name`.
fn h11_answer(coding_name: []const u8, coded: []const u8) !void {
    try support.peer_h11_read();
    var digits: [length_digits_max]u8 = undefined;
    const length = std.fmt.bufPrint(&digits, "{d}", .{coded.len}) catch unreachable;
    const fields = [_]Field{ .{ .name = "Content-Encoding", .value = coding_name }, .{ .name = "Content-Length", .value = length } };
    try support.peer_h11_answer(ok, &fields, coded);
    try support.client_receive();
}

/// Every decoder of every pool free.
fn expect_pools_free() !void {
    try testing.expectEqual(support.pool_decoders, support.pool.storage().free_count());
    try testing.expectEqual(1, coding_support.zstd_pool.storage().free_count());
    try testing.expectEqual(1, coding_support.br_pool.storage().free_count());
}

test "decision 101 as amended: the client offers zstd, br and gzip, and decodes zstd from its fixture" {
    try support.start_offering_all(.h11, &.{ .zstd, .br, .gzip });
    var exchange: HttpExchange = .{ .method = "GET", .path = "/", .body = &body };
    _ = try connection.request(&exchange);
    support.client_send();
    // RFC 9110 §12.4.2: each coding after the first weighs less, in the client's order, and a
    // decoder waits in each pool for the response.
    try testing.expect(sent("Accept-Encoding: zstd, br;q=0.9, gzip;q=0.8\r\n"));
    try testing.expectEqual(0, coding_support.zstd_pool.storage().free_count());
    try testing.expectEqual(0, coding_support.br_pool.storage().free_count());
    try testing.expectEqual(support.pool_decoders - 1, support.pool.storage().free_count());
    // RFC 8878 §7.2: the response is in zstd, and the br and gzip decoders go back with its head.
    try h11_answer("zstd", coding_support.plain_zst);
    try testing.expectEqual(.response, exchange.outcome);
    try testing.expectEqual(.zstd, exchange.coding.?);
    try testing.expectEqualStrings(coding_support.plain, exchange.content_received());
    try expect_pools_free();
}

test "decision 101 as amended: a coding whose pool has no decoder free is not offered, and br decodes" {
    try support.start_offering_all(.h11, &.{ .zstd, .br });
    // Another exchange holds the only zstd decoder.
    var taken: coding_pool.Held(coding_pool.Zstd) = .{};
    try testing.expect(taken.reserve(coding_support.zstd_pool.storage()));
    var exchange: HttpExchange = .{ .method = "GET", .path = "/", .body = &body };
    _ = try connection.request(&exchange);
    support.client_send();
    try testing.expect(sent("Accept-Encoding: br\r\n"));
    // RFC 7932 §13: the response is in br, whose stream holds a 16 MiB window.
    try h11_answer("br", coding_support.plain_br);
    try testing.expectEqual(.response, exchange.outcome);
    try testing.expectEqual(.br, exchange.coding.?);
    try testing.expectEqualStrings(coding_support.plain, exchange.content_received());
    taken.release();
    try expect_pools_free();
}

test "RFC 9659 §3: a zstd frame whose window passes 8 MB fails its response, and the decoder goes back" {
    try support.start_offering_all(.h11, &.{.zstd});
    var exchange: HttpExchange = .{ .method = "GET", .path = "/", .body = &body };
    _ = try connection.request(&exchange);
    support.client_send();
    try testing.expect(sent("Accept-Encoding: zstd\r\n"));
    try h11_answer("zstd", coding_support.window_16mb_zst);
    try testing.expectEqual(.malformed, exchange.outcome);
    try expect_pools_free();
}

/// The h2 peer answers stream `stream_id` with a head naming `coding_name`, and no content yet.
fn h2_head(stream_id: u32, coding_name: []const u8) !void {
    const fields = [_]h2.hpack.Field{.{ .name = "content-encoding", .value = coding_name }};
    support.to_client_len += try support.peer_h2.write_response(support.to_client[support.to_client_len..], stream_id, ok, &fields, false);
    try support.client_receive();
}

/// The h2 peer sends stream `stream_id`'s content, `coded`, and ends the stream.
fn h2_content(stream_id: u32, coded: []const u8) !void {
    const sent_data = try support.peer_h2.write_data(support.to_client[support.to_client_len..], stream_id, coded, true);
    try testing.expectEqual(coded.len, sent_data.consumed);
    support.to_client_len += sent_data.written;
    try support.client_receive();
}

test "decision 101 as amended: a response's head keeps its coding's decoder and gives back the rest" {
    try support.start_offering_all(.h2, &.{ .zstd, .br, .gzip });
    support.peer_events_len = 0;
    gzip_encoder.init(.none());
    const plain_gzip = gzip_room[0..try gzip_encoder.encode_all(coding_support.plain, &gzip_room)];
    const names = [_][]const u8{ "zstd", "br", "gzip" };
    const coded = [_][]const u8{ coding_support.plain_zst, coding_support.plain_br, plain_gzip };
    // What each pool has free once the head arrives, before any content: the exchange holds the
    // decoder of its coding alone.
    const zstd_free = [_]usize{ 0, 1, 1 };
    const br_free = [_]usize{ 1, 0, 1 };
    const deflate_held = [_]usize{ 0, 0, 1 };
    const stream_ids = [_]u32{ 1, 3, 5 };
    for (names, coded, zstd_free, br_free, deflate_held, stream_ids) |name, content, zstd_left, br_left, deflate_taken, stream_id| {
        var exchange: HttpExchange = .{ .method = "GET", .path = "/", .body = &body };
        _ = try connection.request(&exchange);
        try support.pump_h2();
        try h2_head(stream_id, name);
        try testing.expectEqual(zstd_left, coding_support.zstd_pool.storage().free_count());
        try testing.expectEqual(br_left, coding_support.br_pool.storage().free_count());
        try testing.expectEqual(support.pool_decoders - deflate_taken, support.pool.storage().free_count());
        try h2_content(stream_id, content);
        try testing.expectEqual(.response, exchange.outcome);
        try testing.expectEqualStrings(coding_support.plain, exchange.content_received());
        try expect_pools_free();
    }
}

test "decision 101 as amended: a head that waits for the stream limit offers again with the decoders it took" {
    try support.start_offering_all(.h2, &.{ .zstd, .br, .gzip });
    support.peer_events_len = 0;
    try support.pump_h2();
    // RFC 9113 §5.1.2: one stream at a time, so the second head waits for the first to close.
    try support.peer_setting(h2.constants.setting_max_concurrent_streams, 1);
    try support.client_receive();
    // Decision 101: a request that names Accept-Encoding takes no decoder. RFC 9113 §8.2: h2
    // field names are lowercase.
    const own = [_]Field{.{ .name = "accept-encoding", .value = "identity" }};
    var first: HttpExchange = .{ .method = "GET", .path = "/", .fields = &own, .body = &first_body };
    var second: HttpExchange = .{ .method = "GET", .path = "/", .body = &body };
    _ = try connection.request(&first);
    _ = try connection.request(&second);
    // Each pass writes the second head again, with the decoders its first pass took.
    try support.pump_h2();
    try testing.expectEqual(.pending, second.outcome);
    try testing.expectEqual(0, coding_support.zstd_pool.storage().free_count());
    try testing.expectEqual(0, coding_support.br_pool.storage().free_count());
    try testing.expectEqual(support.pool_decoders - 1, support.pool.storage().free_count());
    try support.peer_h2_answer(1, ok, &.{}, "");
    try support.pump_h2();
    const offered = support.peer_h2.field_section().find("accept-encoding") orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("zstd, br;q=0.9, gzip;q=0.8", offered.value);
    const br_answer = [_]h2.hpack.Field{.{ .name = "content-encoding", .value = "br" }};
    try support.peer_h2_answer(3, ok, &br_answer, coding_support.plain_br);
    try support.client_receive();
    try testing.expectEqual(.response, first.outcome);
    try testing.expectEqual(.response, second.outcome);
    try testing.expectEqualStrings(coding_support.plain, second.content_received());
    try expect_pools_free();
}

test "decision 101: a zstd response to a request that did not offer zstd goes on as it came" {
    try support.start_offering_all(.h11, &.{.br});
    var exchange: HttpExchange = .{ .method = "GET", .path = "/", .body = &body };
    _ = try connection.request(&exchange);
    support.client_send();
    try testing.expect(sent("Accept-Encoding: br\r\n"));
    try h11_answer("zstd", coding_support.plain_zst);
    try testing.expectEqual(.response, exchange.outcome);
    try testing.expectEqual(null, exchange.coding);
    try testing.expectEqualStrings(coding_support.plain_zst, exchange.content_received());
    try expect_pools_free();
}

test "decision 101 as amended: over h2, br decodes, and a zstd frame or a br stream cut short is malformed" {
    try support.start_offering_all(.h2, &.{ .br, .zstd });
    support.peer_events_len = 0;
    var exchange: HttpExchange = .{ .method = "GET", .path = "/", .body = &body };
    _ = try connection.request(&exchange);
    try support.pump_h2();
    // The request's section is the last one the peer decoded.
    const offered = support.peer_h2.field_section().find("accept-encoding") orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("br, zstd;q=0.9", offered.value);
    const br_answer = [_]h2.hpack.Field{.{ .name = "content-encoding", .value = "br" }};
    try support.peer_h2_answer(1, ok, &br_answer, coding_support.plain_br);
    try support.client_receive();
    try testing.expectEqual(.response, exchange.outcome);
    try testing.expectEqualStrings(coding_support.plain, exchange.content_received());
    // RFC 8878 §3.1.1: a frame without its checksum's last octet never ends.
    var cut: HttpExchange = .{ .method = "GET", .path = "/", .body = &body };
    _ = try connection.request(&cut);
    try support.pump_h2();
    const zstd_answer = [_]h2.hpack.Field{.{ .name = "content-encoding", .value = "zstd" }};
    try support.peer_h2_answer(3, ok, &zstd_answer, coding_support.plain_zst[0 .. coding_support.plain_zst.len - 1]);
    try support.client_receive();
    try testing.expectEqual(.malformed, cut.outcome);
    // RFC 7932 §9.2: a stream without its last meta-block never ends.
    var cut_br: HttpExchange = .{ .method = "GET", .path = "/", .body = &body };
    _ = try connection.request(&cut_br);
    try support.pump_h2();
    try support.peer_h2_answer(5, ok, &br_answer, coding_support.plain_br[0 .. coding_support.plain_br.len - 1]);
    try support.client_receive();
    try testing.expectEqual(.malformed, cut_br.outcome);
    try expect_pools_free();
}
