//! The tests of content codings at the client (`coding.zig`, decision 101) over h11 and h2: the
//! client offers its codings in Accept-Encoding with a decoder taken, decodes a response in a
//! coding it offered into the exchange's body, and passes any other on as it arrived.
const std = @import("std");
const h2 = @import("h2");
const h11 = @import("h11");
const gzip = @import("gzip");
const zlib = @import("zlib");
const support = @import("connection_test_support.zig");

const testing = std.testing;
const connection = &support.connection;
const HttpExchange = support.HttpExchange;
const Field = support.Field;

const ok: u16 = 200;
const partial_content: u16 = 206;
const decoders_all: usize = 2;
const text = "colibri decodes what the server coded, octet for octet. " ** text_repeats;
const text_repeats: usize = 8;

/// Where the tests code content and where exchanges put their responses. Test-only.
threadlocal var gzip_encoder: gzip.Encoder(.{ .level = 1 }) align(@alignOf(gzip.Encoder(.{ .level = 1 }))) = undefined;
threadlocal var zlib_encoder: zlib.Encoder(.{ .level = 1 }) align(@alignOf(zlib.Encoder(.{ .level = 1 }))) = undefined;
threadlocal var coded_room: [coded_len_max]u8 = undefined;
threadlocal var body: [body_len]u8 = undefined;
/// Room for the text coded, which stored blocks never double, and for it decoded.
const coded_len_max: usize = room_factor * text.len;
const body_len: usize = room_factor * text.len;
const room_factor: usize = 2;

fn gzip_of(content: []const u8) ![]u8 {
    gzip_encoder.init(.none());
    return coded_room[0..try gzip_encoder.encode_all(content, &coded_room)];
}

fn zlib_of(content: []const u8) ![]u8 {
    zlib_encoder.init(.none());
    return coded_room[0..try zlib_encoder.encode_all(content, &coded_room)];
}

/// Whether the octets the client sent and the peer has not read hold `wanted`. Test-only.
fn sent(wanted: []const u8) bool {
    return std.mem.indexOf(u8, support.to_peer[0..support.to_peer_len], wanted) != null;
}

/// Sends `exchange` over h11 and answers it with `status`, `fields` and `content`.
fn h11_exchange(exchange: *HttpExchange, status: u16, fields: []const Field, content: []const u8) !void {
    _ = try connection.request(exchange);
    support.client_send();
    try support.peer_h11_read();
    try support.peer_h11_answer(status, fields, content);
    try support.client_receive();
}

fn length_of(content: []const u8, digits: []u8) []const u8 {
    return std.fmt.bufPrint(digits, "{d}", .{content.len}) catch unreachable;
}

test "decision 101: the client offers its codings with weights, and decodes gzip into the body" {
    try support.start_coding(.h11);
    var exchange: HttpExchange = .{ .method = "GET", .path = "/", .body = &body };
    _ = try connection.request(&exchange);
    support.client_send();
    // RFC 9110 §12.4.2: each coding after the first weighs less, in the client's order.
    try testing.expect(sent("Accept-Encoding: gzip, deflate;q=0.9\r\n"));
    try testing.expectEqual(decoders_all - 1, support.pool.storage().free_count());
    try support.peer_h11_read();
    const coded = try gzip_of(text);
    var digits: [8]u8 = undefined;
    const fields = [_]Field{ .{ .name = "Content-Encoding", .value = "x-gzip" }, .{ .name = "Content-Length", .value = length_of(coded, &digits) } };
    try support.peer_h11_answer(ok, &fields, coded);
    try support.client_receive();
    try testing.expectEqual(.response, exchange.outcome);
    try testing.expectEqual(.gzip, exchange.coding.?);
    try testing.expectEqualStrings(text, exchange.content_received());
    try testing.expectEqual(decoders_all, support.pool.storage().free_count());
}

test "decision 101: a request naming Accept-Encoding goes as written, and its coded response as it came" {
    try support.start_coding(.h11);
    const fields = [_]Field{.{ .name = "accept-encoding", .value = "gzip" }};
    var exchange: HttpExchange = .{ .method = "GET", .path = "/", .fields = &fields, .body = &body };
    const coded = try gzip_of(text);
    var digits: [8]u8 = undefined;
    const answer = [_]Field{ .{ .name = "Content-Encoding", .value = "gzip" }, .{ .name = "Content-Length", .value = length_of(coded, &digits) } };
    try h11_exchange(&exchange, ok, &answer, coded);
    try testing.expect(!sent("deflate"));
    try testing.expectEqual(.response, exchange.outcome);
    try testing.expectEqual(null, exchange.coding);
    try testing.expectEqualSlices(u8, coded, exchange.content_received());
    try testing.expectEqual(decoders_all, support.pool.storage().free_count());
}

test "decision 101: a coding not offered, content coded twice and a 206 go on as they arrived" {
    const cases = [_]struct { status: u16, coding: []const u8 }{
        .{ .status = ok, .coding = "br" },
        .{ .status = ok, .coding = "gzip, gzip" },
        .{ .status = partial_content, .coding = "gzip" },
    };
    for (cases) |case| {
        try support.start_coding(.h11);
        var exchange: HttpExchange = .{ .method = "GET", .path = "/", .body = &body };
        const answer = [_]Field{ .{ .name = "Content-Encoding", .value = case.coding }, .{ .name = "Content-Length", .value = "5" } };
        try h11_exchange(&exchange, case.status, &answer, "hello");
        try testing.expectEqual(.response, exchange.outcome);
        try testing.expectEqual(null, exchange.coding);
        try testing.expectEqualStrings("hello", exchange.content_received());
        try testing.expectEqual(decoders_all, support.pool.storage().free_count());
    }
}

test "decision 101: corrupt coded content ends malformed, and decoded content past the body too_large" {
    try support.start_coding(.h11);
    var exchange: HttpExchange = .{ .method = "GET", .path = "/", .body = &body };
    const coded = try gzip_of(text);
    // RFC 1952 §2.3.1: a wrong CRC32 in the trailer.
    coded[coded.len - gzip_trailer_len] +%= 1;
    var digits: [8]u8 = undefined;
    const answer = [_]Field{ .{ .name = "Content-Encoding", .value = "gzip" }, .{ .name = "Content-Length", .value = length_of(coded, &digits) } };
    try h11_exchange(&exchange, ok, &answer, coded);
    try testing.expectEqual(.malformed, exchange.outcome);
    try testing.expectEqual(decoders_all, support.pool.storage().free_count());
    try support.start_coding(.h11);
    var small: [text.len - 1]u8 = undefined;
    var tight: HttpExchange = .{ .method = "GET", .path = "/", .body = &small };
    const deflated = try zlib_of(text);
    const deflate_answer = [_]Field{ .{ .name = "Content-Encoding", .value = "deflate" }, .{ .name = "Content-Length", .value = length_of(deflated, &digits) } };
    try h11_exchange(&tight, ok, &deflate_answer, deflated);
    try testing.expectEqual(.too_large, tight.outcome);
    try testing.expectEqual(decoders_all, support.pool.storage().free_count());
}

/// RFC 1952 §2.3: a member ends with its CRC32 and ISIZE, four octets each.
const gzip_trailer_len: usize = 8;

test "decision 101: with every decoder taken, the client offers nothing" {
    try support.start_coding(.h11);
    const storage = support.pool.storage();
    var taken: [decoders_all]h11.coding.Decoding = @splat(.{});
    for (&taken) |*decoding| try testing.expect(h11.coding.reserve(decoding, storage));
    var exchange: HttpExchange = .{ .method = "GET", .path = "/", .body = &body };
    _ = try connection.request(&exchange);
    support.client_send();
    try testing.expect(!sent("Accept-Encoding"));
    for (&taken) |*decoding| h11.coding.release(decoding, storage);
}

test "RFC 9110 §9.3.2: a response to HEAD names a coding it carries no content in, and decodes nothing" {
    try support.start_coding(.h11);
    var head: HttpExchange = .{ .method = "HEAD", .path = "/", .body = &body };
    _ = try connection.request(&head);
    support.client_send();
    try testing.expect(sent("Accept-Encoding"));
    try support.peer_h11_read();
    const answer = [_]Field{ .{ .name = "Content-Encoding", .value = "gzip" }, .{ .name = "Content-Length", .value = "30" } };
    try support.peer_h11_answer(ok, &answer, "");
    try support.client_receive();
    try testing.expectEqual(.response, head.outcome);
    try testing.expectEqual(null, head.coding);
    try testing.expectEqual(decoders_all, support.pool.storage().free_count());
}

test "decision 101: over h2 the offer is an accept-encoding line, and a coded response decodes" {
    try support.start_coding(.h2);
    support.peer_events_len = 0;
    var exchange: HttpExchange = .{ .method = "GET", .path = "/", .body = &body };
    _ = try connection.request(&exchange);
    try support.pump_h2();
    // The request's section is the last one the peer decoded.
    const offered = support.peer_h2.field_section().find("accept-encoding") orelse return error.TestUnexpectedResult;
    try testing.expectEqualStrings("gzip, deflate;q=0.9", offered.value);
    const coded = try zlib_of(text);
    const answer = [_]h2.hpack.Field{.{ .name = "content-encoding", .value = "deflate" }};
    try support.peer_h2_answer(1, ok, &answer, coded);
    try support.client_receive();
    try testing.expectEqual(.response, exchange.outcome);
    try testing.expectEqual(.deflate, exchange.coding.?);
    try testing.expectEqualStrings(text, exchange.content_received());
    try testing.expectEqual(decoders_all, support.pool.storage().free_count());
}

test "decision 101: content coded twice in two lines, or in a coding not offered, goes on as it came" {
    try support.start_coding(.h11);
    var twice: HttpExchange = .{ .method = "GET", .path = "/", .body = &body };
    const lines = [_]Field{
        .{ .name = "Content-Encoding", .value = "gzip" },
        .{ .name = "Content-Encoding", .value = "gzip" },
        .{ .name = "Content-Length", .value = "5" },
    };
    try h11_exchange(&twice, ok, &lines, "hello");
    try testing.expectEqual(.response, twice.outcome);
    try testing.expectEqualStrings("hello", twice.content_received());
    // A client that offers gzip alone passes deflate on.
    try support.start_offering(.h11, &.{.gzip});
    var exchange: HttpExchange = .{ .method = "GET", .path = "/", .body = &body };
    const deflate = [_]Field{ .{ .name = "Content-Encoding", .value = "deflate" }, .{ .name = "Content-Length", .value = "5" } };
    try h11_exchange(&exchange, ok, &deflate, "hello");
    try testing.expectEqual(.response, exchange.outcome);
    try testing.expectEqual(null, exchange.coding);
    try testing.expectEqualStrings("hello", exchange.content_received());
}

test "decision 101: decoded content that fills the body exactly fits, and a stream cut short is malformed" {
    try support.start_coding(.h11);
    var exact: [text.len]u8 = undefined;
    var fitting: HttpExchange = .{ .method = "GET", .path = "/", .body = &exact };
    const coded = try gzip_of(text);
    var digits: [8]u8 = undefined;
    const answer = [_]Field{ .{ .name = "Content-Encoding", .value = "gzip" }, .{ .name = "Content-Length", .value = length_of(coded, &digits) } };
    try h11_exchange(&fitting, ok, &answer, coded);
    try testing.expectEqual(.response, fitting.outcome);
    try testing.expectEqualStrings(text, fitting.content_received());
    // RFC 1952 §2.3: the member's last octets, its trailer, never arrive.
    try support.start_coding(.h11);
    var cut: HttpExchange = .{ .method = "GET", .path = "/", .body = &body };
    const short = coded[0 .. coded.len - 1];
    const short_answer = [_]Field{ .{ .name = "Content-Encoding", .value = "gzip" }, .{ .name = "Content-Length", .value = length_of(short, &digits) } };
    try h11_exchange(&cut, ok, &short_answer, short);
    try testing.expectEqual(.malformed, cut.outcome);
    try testing.expectEqual(decoders_all, support.pool.storage().free_count());
}

test "decision 101: over h2, an uncoded response gives its decoder back with its head, and a cut stream is malformed" {
    try support.start_coding(.h2);
    var exchange: HttpExchange = .{ .method = "GET", .path = "/", .body = &body };
    _ = try connection.request(&exchange);
    try support.pump_h2();
    try testing.expectEqual(decoders_all - 1, support.pool.storage().free_count());
    const plain = [_]h2.hpack.Field{.{ .name = "content-encoding", .value = "br" }};
    support.to_client_len += try support.peer_h2.write_response(support.to_client[support.to_client_len..], 1, ok, &plain, false);
    try support.client_receive();
    // A message holds a decoder only while it is coded (decision 101).
    try testing.expectEqual(decoders_all, support.pool.storage().free_count());
    const sent_data = try support.peer_h2.write_data(support.to_client[support.to_client_len..], 1, "hello", true);
    support.to_client_len += sent_data.written;
    try support.client_receive();
    try testing.expectEqual(.response, exchange.outcome);
    try testing.expectEqualStrings("hello", exchange.content_received());
    var cut: HttpExchange = .{ .method = "GET", .path = "/", .body = &body };
    _ = try connection.request(&cut);
    try support.pump_h2();
    const coded = try gzip_of(text);
    const answer = [_]h2.hpack.Field{.{ .name = "content-encoding", .value = "gzip" }};
    try support.peer_h2_answer(3, ok, &answer, coded[0 .. coded.len - 1]);
    try support.client_receive();
    try testing.expectEqual(.malformed, cut.outcome);
    try testing.expectEqual(decoders_all, support.pool.storage().free_count());
}

test "decision 101: exchanges a closed transport ends give their decoders back before their events" {
    try support.start_coding(.h2);
    var first: HttpExchange = .{ .method = "GET", .path = "/", .body = &body };
    var second: HttpExchange = .{ .method = "GET", .path = "/second", .body = &body };
    _ = try connection.request(&first);
    _ = try connection.request(&second);
    try support.pump_h2();
    try testing.expectEqual(0, support.pool.storage().free_count());
    connection.transport_closed();
    // One event a call: both exchanges ended, and neither holds its decoder while it waits.
    const received = connection.receive(&.{}, support.now_ns);
    try testing.expect(received.event.? == .finished);
    try testing.expectEqual(decoders_all, support.pool.storage().free_count());
}

test "decision 101: a cancelled exchange gives its decoder back, dropped in h11 and reset in h2" {
    try support.start_coding(.h11);
    var dropped: HttpExchange = .{ .method = "GET", .path = "/", .body = &body };
    const id = try connection.request(&dropped);
    support.client_send();
    try support.peer_h11_read();
    // RFC 9112 §9.3: h11 reads the response of an exchange its caller cancelled, and drops it.
    connection.cancel(id);
    try support.peer_h11_answer(ok, &.{.{ .name = "Content-Length", .value = "5" }}, "hello");
    try support.client_receive();
    try testing.expectEqual(decoders_all, support.pool.storage().free_count());
    try support.start_coding(.h2);
    var reset: HttpExchange = .{ .method = "GET", .path = "/", .body = &body };
    const stream = try connection.request(&reset);
    try support.pump_h2();
    connection.cancel(stream);
    try testing.expectEqual(decoders_all, support.pool.storage().free_count());
}

test "decision 101: a gzip trailer that arrives once the body is full decodes to nothing, and fits" {
    try support.start_coding(.h2);
    var exact: [text.len]u8 = undefined;
    var exchange: HttpExchange = .{ .method = "GET", .path = "/", .body = &exact };
    _ = try connection.request(&exchange);
    try support.pump_h2();
    const coded = try gzip_of(text);
    const answer = [_]h2.hpack.Field{.{ .name = "content-encoding", .value = "gzip" }};
    support.to_client_len += try support.peer_h2.write_response(support.to_client[support.to_client_len..], 1, ok, &answer, false);
    // RFC 1952 §2.3: the member's CRC32 and ISIZE come in a DATA frame of their own.
    const content = coded[0 .. coded.len - gzip_trailer_len];
    const first = try support.peer_h2.write_data(support.to_client[support.to_client_len..], 1, content, false);
    support.to_client_len += first.written;
    try support.client_receive();
    try testing.expectEqual(text.len, exchange.body_len);
    const trailer = try support.peer_h2.write_data(support.to_client[support.to_client_len..], 1, coded[content.len..], true);
    support.to_client_len += trailer.written;
    try support.client_receive();
    try testing.expectEqual(.response, exchange.outcome);
    try testing.expectEqualStrings(text, exchange.content_received());
}
