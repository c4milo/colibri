//! The tests of a request's trailer section over h3 (decision 152, design §8 step 38b): the
//! section goes in a HEADERS frame after the last DATA frame, and the stream ends with it (RFC 9114
//! §4.1). A response with a trailer buffer asks for trailers with `te: trailers` (RFC 9110
//! §10.1.4, RFC 9114 §4.2).
const std = @import("std");
const support = @import("quic_test_support.zig");
const event = @import("../event.zig");

const testing = std.testing;
const connection = &support.connection;
const Exchange = support.Exchange;

const trailers = [_]event.Header{support.request_trailer};
const content = "hello";

var body: [body_len]u8 = undefined;
var trailer_buffer: [body_len]u8 = undefined;
const body_len: usize = 256;

/// Checks that the server read the request's content and then one trailer section, which named
/// its field, and answered it.
fn expect_trailers(exchange: *const Exchange, content_len: usize) !void {
    const answer = &support.answers[0];
    try testing.expectEqual(content_len, answer.received);
    try testing.expectEqual(1, answer.trailer_sections);
    try testing.expectEqual(trailers.len, answer.trailer_lines);
    // RFC 9110 §6.6.2: the head named each trailer field.
    try testing.expectEqual(trailers.len, answer.named);
    try testing.expect(answer.ended);
    try testing.expectEqual(.response, exchange.response.result);
}

test "RFC 9114 §4.1: a request's trailer section follows its content, and the stream ends with it" {
    try support.start(&support.alpn_h3, &support.alpn_h3, false);
    var exchange: Exchange = .{
        .request = .{ .method = "POST", .path = "/upload", .body = content, .trailers = &trailers },
        .response = .{ .body = &body, .trailers = .{ .buffer = &trailer_buffer } },
    };
    _ = try connection.request(&exchange.request, &exchange.response);
    try support.pump(support.rounds_default);
    try expect_trailers(&exchange, content.len);
    // RFC 9114 §4.2: "trailers" is the one TE value h3 allows.
    try testing.expect(support.answers[0].te);
}

test "RFC 9114 §4.1: a request with trailers and no content sends its section after its head" {
    try support.start(&support.alpn_h3, &support.alpn_h3, false);
    var exchange: Exchange = .{
        .request = .{ .method = "GET", .path = "/", .trailers = &trailers },
        .response = .{ .body = &body },
    };
    _ = try connection.request(&exchange.request, &exchange.response);
    try support.pump(support.rounds_default);
    try expect_trailers(&exchange, 0);
    // A response with no trailer buffer asks for none.
    try testing.expect(!support.answers[0].te);
}

test "decision 152: a streamed request's trailer section follows its last piece over h3" {
    try support.start(&support.alpn_h3, &support.alpn_h3, false);
    var exchange: Exchange = .{
        .request = .{ .method = "PUT", .path = "/upload", .streamed = .{ .request = true }, .trailers = &trailers },
        .response = .{ .body = &body },
    };
    const id = try connection.request(&exchange.request, &exchange.response);
    try connection.write_body(id, "hel", false);
    try support.pump(support.rounds_default);
    try testing.expectEqual(0, support.answers[0].trailer_sections);
    try testing.expect(support.find(.body_taken) != null);
    try connection.write_body(id, "lo", true);
    try support.pump(support.rounds_default);
    try expect_trailers(&exchange, content.len);
}

/// A value of the longest length colibri sends (RFC 9110 §5.4), of an octet whose Huffman code is
/// longer than 8 bits, so the encoder writes it as it is (RFC 7541 Appendix B). Test-only.
const long_value: [long_value_len]u8 = @splat('^');
const long_value_len: usize = @import("h3").core.constants.limits.field_value_len_max;
const half_value_len: usize = 4096;

test "RFC 9114 §4.1.1: a header and a trailer section that the stream's frames cannot hold together end the exchange invalid" {
    try support.start(&support.alpn_h3, &support.alpn_h3, false);
    // Each section alone is within `field_section_size_max`, but over h3 the two share the
    // stream's `prefix` (`request_prefix_len_max`).
    const headers = [_]event.Header{ .{ .name = "x-long", .value = &long_value }, .{ .name = "x-more", .value = long_value[0..half_value_len] } };
    const long_trailers = [_]event.Header{.{ .name = "x-long", .value = &long_value }};
    var exchange: Exchange = .{
        .request = .{ .method = "POST", .path = "/upload", .headers = &headers, .body = content, .trailers = &long_trailers },
        .response = .{ .body = &body },
    };
    _ = try connection.request(&exchange.request, &exchange.response);
    try support.pump(support.rounds_default);
    try testing.expectEqual(.invalid, exchange.response.result);
    // H3_REQUEST_CANCELLED closed the stream before any of it went out, so no request reached
    // the server.
    try testing.expectEqual(0, support.answers_len);
    // The header section alone goes out and is answered.
    exchange.request.trailers = &.{};
    _ = try connection.request(&exchange.request, &exchange.response);
    try support.pump(support.rounds_default);
    try testing.expectEqual(.response, exchange.response.result);
}
