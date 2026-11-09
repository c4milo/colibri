//! The tests of a status code outside 100 to 599 at the client, over h11 and h2 (decision 158,
//! ruling 17). RFC 9110 §15 tells a client to read such a code as a 5xx, so the exchange ends
//! with a final response, and the program reads the code as it arrived. A status that is not
//! three digits still makes the response malformed.
const std = @import("std");
const h2 = @import("h2");
const http = @import("http");
const support = @import("connection_test_support.zig");
const event = @import("../event.zig");

const testing = std.testing;
const connection = &support.connection;
const Exchange = support.Exchange;

/// The codes the tests send, as text, which RFC 9110 §15 calls invalid.
const texts = [_][]const u8{ "099", "600", "800", "999" };

/// The code that `text` names. Test-only.
fn code_of(text: []const u8) !u16 {
    return std.fmt.parseInt(u16, text, http.constants.protocol.status_digit_radix);
}
/// Status text that is not three digits (RFC 9110 §15).
const not_three_digits = [_][]const u8{ "80", "8000", "8x0" };

/// Where the exchange puts its response, outside any stack frame. Test-only.
var body: [body_len]u8 = undefined;
const body_len: usize = 64;

/// The h2 stream the client's first request opens (RFC 9113 §5.1.1).
const first_stream: u32 = 1;
/// RFC 7541 §6.2.2: a literal field line without indexing whose name is static entry 8,
/// `:status` (RFC 7541 Appendix A), with a 4-bit prefix.
const status_name_literal: u8 = 0x08;
/// The longest status text a test writes into one HPACK string, whose length takes 7 bits with
/// the Huffman bit clear (RFC 7541 §5.2).
const status_text_len_max: usize = 4;
/// Octets of a field line before its value: the index octet and the length octet.
const line_prefix_len: usize = 2;
/// Room for one HEADERS frame of one `:status` line.
const frame_len_max: usize = h2.constants.protocol.frame_header_len + line_prefix_len + status_text_len_max;
/// Room for one h11 status line and its Content-Length line.
const head_len_max: usize = 64;

/// Sends one GET over `protocol`, so a response can answer it. Test-only.
fn send_get(protocol: event.Protocol, exchange: *Exchange) !void {
    try support.start_cleartext(protocol);
    support.peer_events_len = 0;
    exchange.* = .{ .request = .{ .method = "GET", .path = "/" }, .response = .{ .body = &body } };
    _ = try connection.request(&exchange.request, &exchange.response);
    switch (protocol) {
        .h11 => {
            support.client_send();
            try support.peer_h11_read();
        },
        .h2 => try support.pump_h2(),
        else => unreachable,
    }
}

/// The peer writes `octets` itself, and the client reads them. Test-only.
fn peer_writes(octets: []const u8) !void {
    @memcpy(support.to_client[support.to_client_len..][0..octets.len], octets);
    support.to_client_len += octets.len;
    try support.client_receive();
}

/// The h2 peer answers the first stream with a HEADERS frame of `:status` `text` and END_STREAM,
/// written raw, since h2's own write_response refuses a code outside 100 to 599.
fn peer_h2_status(text: []const u8) !void {
    std.debug.assert(text.len <= status_text_len_max);
    var octets: [frame_len_max]u8 = undefined;
    var frame = h2.core.Writer.init(&octets);
    const flags = h2.constants.protocol.flag_end_headers | h2.constants.protocol.flag_end_stream;
    const length: u24 = @intCast(line_prefix_len + text.len);
    try h2.frame.write_header(&frame, .{ .length = length, .type = .headers, .flags = flags, .stream_id = first_stream });
    try frame.write_byte(status_name_literal);
    try frame.write_byte(@intCast(text.len));
    try frame.write_bytes(text);
    try peer_writes(frame.written());
}

/// Checks that the exchange ended with a final response of `code`, a 5xx by RFC 9110 §15.
fn expect_server_error(exchange: *const Exchange, code: u16) !void {
    try testing.expectEqual(.response, exchange.response.result);
    try testing.expectEqual(code, @intFromEnum(exchange.response.status));
    try testing.expectEqual(http.Status.Class.server_error, exchange.response.status.class());
    // RFC 9110 §15: such a code is a 5xx, so it is never an interim response.
    try testing.expectEqual(0, exchange.response.interims);
}

var test_exchange: Exchange align(@alignOf(Exchange)) = undefined;

test "RFC 9110 §15: over h11 a status outside 100 to 599 is a final 5xx" {
    for (texts) |text| {
        const code = try code_of(text);
        try send_get(.h11, &test_exchange);
        var line: [head_len_max]u8 = undefined;
        try peer_writes(try std.fmt.bufPrint(&line, "HTTP/1.1 {s} X\r\nContent-Length: 0\r\n\r\n", .{text}));
        try expect_server_error(&test_exchange, code);
    }
}

test "RFC 9112 §4: over h11 a status that is not three digits makes the response malformed" {
    for (not_three_digits) |text| {
        try send_get(.h11, &test_exchange);
        var line: [head_len_max]u8 = undefined;
        try peer_writes(try std.fmt.bufPrint(&line, "HTTP/1.1 {s} X\r\nContent-Length: 0\r\n\r\n", .{text}));
        try testing.expectEqual(.malformed, test_exchange.response.result);
    }
}

test "RFC 9110 §15: over h2 a :status outside 100 to 599 is a final 5xx" {
    for (texts) |text| {
        const code = try code_of(text);
        try send_get(.h2, &test_exchange);
        try peer_h2_status(text);
        try expect_server_error(&test_exchange, code);
    }
}

test "RFC 9113 §8.3.2: over h2 a :status that is not three digits makes the response malformed" {
    for (not_three_digits) |text| {
        try send_get(.h2, &test_exchange);
        try peer_h2_status(text);
        try testing.expectEqual(.malformed, test_exchange.response.result);
    }
}
