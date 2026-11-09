//! The tests of a status code outside 100 to 599 at the client over h3 (decision 158, ruling
//! 17). RFC 9110 §15 tells a client to read such a code as a 5xx, so the exchange ends with a
//! final response, and the program reads the code as it arrived. A status that is not three
//! digits still makes the response malformed (RFC 9114 §4.1.2).
const std = @import("std");
const http = @import("http");
const quic = @import("quic");
const support = @import("quic_test_support.zig");

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
var test_exchange: Exchange align(@alignOf(Exchange)) = undefined;

/// RFC 9114 §7.2.2: the type of a HEADERS frame.
const frame_headers: u8 = 0x01;
/// RFC 9204 §4.5.1: a field section prefix of no dynamic entry, a Required Insert Count of 0
/// and a Delta Base of 0.
const section_prefix = "\x00\x00";
/// RFC 9204 §4.5.4: a literal field line whose name is static entry 24, `:status` (RFC 9204
/// Appendix A). The pattern 01NT with T set and a 4-bit index of 15, then 24 - 15 = 9.
const status_name_reference = "\x5f\x09";
/// The longest status text a test writes, whose string length takes 7 bits with the Huffman bit
/// clear (RFC 7541 §5.2, which RFC 9204 §4.1.2 uses).
const status_text_len_max: usize = 4;
/// Octets of the HEADERS frame before its payload: its type and its length, each one octet.
const frame_prefix_len: usize = 2;
/// Octets of the payload before the status text: the prefix, the name and the string length.
const payload_prefix_len: usize = section_prefix.len + status_name_reference.len + 1;

/// Sends one GET, and has the server answer it with a HEADERS frame of `:status` `text` and the
/// stream's end. It is written raw, since h3's own write_response refuses such a code.
fn answer_status(text: []const u8) !void {
    std.debug.assert(text.len <= status_text_len_max);
    try support.start(&support.alpn_h3, &support.alpn_h3, false);
    support.server_answers = false;
    test_exchange = .{ .request = .{ .method = "GET", .path = "/" }, .response = .{ .body = &body } };
    _ = try connection.request(&test_exchange.request, &test_exchange.response);
    try support.pump(support.rounds_default);
    const answer = &support.answers[0];
    var writer = quic.core.Writer.init(&answer.prefix);
    try writer.write_byte(frame_headers);
    try writer.write_byte(@intCast(payload_prefix_len + text.len));
    try writer.write_bytes(section_prefix ++ status_name_reference);
    try writer.write_byte(@intCast(text.len));
    try writer.write_bytes(text);
    std.debug.assert(writer.written().len == frame_prefix_len + payload_prefix_len + text.len);
    answer.prefix_len = writer.written().len;
    answer.content = "";
    answer.answered = true;
    try quic.Connection.supply(&support.server, .{ .value = answer.id }, answer.prefix_len, true);
    try support.pump(support.rounds_default);
}

test "RFC 9110 §15: over h3 a :status outside 100 to 599 is a final 5xx" {
    for (texts) |text| {
        const code = try code_of(text);
        try answer_status(text);
        try testing.expectEqual(.response, test_exchange.response.result);
        try testing.expectEqual(code, @intFromEnum(test_exchange.response.status));
        try testing.expectEqual(http.Status.Class.server_error, test_exchange.response.status.class());
        // RFC 9110 §15: such a code is a 5xx, so it is never an interim response.
        try testing.expectEqual(0, test_exchange.response.interims);
    }
}

test "RFC 9114 §4.1.2: over h3 a :status that is not three digits makes the response malformed" {
    for (not_three_digits) |text| {
        try answer_status(text);
        try testing.expectEqual(.malformed, test_exchange.response.result);
    }
}
