//! The tests of design §9's server session (`server_session.zig`) in cleartext, over h11 and h2:
//! every request is answered once it is read whole, in the order it was read, and the echo mode
//! answers with what h11 parsed. The TLS half is `server`'s, and `src/server/` tests it.
const std = @import("std");
const server = @import("server");
const h2 = @import("h2");
const constants = @import("constants.zig");
const h11_echo = @import("h11/h11_echo.zig");
const session_module = @import("server_session.zig");
const entropy = @import("entropy.zig");

const testing = std.testing;
const Session = session_module.Session;

/// The session, its configuration and buffers, outside any stack frame. Test-only.
var test_session: Session align(@alignOf(Session)) = undefined;
var test_config: server.Config align(@alignOf(server.Config)) = .{};
var test_input: [test_input_len]u8 = undefined;
var test_output: [test_output_len]u8 = undefined;
var test_echo: h11_echo.Echo align(@alignOf(h11_echo.Echo)) = undefined;

const test_input_len: usize = constants.echo_body_len_max + test_head_len_max;
const test_output_len: usize = 4096;
/// Room for a head of a request whose content is one past the echo's limit. Test-only.
const test_head_len_max: usize = 128;
/// An output smaller than any echo, so an echo goes out in slices. Test-only.
const test_small_output_len: usize = 128;

/// The response every request gets. Test-only.
const response = "HTTP/1.1 200 OK\r\ncontent-type: " ++ constants.response_content_type ++
    "\r\ncontent-length: " ++ constants.response_content_length ++ "\r\n\r\n";

/// A session speaking `protocol` in cleartext, with nothing read or written. Test-only.
fn fresh_session(protocol: server.Protocol, echo: ?*h11_echo.Echo) !*Session {
    test_config = .{ .cleartext = protocol };
    // Cleartext draws nothing from the source.
    try test_session.init(&test_config, entropy.random(), echo);
    return &test_session;
}

/// Steps the session over `input`, copied where the connection may read it. Test-only.
fn step(input: []const u8, output: []u8) session_module.Step {
    @memcpy(test_input[0..input.len], input);
    return test_session.step(test_input[0..input.len], output);
}

test "every h11 request is answered with 200 and the body, pipelined ones in order" {
    _ = try fresh_session(.h11, null);
    const input = "GET / HTTP/1.1\r\nHost: a\r\n\r\nPOST /p HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\nabc";
    const stepped = step(input, &test_output);
    try testing.expectEqual(input.len, stepped.consumed);
    try testing.expectEqualStrings(response ++ constants.response_body ++ response ++ constants.response_body, test_output[0..stepped.written]);
    try testing.expect(!stepped.done);
}

test "an h11 request split anywhere is answered once it is whole" {
    _ = try fresh_session(.h11, null);
    const input = "POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\n\r\n";
    var consumed: usize = 0;
    var written: usize = 0;
    for (1..input.len + 1) |end| {
        const stepped = step(input[consumed..end], test_output[written..]);
        consumed += stepped.consumed;
        written += stepped.written;
        // Nothing is written before the last octet arrives.
        if (end < input.len) try testing.expectEqual(0, written);
    }
    try testing.expectEqual(input.len, consumed);
    try testing.expectEqualStrings(response ++ constants.response_body, test_output[0..written]);
}

test "RFC 9110 §9.3.2 and RFC 9112 §9.6: HEAD gets no body, and the close option ends the session" {
    _ = try fresh_session(.h11, null);
    const input = "HEAD / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\nGET / HTTP/1.1\r\nHost: a\r\n\r\n";
    const stepped = step(input, &test_output);
    const closed = "HTTP/1.1 200 OK\r\ncontent-type: " ++ constants.response_content_type ++
        "\r\ncontent-length: " ++ constants.response_content_length ++ "\r\nConnection: close\r\n\r\n";
    try testing.expectEqualStrings(closed, test_output[0..stepped.written]);
    try testing.expect(stepped.done);
    // The request after the close is never read.
    try testing.expect(stepped.consumed < input.len);
}

test "decision 92: a refused h11 request gets its error response, and then the session is done" {
    _ = try fresh_session(.h11, null);
    // No room for the error response: the session is not done until it is written.
    const first = step("GET / HTTP/1.1\r\n\r\n", test_output[0..1]);
    try testing.expectEqual(1, first.written);
    try testing.expect(!first.done);
    const stepped = step(&.{}, test_output[1..]);
    try testing.expectEqualStrings("HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n", test_output[0 .. 1 + stepped.written]);
    try testing.expect(stepped.done);
}

test "RFC 9110 §10.1.1: an HTTP/1.1 request expecting 100-continue gets it before its content" {
    _ = try fresh_session(.h11, null);
    const head = "POST / HTTP/1.1\r\nHost: a\r\nExpect: token, 100-Continue\r\nContent-Length: 3\r\n\r\n";
    const first = step(head, &test_output);
    try testing.expectEqual(head.len, first.consumed);
    try testing.expectEqualStrings("HTTP/1.1 100 Continue\r\n\r\n", test_output[0..first.written]);
    const second = step("abc", &test_output);
    try testing.expectEqualStrings(response ++ constants.response_body, test_output[0..second.written]);
}

test "the echo mode answers each h11 request with the JSON of what h11 read" {
    _ = try fresh_session(.h11, &test_echo);
    const input = "POST /p HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
    const stepped = step(input, &test_output);
    const json = "{\"method\":\"UE9TVA==\",\"uri\":\"L3A=\",\"version\":\"SFRUUC8xLjE=\"," ++
        "\"headers\":[[\"SG9zdA==\",\"YQ==\"],[\"VHJhbnNmZXItRW5jb2Rpbmc=\",\"Y2h1bmtlZA==\"]],\"body\":\"aGVsbG8=\"}";
    const head = "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: " ++
        std.fmt.comptimePrint("{d}", .{json.len}) ++ "\r\n\r\n";
    try testing.expectEqualStrings(head ++ json, test_output[0..stepped.written]);
}

test "the echo mode answers content past its limit with 413, and writes a long echo in slices" {
    _ = try fresh_session(.h11, &test_echo);
    const head = "POST / HTTP/1.1\r\nHost: a\r\nContent-Length: " ++
        std.fmt.comptimePrint("{d}", .{constants.echo_body_len_max + 1}) ++ "\r\n\r\n";
    @memcpy(test_input[0..head.len], head);
    @memset(test_input[head.len..][0 .. constants.echo_body_len_max + 1], 'x');
    const refused = test_session.step(test_input[0 .. head.len + constants.echo_body_len_max + 1], &test_output);
    try testing.expect(std.mem.startsWith(u8, test_output[0..refused.written], "HTTP/1.1 413 Content Too Large\r\n"));
    // A GET whose echo is longer than the output: the content goes out over several steps.
    _ = try fresh_session(.h11, &test_echo);
    const get = "GET /" ++ "a" ** 1200 ++ " HTTP/1.1\r\nHost: a\r\n\r\n";
    var steps: usize = 0;
    var sent_len: usize = 0;
    for (0..test_output_len) |_| {
        const stepped = step(if (steps == 0) get else "", test_output[0..test_small_output_len]);
        steps += 1;
        sent_len += stepped.written;
        if (test_session.owed_count == 0 and stepped.written == 0) break;
    }
    try testing.expect(steps > 2);
    try testing.expect(sent_len > test_small_output_len);
}

/// The client connection preface, then an empty SETTINGS frame (RFC 9113 §3.4). Test-only.
const client_preface = h2.constants.client_preface ++ "\x00\x00\x00\x04\x00\x00\x00\x00\x00";
/// A HEADERS frame on stream `id` ending it, whose block is the static table's `:method: GET`,
/// `:scheme: http` and `:path: /`, each an indexed field line (RFC 7541 §6.1, Appendix A).
/// Test-only.
fn get_frame(comptime id: u8) []const u8 {
    return "\x00\x00\x03\x01\x05\x00\x00\x00" ++ [_]u8{id} ++ "\x82\x86\x84";
}
/// A frame's header: a length of three octets, then its type and its flags (RFC 9113 §4.1).
const type_index: usize = 3;
const flags_index: usize = 4;
const length_len: usize = 3;

test "an h2 GET is answered with 200, its body, and END_STREAM on the DATA frame" {
    _ = try fresh_session(.h2, null);
    const preface = step(client_preface, &test_output);
    try testing.expectEqual(client_preface.len, preface.consumed);
    try testing.expectEqual(h2.constants.frame_type_settings, test_output[type_index]);
    const answer = step(get_frame(1), &test_output);
    const written = test_output[0..answer.written];
    try testing.expectEqual(h2.constants.frame_type_headers, written[type_index]);
    const head_len = h2.constants.frame_header_len + std.mem.readInt(u24, written[0..length_len], .big);
    const body = written[head_len..];
    try testing.expectEqual(h2.constants.frame_type_data, body[type_index]);
    try testing.expectEqual(h2.constants.flag_end_stream, body[flags_index]);
    try testing.expectEqualStrings(constants.response_body, body[h2.constants.frame_header_len..]);
    try testing.expect(!answer.done);
    // A second stream is answered too, and both close.
    _ = step(get_frame(3), &test_output);
    try testing.expectEqual(0, test_session.connection.session.h2.streams.peer_active);
    try testing.expectEqual(0, test_session.owed_count);
}

test "an h2 peer that breaks the protocol gets a GOAWAY, and the session is done" {
    _ = try fresh_session(.h2, null);
    _ = step(client_preface, &test_output);
    // RFC 9113 §5.1: a DATA frame on an idle stream ends the connection.
    const data = "\x00\x00\x04\x00\x00\x00\x00\x00\x01test";
    const answer = step(data, &test_output);
    try testing.expectEqual(h2.constants.frame_type_goaway, test_output[type_index]);
    try testing.expect(answer.done);
    // A finished session reads nothing more and writes nothing.
    const after = step(data, &test_output);
    try testing.expectEqual(0, after.consumed);
    try testing.expectEqual(0, after.written);
}

test "an h2 response's body waits for room, and goes out with END_STREAM" {
    _ = try fresh_session(.h2, null);
    _ = step(client_preface, &test_output);
    // No room at all: the request is read and its answer owed.
    var cramped: [1]u8 = undefined;
    const first = step(get_frame(1), &cramped);
    try testing.expectEqual(get_frame(1).len, first.consumed);
    try testing.expect(first.written <= cramped.len);
    const rest = step("", &test_output);
    try testing.expect(rest.written > 0);
    try testing.expectEqual(0, test_session.owed_count);
    try testing.expect(std.mem.endsWith(u8, test_output[0..rest.written], constants.response_body));
}
