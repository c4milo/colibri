//! The tests of design §9's server session (`server_session.zig`) in cleartext, over h11 and h2:
//! every request is answered once it is read whole, in the order it was read, and the echo mode
//! answers with what h11 parsed. Then two connections on one endpoint: an event reaches the entry
//! of the connection it names, a slot serves a new entry while its last one still holds its
//! socket, and a `send_stream` that filled its room is called again. The TLS half is `server`'s,
//! and `src/server/` tests it.
const std = @import("std");
const server = @import("server");
const h2 = @import("h2");
const constants = @import("../constants.zig");
const h11_echo = @import("../h11/h11_echo.zig");
const session_module = @import("server_session.zig");
const entropy = @import("../entropy.zig");

const testing = std.testing;
/// A session of two entries over an endpoint of two slots, so a slot is taken again after one
/// other connection. Test-only.
const Session = session_module.SessionOf(test_connections);
const test_connections: usize = 2;

/// The session, its configuration and buffers, outside any stack frame. Test-only.
var test_session: Session align(@alignOf(Session)) = undefined;
var test_config: server.Config align(@alignOf(server.Config)) = .{};
var test_input: [test_input_len]u8 = undefined;
var test_output: [test_output_len]u8 = undefined;
var test_other_output: [test_output_len]u8 = undefined;
var test_echo: h11_echo.Echo align(@alignOf(h11_echo.Echo)) = undefined;
var test_other_echo: h11_echo.Echo align(@alignOf(h11_echo.Echo)) = undefined;

const test_input_len: usize = constants.echo_body_len_max + test_head_len_max;
const test_output_len: usize = 4096;
/// Room for a head of a request whose content is one past the echo's limit. Test-only.
const test_head_len_max: usize = 128;
/// An output smaller than any echo, so an echo goes out in slices. Test-only.
const test_small_output_len: usize = 128;

/// The response every request gets. Test-only.
const response = "HTTP/1.1 200 OK\r\ncontent-type: " ++ constants.response_content_type ++
    "\r\ncontent-length: " ++ constants.response_content_length ++ "\r\n\r\n";

/// A session speaking `protocol` in cleartext, whose entry 0 holds a connection with nothing read
/// or written: its configuration allows that version alone (decision 117). Test-only.
fn fresh_session(protocol: server.Protocol, echo: ?*h11_echo.Echo) !*Session {
    test_config = .{ .versions = if (protocol == .h2) .{ .h11 = false } else .{ .h2 = false } };
    // Cleartext draws nothing from the source.
    test_now_ns = 0;
    try test_session.init(&test_config, entropy.random(), test_now_ns);
    try testing.expect(test_session.accept(0, .cleartext, echo, test_now_ns));
    return &test_session;
}

/// Steps entry 0 over `input`, copied where the connection may read it, a tick after the step
/// before. Test-only.
fn step(input: []const u8, output: []u8) session_module.Step {
    return step_entry(0, input, output);
}

/// Steps entry `index` the same way. Test-only.
fn step_entry(index: usize, input: []const u8, output: []u8) session_module.Step {
    @memcpy(test_input[0..input.len], input);
    test_now_ns += constants.tick_ns;
    return test_session.step(index, test_input[0..input.len], output, test_now_ns);
}

/// The responses entry `index` owes. Test-only.
fn owed_count(index: usize) u32 {
    return test_session.entries[index].answers.owed_count;
}

/// The instant of the tests' last step. Test-only.
var test_now_ns: u64 = 0;

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

test "RFC 9110 §9.3.6: the server opens no tunnel, so a CONNECT gets 501, and h11 closes after it" {
    _ = try fresh_session(.h11, null);
    const input = "CONNECT a:443 HTTP/1.1\r\nHost: a:443\r\n\r\nGET / HTTP/1.1\r\nHost: a\r\n\r\n";
    const stepped = step(input, &test_output);
    // RFC 9931 §8: nothing after a refused CONNECT is read.
    try testing.expectEqualStrings("HTTP/1.1 501 Not Implemented\r\ncontent-length: 0\r\nConnection: close\r\n\r\n", test_output[0..stepped.written]);
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
    test_now_ns += constants.tick_ns;
    const refused = test_session.step(0, test_input[0 .. head.len + constants.echo_body_len_max + 1], &test_output, test_now_ns);
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
        if (owed_count(0) == 0 and stepped.written == 0) break;
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
    const slot = test_session.entries[0].handle.slot;
    try testing.expectEqual(0, test_session.endpoint.tcp[slot].session.h2.streams.peer_active);
    try testing.expectEqual(0, owed_count(0));
}

/// A HEADERS frame on stream 1 ending it, whose block is `:method: CONNECT` and
/// `:authority: a:443`, each a literal field line naming the static table's entry (RFC 7541
/// §6.2.2, Appendix A), as RFC 9113 §8.5 has a CONNECT carry them. Test-only.
const connect_frame = "\x00\x00\x10\x01\x05\x00\x00\x00\x01" ++ "\x02\x07CONNECT\x01\x05a:443";

/// The status the server answers CONNECT with (RFC 9110 §15.6.2). Test-only.
const not_implemented = "501";

test "RFC 9110 §9.3.6: an h2 CONNECT gets 501 on a HEADERS frame that ends the stream, and no DATA" {
    _ = try fresh_session(.h2, null);
    _ = step(client_preface, &test_output);
    const answer = step(connect_frame, &test_output);
    try testing.expectEqual(connect_frame.len, answer.consumed);
    const written = test_output[0..answer.written];
    try testing.expectEqual(h2.constants.frame_type_headers, written[type_index]);
    try testing.expect(written[flags_index] & h2.constants.flag_end_stream != 0);
    const head_len = h2.constants.frame_header_len + std.mem.readInt(u24, written[0..length_len], .big);
    try testing.expectEqual(head_len, written.len);
    // RFC 7541 Appendix A: the static table holds no :status of 501, so its digits are a string
    // literal, which the encoder writes in the Huffman code because that is shorter (§5.2).
    var digits: [h2.wire.huffman.encoded_len_max(not_implemented.len)]u8 = undefined;
    var writer = h2.core.Writer.init(&digits);
    try h2.wire.huffman.encode(not_implemented, &writer);
    try testing.expect(std.mem.indexOf(u8, written, writer.written()) != null);
    try testing.expectEqual(0, owed_count(0));
    try testing.expect(!answer.done);
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
    try testing.expectEqual(0, owed_count(0));
    try testing.expect(std.mem.endsWith(u8, test_output[0..rest.written], constants.response_body));
}

const get_h11 = "GET / HTTP/1.1\r\nHost: a\r\n\r\n";
const get_h11_close = "GET / HTTP/1.1\r\nHost: a\r\nConnection: close\r\n\r\n";

test "decision 119: an event that names another connection reaches that connection's entry" {
    // h2 alone: each connection owes its preface, a SETTINGS frame, before it reads anything
    // (RFC 9113 §3.4), and the endpoint reports each one's `send` when its turn comes.
    _ = try fresh_session(.h2, null);
    try testing.expect(test_session.accept(1, .cleartext, null, test_now_ns));
    const first = step_entry(0, client_preface, &test_output);
    try testing.expectEqual(h2.constants.frame_type_settings, test_output[type_index]);
    try testing.expect(first.written > 0);
    // The step of entry 0 read the `send` of entry 1, which owes it and waits for its own step.
    try testing.expect(test_session.entries[1].send_owed);
    try testing.expectEqual(@as(?usize, 1), test_session.next_pending());
    try testing.expectEqual(null, test_session.next_pending());
    const second = step_entry(1, "", &test_other_output);
    try testing.expectEqual(h2.constants.frame_type_settings, test_other_output[type_index]);
    try testing.expect(second.written > 0 and !test_session.entries[1].send_owed);
    // Each connection's request is answered on its own stream and in its own output.
    _ = step_entry(1, client_preface, &test_other_output);
    const answered = step_entry(1, get_frame(1), &test_other_output);
    try testing.expect(std.mem.endsWith(u8, test_other_output[0..answered.written], constants.response_body));
    try testing.expectEqual(0, step_entry(0, "", &test_output).written);
}

test "decision 110: one instant's deadlines end two connections, each in its own entry" {
    _ = try fresh_session(.h11, null);
    try testing.expect(test_session.accept(1, .cleartext, null, test_now_ns));
    // Entry 0 sends half a head, which it holds until the rest arrives, and entry 1 nothing.
    const half = "GET / HT";
    const held = half[step_entry(0, half, &test_output).consumed..];
    try testing.expectEqual(0, step_entry(1, "", &test_other_output).written);
    try testing.expectEqual(null, test_session.next_pending());
    // Both were accepted at one instant, so the first-request deadline passes for both at once,
    // and the endpoint's events name both.
    test_now_ns = test_session.deadline_ns().?;
    test_session.on_instant(test_now_ns);
    try testing.expectEqual(@as(?usize, 0), test_session.next_pending());
    try testing.expectEqual(@as(?usize, 1), test_session.next_pending());
    // RFC 9110 §15.5.9: the half head gets a 408, and the silent connection nothing.
    const cut = step_entry(0, held, &test_output);
    try testing.expect(std.mem.startsWith(u8, test_output[0..cut.written], "HTTP/1.1 408 "));
    try testing.expect(cut.done);
    const silent = step_entry(1, "", &test_other_output);
    try testing.expectEqual(0, silent.written);
    try testing.expect(silent.done);
    try testing.expect(!test_session.entries[0].attached and !test_session.entries[1].attached);
}

test "decision 119: a slot serves a new entry while its last entry still holds its socket" {
    _ = try fresh_session(.h11, null);
    try testing.expect(test_session.accept(1, .cleartext, null, test_now_ns));
    const first = test_session.entries[0].handle;
    // Entry 0's connection ends with its response: the endpoint frees its slot, and the entry
    // stays its socket's until the octets are sent and the socket is closed.
    const closing = step_entry(0, get_h11_close, &test_output);
    try testing.expect(closing.done and !test_session.entries[0].attached);
    // Entry 1's peer leaves, so its slot frees after entry 0's. Nothing of its socket's is read
    // from here on, and the endpoint reported no `close` for it.
    test_session.peer_closed(1, test_now_ns);
    try testing.expect(!test_session.entries[1].attached);
    const left = step_entry(1, get_h11, &test_other_output);
    try testing.expectEqual(0, left.consumed + left.written);
    try testing.expect(!left.done);
    // Entry 1 takes a new socket.
    try testing.expect(test_session.accept(1, .cleartext, null, test_now_ns));
    const second = test_session.entries[1].handle;
    try testing.expectEqual(first.slot, second.slot);
    try testing.expect(first.generation != second.generation);
    // The new connection's events name entry 0's old slot, and reach entry 1.
    const answered = step_entry(1, get_h11, &test_other_output);
    try testing.expectEqualStrings(response ++ constants.response_body, test_other_output[0..answered.written]);
    // Entry 0's socket fails late. Its handle names nothing, so the connection in its slot stays.
    test_session.peer_closed(0, test_now_ns);
    try testing.expect(test_session.entries[1].attached);
    const again = step_entry(1, get_h11, &test_other_output);
    try testing.expectEqualStrings(response ++ constants.response_body, test_other_output[0..again.written]);
    // And entry 0 reads and writes nothing more.
    const over = step_entry(0, get_h11, &test_output);
    try testing.expectEqual(0, over.consumed + over.written);
    try testing.expect(over.done);
}

test "an entry whose close was read passes its connection no more input" {
    _ = try fresh_session(.h11, null);
    // What an entry holds between its connection's `close` and its `ended`. One read of the
    // endpoint's events reports both, unless the read stops at its bound between them.
    test_session.entries[0].closing = true;
    const stepped = step_entry(0, get_h11, &test_output);
    try testing.expectEqual(0, stepped.consumed + stepped.written);
    try testing.expect(stepped.done);
    try testing.expectEqual(0, owed_count(0));
}

test "a step that stops at its bound leaves its entry pending" {
    _ = try fresh_session(.h2, null);
    _ = step_entry(0, client_preface, &test_output);
    try testing.expectEqual(null, test_session.next_pending());
    // One pass a step. It reads a WINDOW_UPDATE for the connection (RFC 9113 §6.9), which brings
    // no event and owes no octet, and stops before the pass that would find nothing to do.
    test_session.events_max = 1;
    const window_update = "\x00\x00\x04\x08\x00\x00\x00\x00\x00" ++ "\x00\x00\x00\x01";
    const first = step_entry(0, window_update, &test_output);
    try testing.expectEqual(window_update.len, first.consumed);
    try testing.expectEqual(0, first.written);
    try testing.expectEqual(@as(?usize, 0), test_session.next_pending());
    // The step the worker takes next finds nothing, and the entry is pending no more.
    test_session.mark(0);
    const second = step_entry(0, "", &test_output);
    try testing.expectEqual(0, second.consumed + second.written);
    try testing.expectEqual(null, test_session.next_pending());
}

/// The value of the content-length field in `head` (RFC 9110 §8.6). Test-only.
fn content_length(head: []const u8) !usize {
    const name = "content-length: ";
    const start = (std.mem.indexOf(u8, head, name) orelse return error.TestUnexpectedResult) + name.len;
    const end = std.mem.indexOfPos(u8, head, start, "\r\n") orelse return error.TestUnexpectedResult;
    return std.fmt.parseInt(usize, head[start..end], constants.port_radix);
}

test "decision 119: a send_stream that filled its room stays owed until the response is out" {
    _ = try fresh_session(.h11, &test_echo);
    // An echo many times the room each step has.
    const long_get = "GET /" ++ "a" ** 1200 ++ " HTTP/1.1\r\nHost: a\r\n\r\n";
    var gathered: usize = 0;
    var steps: usize = 0;
    for (0..test_output_len) |_| {
        const room = test_output[gathered..][0..test_small_output_len];
        const stepped = step_entry(0, if (steps == 0) long_get else "", room);
        if (stepped.written == 0) break;
        // A step that filled its room leaves the send owed, and the next one calls again.
        try testing.expectEqual(stepped.written == room.len, test_session.entries[0].send_owed);
        gathered += stepped.written;
        steps += 1;
    }
    // The whole response arrived: the content is as long as its head says.
    const sent = test_output[0..gathered];
    const head_len = std.mem.indexOf(u8, sent, "\r\n\r\n").? + "\r\n\r\n".len;
    try testing.expectEqual(try content_length(sent[0..head_len]), sent.len - head_len);
    try testing.expect(steps > 2 and sent.len > 2 * test_small_output_len);
    try testing.expect(sent[sent.len - 1] == '}');
}

test "the echo mode returns each of two connections its own request" {
    _ = try fresh_session(.h11, &test_echo);
    try testing.expect(test_session.accept(1, .cleartext, &test_other_echo, test_now_ns));
    // Entry 0's head arrives, then entry 1's whole request, then entry 0's content.
    const waiting = step_entry(0, "POST /one HTTP/1.1\r\nHost: a\r\nContent-Length: 3\r\n\r\n", &test_output);
    try testing.expectEqual(0, waiting.written);
    const second = step_entry(1, "GET /two HTTP/1.1\r\nHost: b\r\n\r\n", &test_other_output);
    // "/two", and no content.
    try testing.expect(std.mem.indexOf(u8, test_other_output[0..second.written], "\"uri\":\"L3R3bw==\"") != null);
    try testing.expect(std.mem.endsWith(u8, test_other_output[0..second.written], "\"body\":\"\"}"));
    const first = step_entry(0, "abc", &test_output);
    // "/one", and "abc".
    try testing.expect(std.mem.indexOf(u8, test_output[0..first.written], "\"uri\":\"L29uZQ==\"") != null);
    try testing.expect(std.mem.endsWith(u8, test_output[0..first.written], "\"body\":\"YWJj\"}"));
}

test "an entry a new socket takes starts with nothing owed and not closing" {
    _ = try fresh_session(.h11, null);
    const entry = &test_session.entries[0];
    // The endpoint closes the entry's first connection after its response.
    try testing.expect(step_entry(0, get_h11_close, &test_output).done);
    try testing.expect(entry.closing and !entry.attached);
    // The entry's next socket: its connection reads and answers, and is not closing.
    try testing.expect(test_session.accept(0, .cleartext, null, test_now_ns));
    try testing.expect(!entry.closing);
    // Its peer leaves while the response's send is owed: the room held one octet.
    var cramped: [1]u8 = undefined;
    try testing.expect(!step_entry(0, get_h11, &cramped).done);
    try testing.expect(entry.send_owed);
    test_session.peer_closed(0, test_now_ns);
    try testing.expect(entry.send_owed and !entry.attached);
    // The third socket's connection owes nothing of the second's.
    try testing.expect(test_session.accept(0, .cleartext, null, test_now_ns));
    try testing.expect(!entry.send_owed);
    const answered = step_entry(0, get_h11, &test_output);
    try testing.expectEqualStrings(response ++ constants.response_body, test_output[0..answered.written]);
    try testing.expect(!answered.done);
}
