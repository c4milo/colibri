//! The tests of a streamed response body on a TCP connection (`connection_body.zig`, decision 153
//! ruling 7, design §8 step 39f). Each piece fills `Response.body` at most, the connection reads
//! no more while the caller holds it, and the exchange finishes only once the last piece is
//! released. Over h2 the stream's credit goes back only as the caller releases, a cancel gives
//! back a held piece, and a request body goes on after the response's head (design §8 step 39g).
const std = @import("std");
const h2 = @import("h2");
const support = @import("connection_test_support.zig");
const tls_support = @import("connection_tls_test_support.zig");

const testing = std.testing;
const connection = &support.connection;
const Exchange = support.Exchange;
const RequestId = @import("connection.zig").RequestId;
const Header = support.Header;

/// Where each piece lands: four octets, so most runs of content leave a tail. Test-only.
var piece: [piece_len]u8 = undefined;
const piece_len: usize = 4;
/// Where each piece lands in the test of flow control: half a full DATA frame (RFC 9113 §4.2).
var frame_piece: [frame_piece_len]u8 = undefined;
const frame_piece_len: usize = 8192;
var trailer_buffer: [trailer_buffer_len]u8 = undefined;
const trailer_buffer_len: usize = 64;

/// What the pieces added up to, and the events of the exchange the tests count. Test-only.
var received: [content_len]u8 = undefined;
var received_len: usize = 0;
var headers_count: usize = 0;
var pieces_count: usize = 0;
var finished_count: usize = 0;
var taken_count: usize = 0;

/// The content the h2 peer sends in the test of flow control: more than the stream's window.
var content: [content_len]u8 = undefined;
const content_len: usize = 100_000;

const ok: u16 = 200;
const alphabet = "abcdefghijklmnopqrstuvwxyz";
/// Rounds of reading and releasing one test takes at most.
const rounds_max: usize = 256;
/// RFC 9113 §6.9.2: the initial window of every stream, 65,535 octets.
const window_initial: usize = 65_535;

/// A GET whose response comes in pieces of `body`'s length.
fn streamed_get(body: []u8) Exchange {
    return .{
        .request = .{ .method = "GET", .path = "/stream", .streamed = .{ .response = true } },
        .response = .{ .body = body, .trailers = .{ .buffer = &trailer_buffer } },
    };
}

fn reset_counts() void {
    received_len = 0;
    headers_count = 0;
    pieces_count = 0;
    finished_count = 0;
    taken_count = 0;
}

/// Reads what the peer sent until the client reads nothing more, keeps the piece of exchange `id`
/// it reported, if any, and releases it. Returns whether a piece came.
fn read_piece(id: RequestId) !bool {
    support.events_len = 0;
    try support.client_receive();
    var held = false;
    var held_len: usize = 0;
    for (support.events[0..support.events_len]) |reported| {
        switch (reported) {
            .headers => |headers_id| {
                try testing.expectEqual(id, headers_id);
                headers_count += 1;
            },
            .body => |body| {
                try testing.expectEqual(id, body.id);
                held = true;
                held_len = body.len;
            },
            .body_taken => taken_count += 1,
            .finished => |finished| {
                // Decision 153 ruling 7: the exchange finishes only once its last piece is back.
                try testing.expect(!held);
                try testing.expectEqual(id, finished.id);
                finished_count += 1;
            },
            else => {},
        }
    }
    if (!held) return false;
    // The connection reads nothing more while the caller holds the piece.
    const waiting = connection.receive(support.to_client[0..support.to_client_len], support.now_ns);
    try testing.expectEqual(0, waiting.consumed);
    try testing.expectEqual(null, waiting.event);
    const response = connection.slots.of_id(id).?.response;
    try testing.expectEqual(held_len, response.body_len);
    @memcpy(received[received_len..][0..held_len], response.body[0..held_len]);
    received_len += held_len;
    pieces_count += 1;
    connection.release_body(id);
    return true;
}

/// Reads and releases every piece of exchange `id` the peer sent.
fn read_pieces(id: RequestId) !void {
    for (0..rounds_max) |_| {
        if (!try read_piece(id)) return;
    }
    return error.TestUnexpectedResult;
}

test "decision 153 ruling 7: an h11 response comes in pieces of Response.body's length, each held until its release" {
    try support.start_cleartext(.h11);
    reset_counts();
    var get = streamed_get(&piece);
    const id = try connection.request(&get.request, &get.response);
    support.client_send();
    try support.peer_h11_read();
    try support.peer_h11_answer(ok, &.{.{ .name = "Content-Length", .value = "26" }}, alphabet);
    try read_pieces(id);
    try testing.expectEqual(1, headers_count);
    try testing.expectEqual(ok, @intFromEnum(get.response.status));
    // RFC 9112 §6.3: 26 octets in pieces of 4.
    try testing.expectEqual(7, pieces_count);
    try testing.expectEqualStrings(alphabet, received[0..received_len]);
    try testing.expectEqual(1, finished_count);
    try testing.expectEqual(.response, get.response.result);
    try testing.expectEqual(0, get.response.body_len);
    try testing.expectEqual(0, support.to_client_len);
}

test "RFC 9112 §7.1.2: a chunked streamed response's trailer section lands in Response.trailers" {
    try support.start_cleartext(.h11);
    reset_counts();
    var get = streamed_get(&piece);
    const id = try connection.request(&get.request, &get.response);
    support.client_send();
    try support.peer_h11_read();
    const peer = &support.peer_h11;
    support.to_client_len += try peer.write_response(support.to_client[support.to_client_len..], ok, "", &.{.{ .name = "Transfer-Encoding", .value = "chunked" }});
    support.to_client_len += try peer.write_body(support.to_client[support.to_client_len..], alphabet[0..10]);
    support.to_client_len += try peer.write_body(support.to_client[support.to_client_len..], alphabet[10..]);
    const trailers = [_]Header{.{ .name = "grpc-status", .value = "0" }};
    support.to_client_len += try peer.write_end(support.to_client[support.to_client_len..], &trailers);
    try read_pieces(id);
    try testing.expectEqualStrings(alphabet, received[0..received_len]);
    try testing.expectEqual(1, finished_count);
    try testing.expectEqualStrings("0", get.response.trailers.get("grpc-status").?);
    try testing.expectEqual(null, get.response.headers.get("grpc-status"));
}

test "decision 153 ruling 7: over TLS an h11 response's pieces wait in the opened records" {
    try tls_support.prepare_tls(&support.protocols_h11, &support.protocols_h11, "localhost", false);
    try tls_support.run_handshake();
    try tls_support.server_open();
    tls_support.peer_plain_len = 0;
    support.peer_h11.init(.{ .role = .server });
    try support.peer_h11.attach_tls(tls_support.server.provider());
    reset_counts();
    var get = streamed_get(&piece);
    const id = try connection.request(&get.request, &get.response);
    support.client_send();
    try tls_support.server_open();
    _ = try support.peer_h11.receive(tls_support.peer_plain[0..tls_support.peer_plain_len], &.{});
    const out = &tls_support.peer_out;
    var written = try support.peer_h11.write_response(out, ok, "", &.{.{ .name = "Content-Length", .value = "26" }});
    written += try support.peer_h11.write_body(out[written..], alphabet);
    written += try support.peer_h11.write_end(out[written..], &.{});
    try tls_support.server_seal(out[0..written]);
    try read_pieces(id);
    try testing.expectEqual(7, pieces_count);
    try testing.expectEqualStrings(alphabet, received[0..received_len]);
    try testing.expectEqual(1, finished_count);
}

/// Reads until the client reports the piece of exchange `id`, which it holds. Test-only.
fn read_held(id: RequestId) !void {
    support.events_len = 0;
    try support.client_receive();
    try testing.expectEqual(id, support.find(.body).?.body.id);
}

/// Releases the held piece of exchange `id`, and requires the exchange to finish only after the
/// release. Test-only.
fn finish_at_release(id: RequestId) !void {
    try testing.expectEqual(null, support.find(.finished));
    connection.release_body(id);
    support.events_len = 0;
    try support.client_receive();
    try testing.expectEqual(id, support.find(.finished).?.finished.id);
}

/// An h11 answer whose body fits one piece. RFC 9112 §9.6: with the "close" option the server
/// closes the connection after it.
const closing_answer = [_]Header{
    .{ .name = "Content-Length", .value = "3" },
    .{ .name = "Connection", .value = "close" },
};

test "RFC 9112 §6.3: an h11 response read whole ends `response` when the transport closes while its last piece is held" {
    try support.start_cleartext(.h11);
    var get = streamed_get(&piece);
    const id = try connection.request(&get.request, &get.response);
    support.client_send();
    try support.peer_h11_read();
    try support.peer_h11_answer(ok, &closing_answer, "abc");
    try read_held(id);
    connection.transport_closed();
    try finish_at_release(id);
    try testing.expectEqual(.response, get.response.result);
}

test "RFC 9112 §8: an h11 response whose octets wait in the caller's input ends `closed` when the transport closes" {
    try support.start_cleartext(.h11);
    var get = streamed_get(&piece);
    const id = try connection.request(&get.request, &get.response);
    support.client_send();
    try support.peer_h11_read();
    try support.peer_h11_answer(ok, &.{.{ .name = "Content-Length", .value = "26" }}, alphabet);
    try read_held(id);
    // The rest of the body is in the caller's input, which the connection reads no more.
    connection.transport_closed();
    try finish_at_release(id);
    try testing.expectEqual(.closed, get.response.result);
}

test "RFC 9846 §6.1: over TLS an h11 response read whole ends `response` when close_notify comes with its last piece" {
    try tls_support.prepare_tls(&support.protocols_h11, &support.protocols_h11, "localhost", false);
    try tls_support.run_handshake();
    try tls_support.server_open();
    tls_support.peer_plain_len = 0;
    support.peer_h11.init(.{ .role = .server });
    try support.peer_h11.attach_tls(tls_support.server.provider());
    var get = streamed_get(&piece);
    const id = try connection.request(&get.request, &get.response);
    support.client_send();
    try tls_support.server_open();
    _ = try support.peer_h11.receive(tls_support.peer_plain[0..tls_support.peer_plain_len], &.{});
    const out = &tls_support.peer_out;
    var written = try support.peer_h11.write_response(out, ok, "", &closing_answer);
    written += try support.peer_h11.write_body(out[written..], "abc");
    written += try support.peer_h11.write_end(out[written..], &.{});
    try tls_support.server_seal(out[0..written]);
    // RFC 9846 §6.1: the close_notify arrives in the same input as the last piece, so the client
    // reads it while the caller holds the piece.
    const provider = tls_support.server.provider();
    support.to_client_len += try provider.vtable.send_close_notify(provider.context, support.to_client[support.to_client_len..]);
    try read_held(id);
    try finish_at_release(id);
    try testing.expectEqual(.response, get.response.result);
}

test "decision 153: a streamed response is offered no content coding, and its pieces come as they were sent" {
    try support.start_coding(.h11);
    reset_counts();
    var get = streamed_get(&piece);
    const id = try connection.request(&get.request, &get.response);
    support.client_send();
    // Decision 101: the client offers its codings for a response it reads whole, and none here.
    try testing.expectEqual(null, std.mem.indexOf(u8, support.to_peer[0..support.to_peer_len], "Accept-Encoding"));
    try support.peer_h11_read();
    try support.peer_h11_answer(ok, &.{.{ .name = "Content-Length", .value = "26" }}, alphabet);
    try read_pieces(id);
    try testing.expectEqualStrings(alphabet, received[0..received_len]);
    try testing.expectEqual(null, get.response.coding);
}

test "decision 153 ruling 7: a cancel gives back an h11 piece, and the rest of the response is dropped" {
    try support.start_cleartext(.h11);
    reset_counts();
    var get = streamed_get(&piece);
    const id = try connection.request(&get.request, &get.response);
    support.client_send();
    try support.peer_h11_read();
    try support.peer_h11_answer(ok, &.{.{ .name = "Content-Length", .value = "26" }}, alphabet);
    support.events_len = 0;
    try support.client_receive();
    try testing.expect(support.find(.body) != null);
    connection.cancel(id, support.now_ns);
    // The rest of the response is read and dropped, and nothing reports it.
    support.events_len = 0;
    try support.client_receive();
    try testing.expectEqual(0, support.events_len);
    try testing.expectEqual(0, support.to_client_len);
    // The connection goes on with the next exchange.
    var next = streamed_get(&piece);
    const next_id = try connection.request(&next.request, &next.response);
    support.client_send();
    try support.peer_h11_read();
    try support.peer_h11_answer(ok, &.{.{ .name = "Content-Length", .value = "3" }}, "abc");
    try read_pieces(next_id);
    try testing.expectEqualStrings("abc", received[0..received_len]);
    try testing.expectEqual(1, finished_count);
}

/// Writes a DATA frame on `stream_id` that carries `data` with `padding_len` octets of padding
/// and END_STREAM (RFC 9113 §6.1), as the h2 peer would.
fn peer_padded_data(stream_id: u32, data: []const u8, padding_len: u8) !void {
    var frame = h2.core.Writer.init(support.to_client[support.to_client_len..]);
    const flags = h2.constants.protocol.flag_padded | h2.constants.protocol.flag_end_stream;
    const length: u32 = @intCast(1 + data.len + padding_len);
    try h2.frame.write_header(&frame, .{ .length = length, .type = .data, .flags = flags, .stream_id = stream_id });
    try frame.write_int_big(u8, padding_len);
    try frame.write_bytes(data);
    for (0..padding_len) |_| try frame.write_int_big(u8, 0);
    support.to_client_len += frame.written().len;
}

/// Starts an h2 connection in cleartext, and sends a streamed GET whose response comes in pieces
/// of `body`'s length.
fn start_h2(get: *Exchange) !RequestId {
    try support.start_cleartext(.h2);
    try support.pump_h2();
    reset_counts();
    const id = try connection.request(&get.request, &get.response);
    support.client_send();
    try support.peer_h2_read();
    support.to_client_len += try support.peer_h2.write_response(support.to_client[support.to_client_len..], 1, ok, &.{}, false);
    return id;
}

test "RFC 9113 §6.1: an h2 piece that leaves a tail skips the frame's padding, and END_STREAM ends the response after it" {
    var get = streamed_get(&piece);
    const id = try start_h2(&get);
    try peer_padded_data(1, alphabet[0..10], 5);
    try read_pieces(id);
    try testing.expectEqual(1, headers_count);
    try testing.expectEqual(3, pieces_count);
    try testing.expectEqualStrings(alphabet[0..10], received[0..received_len]);
    try testing.expectEqual(1, finished_count);
    try testing.expectEqual(.response, get.response.result);
    try testing.expectEqual(0, support.to_client_len);
}

test "RFC 9113 §6.9: a server faster than the caller waits for the stream's credit, which goes back only as the caller releases" {
    for (&content, 0..) |*octet, index| octet.* = alphabet[index % alphabet.len];
    var get = streamed_get(&frame_piece);
    const id = try start_h2(&get);
    var sent: usize = 0;
    var released: usize = 0;
    for (0..rounds_max) |_| {
        if (sent < content.len) {
            const written = try support.peer_h2.write_data(support.to_client[support.to_client_len..], 1, content[sent..], true);
            sent += written.consumed;
            support.to_client_len += written.written;
        }
        // RFC 9113 §6.9.1: the peer sends the window and what the client gave back, and the
        // client gives back only what the caller released.
        try testing.expect(sent <= window_initial + released);
        if (try read_piece(id)) released = received_len;
        support.client_send();
        try support.peer_h2_read();
        if (finished_count > 0) break;
    }
    try testing.expect(pieces_count > content.len / frame_piece_len);
    try testing.expectEqualStrings(&content, received[0..received_len]);
    try testing.expectEqual(.response, get.response.result);
}

test "decision 153 ruling 7: a cancel gives back an h2 piece, and the stream's tail is skipped" {
    var get = streamed_get(&piece);
    const id = try start_h2(&get);
    // The stream stays open, so the client's CANCEL closes it.
    const sent = try support.peer_h2.write_data(support.to_client[support.to_client_len..], 1, alphabet, false);
    support.to_client_len += sent.written;
    support.events_len = 0;
    try support.client_receive();
    try testing.expect(support.find(.body) != null);
    try testing.expect(support.to_client_len > 0);
    connection.cancel(id, support.now_ns);
    support.events_len = 0;
    try support.client_receive();
    try testing.expectEqual(0, support.events_len);
    try testing.expectEqual(0, support.to_client_len);
    // RFC 9113 §6.4: CANCEL closes the stream.
    support.client_send();
    support.peer_events_len = 0;
    try support.peer_h2_read();
    var resets: usize = 0;
    for (support.peer_events[0..support.peer_events_len]) |peer_event| resets += @intFromBool(peer_event == .stream_reset);
    try testing.expectEqual(1, resets);
}

/// The h2 peer reads every whole frame the client sent, and sends back each DATA frame's payload
/// on the stream it came on, ending its own side when the client ended its. Returns the octets of
/// the request's content it read.
fn peer_h2_echo() !usize {
    var echoed: usize = 0;
    var consumed: usize = 0;
    // Bounded: each pass consumes an octet or writes what the peer owes, and both are finite.
    for (0..support.to_peer_len + support.events_max) |_| {
        const read = try support.peer_h2.receive(support.to_peer[consumed..support.to_peer_len], support.now_ns);
        if (read.consumed == 0) {
            if (!support.peer_h2.has_pending()) break;
            support.peer_h2_owe();
            continue;
        }
        consumed += read.consumed;
        const data = switch (read.event orelse continue) {
            .data => |data| data,
            else => continue,
        };
        const sent = try support.peer_h2.write_data(support.to_client[support.to_client_len..], data.stream_id, data.payload, data.end_stream);
        try testing.expectEqual(data.payload.len, sent.consumed);
        support.to_client_len += sent.written;
        echoed += data.payload.len;
    }
    support.to_peer_len = 0;
    support.peer_h2_owe();
    return echoed;
}

test "RFC 9113 §8.1: over h2 a request body goes on after the response's head, and both bodies arrive whole" {
    var echo: Exchange = .{
        .request = .{ .method = "POST", .path = "/echo", .streamed = .{ .request = true, .response = true } },
        .response = .{ .body = &piece },
    };
    const id = try start_h2(&echo);
    // The response's head comes first, and the request's content goes on after it.
    try read_pieces(id);
    try testing.expectEqual(1, headers_count);
    const parts = [_][]const u8{ alphabet[0..5], alphabet[5..20], alphabet[20..] };
    var echoed: usize = 0;
    for (parts, 1..) |part, handed| {
        try connection.write_body(id, part, handed == parts.len);
        support.client_send();
        echoed += try peer_h2_echo();
        try read_pieces(id);
        try testing.expectEqual(handed, taken_count);
    }
    try testing.expectEqual(alphabet.len, echoed);
    try testing.expectEqualStrings(alphabet, received[0..received_len]);
    try testing.expectEqual(1, finished_count);
    try testing.expectEqual(.response, echo.response.result);
    try testing.expectEqual(alphabet.len, echo.response.body_sent);
}
