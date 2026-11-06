//! The tests of a GOAWAY that refuses a request stream the client wrote (RFC 9114 §5.2): the
//! client cancels the stream with H3_REQUEST_CANCELLED (§4.1.1), so the exchange finishes within
//! a few rounds and not at the idle timeout. A stream below the GOAWAY's identifier stays open.
const std = @import("std");
const quic = @import("quic");
const h3 = @import("h3");
const support = @import("quic_test_support.zig");
const event = @import("../event.zig");

const testing = std.testing;
const connection = &support.connection;
const Exchange = support.Exchange;

/// Where the tests' exchanges put their responses, outside any stack frame. Test-only.
var bodies: [bodies_count][body_len]u8 = undefined;
const bodies_count: usize = 2;
const body_len: usize = 1024;

const cancelled = h3.constants.protocol.error_request_cancelled;

fn get(body: []u8) Exchange {
    return .{ .request = .{ .method = "GET", .path = "/dns-query" }, .response = .{ .body = body } };
}

/// The server sends a GOAWAY that names `stream_id`, and the client reads it. `shutdown` names
/// the lowest identifier it sent before, so the test names `stream_id` first. Test-only.
fn goaway_at(stream_id: u64) !void {
    support.server_h3.goaway_sent = stream_id;
    try support.server_h3.shutdown(&support.server, support.now_ns);
    try testing.expectEqual(stream_id, support.server_h3.goaway_sent.?);
    try support.server_to_client();
}

/// The client's record of stream `stream_id`, which must be open. Test-only.
fn client_stream(stream_id: u64) !*quic.stream.Stream {
    return live(&connection.transport, stream_id);
}

/// `transport`'s record of stream `stream_id`, which must be open. Test-only.
fn live(transport: *quic.Connection, stream_id: u64) !*quic.stream.Stream {
    return switch (transport.streams.lookup(.{ .value = stream_id })) {
        .live => |stream| stream,
        else => error.TestUnexpectedResult,
    };
}

/// Moves datagrams until exchange `id` finishes, and fails when it takes more than a few rounds.
/// Test-only.
fn expect_finished_soon(id: event.RequestId) !void {
    for (0..support.rounds_default) |_| {
        if (support.find(.finished) != null) break;
        try support.pump(1);
    }
    try testing.expectEqual(id, support.find(.finished).?.finished.id);
}

test "RFC 9114 §5.2: a GET a GOAWAY refuses has its stream stopped, and finishes at once" {
    try support.start(&support.alpn_h3, &support.alpn_h3, false);
    support.server_answers = false;
    var exchange = get(&bodies[0]);
    const id = try connection.request(&exchange.request, &exchange.response);
    try support.pump(support.rounds_default);
    try testing.expectEqual(1, support.answers_len);
    const stream_id = support.answers[0].id;
    try goaway_at(stream_id);
    // RFC 9114 §4.1.1: the request's part ended with its FIN, so the client stops the server's.
    const stream = try client_stream(stream_id);
    try testing.expect(stream.stop_sending.owed);
    try testing.expectEqual(cancelled, stream.stop_error_code);
    try expect_finished_soon(id);
    try testing.expectEqual(.refused, exchange.response.result);
    // RFC 9000 §3.5: the server answers the STOP_SENDING with a RESET_STREAM, and it "SHOULD copy
    // the error code from the STOP_SENDING frame".
    const answered = try live(&support.server, stream_id);
    try testing.expect(answered.sending.state == .reset_sent or answered.sending.state == .reset_recvd);
    try testing.expectEqual(cancelled, answered.reset_error_code);
}

test "RFC 9114 §5.2: a streamed PUT a GOAWAY refuses has both parts of its stream cancelled" {
    try support.start(&support.alpn_h3, &support.alpn_h3, false);
    support.server_answers = false;
    var exchange: Exchange = .{ .request = .{ .method = "PUT", .path = "/object", .streamed = .{ .request = true } }, .response = .{ .body = &bodies[0] } };
    const id = try connection.request(&exchange.request, &exchange.response);
    try connection.write_body(id, "hello", false);
    try support.pump(support.rounds_default);
    try testing.expectEqual(1, support.answers_len);
    const stream_id = support.answers[0].id;
    try goaway_at(stream_id);
    const stream = try client_stream(stream_id);
    try testing.expect(stream.stop_sending.owed);
    try testing.expectEqual(cancelled, stream.stop_error_code);
    try testing.expectEqual(cancelled, stream.reset_error_code);
    try expect_finished_soon(id);
    try testing.expectEqual(.refused, exchange.response.result);
    // RFC 9000 §19.4: the server read the client's RESET_STREAM and its error code.
    try testing.expectEqual(cancelled, support.answers[0].reset_code.?);
}

test "RFC 9114 §5.2: a stream below the GOAWAY's identifier stays open and gets its response" {
    try support.start(&support.alpn_h3, &support.alpn_h3, false);
    support.server_answers = false;
    var first = get(&bodies[0]);
    var second = get(&bodies[1]);
    const first_id = try connection.request(&first.request, &first.response);
    const second_id = try connection.request(&second.request, &second.response);
    try support.pump(support.rounds_default);
    try testing.expectEqual(2, support.answers_len);
    try goaway_at(support.answers[1].id);
    // The server may still process the first request, so the client cancels nothing of it.
    const kept = try client_stream(support.answers[0].id);
    try testing.expect(!kept.stop_sending.owed and !kept.stop_sending.sent);
    try expect_finished_soon(second_id);
    try testing.expectEqual(.refused, second.response.result);
    try support.server_answer(&support.answers[0], 200, "hello");
    try support.pump(support.rounds_default);
    try testing.expectEqual(.response, first.response.result);
    try testing.expectEqual(null, support.answers[0].reset_code);
    try testing.expectEqualStrings("hello", first.response.body[0..first.response.body_len]);
    try testing.expect(first_id != second_id);
}
