//! The tests of the client's h2 half (`connection_h2.zig`) over cleartext with prior knowledge
//! (RFC 9113 §3.3): exchanges go out as streams to h2's server side in the same process, and what
//! it answers comes back as each exchange's outcome.
const std = @import("std");
const h2 = @import("h2");
const support = @import("connection_test_support.zig");
const event = @import("event.zig");

const testing = std.testing;
const connection = &support.connection;
const Exchange = support.Exchange;

const ok: u16 = 200;
/// RFC 9110 §15.2.4: 103 Early Hints, an interim response.
const early_hints: u16 = 103;
const content_type = [_]h2.hpack.Field{.{ .name = "content-type", .value = "application/dns-message" }};

/// Where the tests' exchanges put their responses, outside any stack frame. Test-only.
var bodies: [bodies_count][support.buffer_len]u8 = undefined;
var values: [values_len]u8 = undefined;
const bodies_count: usize = 2;
const values_len: usize = 256;

/// The one exchange a test sends, and the stream the peer read it on. Test-only.
fn get(body: []u8) Exchange {
    return .{ .method = "GET", .path = "/dns-query", .body = body };
}

/// The request the h2 peer read last. Test-only.
fn peer_request() ?h2.connection.Request {
    var found: ?h2.connection.Request = null;
    for (support.peer_events[0..support.peer_events_len]) |peer_event| {
        if (peer_event == .request) found = peer_event.request;
    }
    return found;
}

fn start() !void {
    try support.start_cleartext(.h2);
    support.peer_events_len = 0;
}

test "RFC 9113 §8.3.1: a GET goes out on stream 1, and its response fills the exchange" {
    try start();
    // RFC 9113 §8.3: `:status` is a pseudo-header field and no field, so the caller reads none.
    var wanted = [_]event.Wanted{ .{ .name = "content-type" }, .{ .name = "age" }, .{ .name = ":status" } };
    var exchange = get(&bodies[0]);
    exchange.wanted = &wanted;
    exchange.values = &values;
    try testing.expectEqual(1, try connection.request(&exchange));
    try support.pump_h2();
    const arrived = peer_request().?;
    try testing.expectEqual(1, arrived.stream_id);
    try testing.expectEqualStrings("GET", arrived.request.method);
    try testing.expect(arrived.end_stream);
    // RFC 9113 §8.3.1: `:authority` carries the origin, and a cleartext request's scheme is http.
    try testing.expectEqualStrings("localhost", arrived.request.authority.?);
    try testing.expectEqualStrings("http", arrived.request.scheme.?);
    try support.peer_h2_answer(1, ok, &content_type, "hello");
    try support.client_receive();
    try testing.expectEqual(event.Protocol.h2, support.find(.connected).?.connected);
    const finished = support.find(.finished).?.finished;
    try testing.expectEqual(1, finished.id);
    try testing.expectEqual(&exchange, finished.exchange);
    try testing.expectEqual(.response, exchange.outcome);
    try testing.expectEqual(ok, exchange.status);
    try testing.expectEqualStrings("hello", exchange.content_received());
    try testing.expectEqualStrings("application/dns-message", wanted[0].value.?);
    try testing.expectEqual(null, wanted[1].value);
    try testing.expectEqual(null, wanted[2].value);
}

test "RFC 9113 §6.9: content past the stream's window goes out as the peer grants more" {
    try start();
    // RFC 9113 §6.9.2: a stream starts with 65,535 octets of window, so this content goes out
    // whole only if the client reads the peer's WINDOW_UPDATE frames.
    const content_len = 3 * h2.constants.initial_window_size_initial;
    const content = bodies[1][0..content_len];
    @memset(content, 'x');
    var exchange: Exchange = .{ .method = "POST", .path = "/upload", .content = content, .body = &bodies[0] };
    _ = try connection.request(&exchange);
    var received: usize = 0;
    for (0..support.events_max) |_| {
        try support.pump_h2();
        for (support.peer_events[0..support.peer_events_len]) |peer_event| {
            if (peer_event == .data) received += peer_event.data.payload.len;
        }
        support.peer_events_len = 0;
        if (received == content_len) break;
    }
    try testing.expectEqual(content_len, received);
    try support.peer_h2_answer(1, ok, &.{}, "");
    try support.client_receive();
    try testing.expectEqual(.response, exchange.outcome);
    try testing.expectEqual(0, exchange.body_len);
}

test "RFC 9110 §15.2: interim responses are counted, and the final one gives the status" {
    try start();
    var exchange = get(&bodies[0]);
    _ = try connection.request(&exchange);
    try support.pump_h2();
    support.to_client_len += try support.peer_h2.write_response(support.to_client[support.to_client_len..], 1, early_hints, &.{}, false);
    try support.client_receive();
    try testing.expectEqual(1, exchange.interims);
    try testing.expectEqual(.pending, exchange.outcome);
    try support.peer_h2_answer(1, ok, &.{}, "done");
    try support.client_receive();
    try testing.expectEqual(ok, exchange.status);
    try testing.expectEqualStrings("done", exchange.content_received());
}

test "RFC 9113 §6.4: content past the caller's memory ends the exchange, and CANCEL stops the rest" {
    try start();
    var exchange = get(bodies[0][0..4]);
    _ = try connection.request(&exchange);
    try support.pump_h2();
    // The content does not end the stream, so more of it would follow.
    support.to_client_len += try support.peer_h2.write_response(support.to_client[support.to_client_len..], 1, ok, &.{}, false);
    support.to_client_len += (try support.peer_h2.write_data(support.to_client[support.to_client_len..], 1, "hello", false)).written;
    try support.client_receive();
    try testing.expectEqual(.too_large, exchange.outcome);
    support.peer_events_len = 0;
    try support.pump_h2();
    const reset = for (support.peer_events[0..support.peer_events_len]) |peer_event| {
        if (peer_event == .stream_reset) break peer_event.stream_reset;
    } else return error.TestUnexpectedResult;
    try testing.expectEqual(h2.constants.error_cancel, reset.error_code);
}

test "RFC 9113 §8.7: REFUSED_STREAM ends an exchange refused, and another code ends it reset" {
    try start();
    var first = get(&bodies[0]);
    var second = get(&bodies[1]);
    _ = try connection.request(&first);
    _ = try connection.request(&second);
    try support.pump_h2();
    try support.peer_h2.reset_stream(1, h2.constants.error_refused_stream);
    try support.peer_h2.reset_stream(3, h2.constants.error_internal_error);
    support.peer_h2_owe();
    try support.client_receive();
    try testing.expectEqual(.refused, first.outcome);
    try testing.expectEqual(.reset, second.outcome);
    try testing.expectEqual(h2.constants.error_internal_error, second.error_code);
}

test "RFC 9113 §6.8: a GOAWAY refuses the exchanges past its last stream, and the connection drains" {
    try start();
    var first = get(&bodies[0]);
    var second = get(&bodies[1]);
    _ = try connection.request(&first);
    _ = try connection.request(&second);
    try support.pump_h2();
    // The peer took stream 1 and says so; stream 3 it never processed.
    var writer = h2.core.Writer.init(support.to_client[support.to_client_len..]);
    try h2.frame.write_goaway(&writer, 1, h2.constants.error_no_error, "");
    support.to_client_len += writer.written().len;
    try support.client_receive();
    try testing.expectEqual(.refused, second.outcome);
    try testing.expect(support.find(.draining) != null);
    var third = get(&bodies[1]);
    try testing.expectError(error.Draining, connection.request(&third));
    // The exchange the peer took is answered, and then the connection is over.
    try support.peer_h2_answer(1, ok, &.{}, "");
    try support.client_receive();
    try testing.expectEqual(.response, first.outcome);
    try testing.expect(support.find(.closed) != null);
    support.client_send();
    try testing.expect(connection.should_close());
}

test "RFC 9113 §6.4: a cancelled exchange's stream is reset with CANCEL, and no event reports it" {
    try start();
    var exchange = get(&bodies[0]);
    const id = try connection.request(&exchange);
    try support.pump_h2();
    connection.cancel(id);
    support.peer_events_len = 0;
    try support.pump_h2();
    try testing.expectEqual(h2.constants.error_cancel, support.peer_events[0].stream_reset.error_code);
    try testing.expectEqual(0, support.count(.finished));
    try testing.expectEqual(.pending, exchange.outcome);
}

test "RFC 9113 §8.3.1: a method h2 refuses to send ends its exchange invalid and spends no stream" {
    try start();
    var bad: Exchange = .{ .method = "G ET", .path = "/", .body = &bodies[0] };
    var good = get(&bodies[1]);
    _ = try connection.request(&bad);
    _ = try connection.request(&good);
    try support.pump_h2();
    try testing.expectEqual(.invalid, bad.outcome);
    // RFC 9113 §5.1.1: the refused request spent no identifier.
    try testing.expectEqual(1, peer_request().?.stream_id);
}

test "RFC 9113 §5.4.1: a peer that breaks the protocol ends every exchange, and the connection" {
    try start();
    var exchange = get(&bodies[0]);
    _ = try connection.request(&exchange);
    support.client_send();
    // RFC 9113 §3.4: the server's first frame must be SETTINGS, and this is a PING.
    const ping = "\x00\x00\x08\x06\x00\x00\x00\x00\x00" ++ "colibri!";
    @memcpy(support.to_client[0..ping.len], ping);
    support.to_client_len = ping.len;
    try support.client_receive();
    try testing.expectEqual(.closed, exchange.outcome);
    try testing.expect(support.find(.closed) != null);
    try testing.expectError(error.ConnectionClosed, connection.request(&exchange));
    // The GOAWAY colibri owes goes out before the caller closes.
    support.to_peer_len = 0;
    support.client_send();
    try testing.expectEqual(h2.constants.frame_type_goaway, support.to_peer[3]);
    try testing.expect(connection.should_close());
}

test "RFC 9113 §6.8: a shut-down connection sends GOAWAY after its last exchange, and closes" {
    try start();
    var exchange = get(&bodies[0]);
    _ = try connection.request(&exchange);
    try support.pump_h2();
    connection.shutdown();
    try support.client_receive();
    try testing.expect(support.find(.draining) != null);
    try testing.expect(!connection.should_close());
    try support.peer_h2_answer(1, ok, &.{}, "");
    try support.client_receive();
    try testing.expect(support.find(.closed) != null);
    support.peer_events_len = 0;
    support.client_send();
    try support.peer_h2_read();
    try testing.expectEqual(.goaway, std.meta.activeTag(support.peer_events[0]));
    try testing.expect(connection.should_close());
}
