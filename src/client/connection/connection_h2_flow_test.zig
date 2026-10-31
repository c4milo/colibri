//! More tests of the client's h2 half (`connection_h2.zig`): what the server's limits, a GOAWAY, a
//! response that ends the stream early and colibri's own resets leave each exchange. Split out of
//! `connection_h2_test.zig` for length.
const std = @import("std");
const h2 = @import("h2");
const support = @import("connection_test_support.zig");
const constants = @import("../constants.zig");

const testing = std.testing;
const connection = &support.connection;
const Exchange = support.Exchange;
const Header = support.Header;

const ok: u16 = 200;

/// Where the tests' exchanges put their responses, and the content they send, outside any stack
/// frame. Test-only.
var bodies: [bodies_count][body_len]u8 = undefined;
var upload: [upload_len]u8 = undefined;
const bodies_count: usize = 2;
const body_len: usize = 64;
/// RFC 9113 §6.9.2: past the 65,535 octets a stream's window starts with. Test-only.
const upload_len: usize = 196_605;
/// Longer than the connection's own output, and within the 65,535 octets a stream's window starts
/// with (RFC 9113 §6.9.2). Test-only.
const direct_len: usize = 60_000;

comptime {
    std.debug.assert(direct_len > constants.limits.output_len);
}

fn start() !void {
    try support.start_cleartext(.h2);
    support.peer_events_len = 0;
}

fn get(body: []u8) Exchange {
    return .{ .request = .{ .method = "GET", .path = "/" }, .response = .{ .body = body } };
}

/// The first stream reset the h2 peer read, or null. Test-only.
fn peer_reset() ?h2.connection.StreamReset {
    for (support.peer_events[0..support.peer_events_len]) |peer_event| {
        if (peer_event == .stream_reset) return peer_event.stream_reset;
    }
    return null;
}

test "RFC 9113 §8.1: a response that ends before the upload does closes the stream with CANCEL" {
    try start();
    @memset(&upload, 'x');
    var post: Exchange = .{ .request = .{ .method = "POST", .path = "/", .body = &upload }, .response = .{ .body = &bodies[0] } };
    _ = try connection.request(&post.request, &post.response);
    support.client_send();
    try support.peer_h2_read();
    // The server answers whole while most of the content is still to come.
    try support.peer_h2_answer(1, ok, &.{}, "");
    try support.client_receive();
    try testing.expectEqual(.response, post.response.result);
    try testing.expect(post.response.body_sent < upload.len);
    support.peer_events_len = 0;
    try support.pump_h2();
    try testing.expectEqual(h2.constants.protocol.error_cancel, peer_reset().?.error_code);
}

test "RFC 9113 §6.8: an exchange not yet written when a GOAWAY arrives is refused" {
    try start();
    var sent = get(&bodies[0]);
    var waiting = get(&bodies[1]);
    _ = try connection.request(&sent.request, &sent.response);
    try support.pump_h2();
    _ = try connection.request(&waiting.request, &waiting.response);
    var writer = h2.core.Writer.init(support.to_client[support.to_client_len..]);
    try h2.frame.write_goaway(&writer, 1, h2.constants.protocol.error_no_error, "");
    support.to_client_len += writer.written().len;
    try support.client_receive();
    try testing.expectEqual(.refused, waiting.response.result);
    try testing.expectEqual(.pending, sent.response.result);
}

test "RFC 9113 §5.1.2: an exchange past the server's stream limit waits for a stream to close" {
    try start();
    // The prefaces go first: the server's own SETTINGS names its limit, and this one lowers it.
    try support.pump_h2();
    try support.peer_setting(h2.constants.protocol.setting_max_concurrent_streams, 1);
    try support.client_receive();
    var first = get(&bodies[0]);
    var second = get(&bodies[1]);
    _ = try connection.request(&first.request, &first.response);
    _ = try connection.request(&second.request, &second.response);
    try support.pump_h2();
    try testing.expectEqual(1, connection.slots.count(.sent));
    try testing.expectEqual(.pending, second.response.result);
    try support.peer_h2_answer(1, ok, &.{}, "");
    try support.pump_h2();
    // The first stream closed, so the second exchange opened stream 3.
    try support.peer_h2_answer(3, ok, &.{}, "");
    try support.client_receive();
    try testing.expectEqual(.response, first.response.result);
    try testing.expectEqual(.response, second.response.result);
}

test "RFC 9113 §5.1.1: with no stream identifier left, an exchange is refused and the connection drains" {
    try start();
    connection.session.h2.streams.next_local_id = h2.constants.protocol.stream_id_max + h2.constants.protocol.stream_id_step;
    var exchange = get(&bodies[0]);
    _ = try connection.request(&exchange.request, &exchange.response);
    try support.pump_h2();
    try testing.expectEqual(.refused, exchange.response.result);
    try testing.expect(support.find(.draining) != null);
}

test "RFC 9113 §4.3: a field section past what h2 sends in one block ends its exchange invalid" {
    try start();
    var value: [8000]u8 = undefined;
    // RFC 7541 Appendix B: '~' takes 13 bits in the Huffman code, so the literal goes out raw.
    @memset(&value, '~');
    const fields = [_]Header{
        .{ .name = "x-a", .value = &value }, .{ .name = "x-b", .value = &value }, .{ .name = "x-c", .value = &value },
        .{ .name = "x-d", .value = &value }, .{ .name = "x-e", .value = &value },
    };
    var exchange: Exchange = .{ .request = .{ .method = "GET", .path = "/", .headers = &fields }, .response = .{ .body = &bodies[0] } };
    _ = try connection.request(&exchange.request, &exchange.response);
    try support.pump_h2();
    try testing.expectEqual(.invalid, exchange.response.result);
}

test "RFC 9113 §8.1: content before the response's head is malformed, and colibri resets the stream" {
    try start();
    var exchange = get(&bodies[0]);
    _ = try connection.request(&exchange.request, &exchange.response);
    try support.pump_h2();
    var writer = h2.core.Writer.init(support.to_client[support.to_client_len..]);
    try h2.frame.write_data(&writer, 1, "hello", true, 0);
    support.to_client_len += writer.written().len;
    try support.client_receive();
    try testing.expectEqual(.malformed, exchange.response.result);
    try testing.expectEqual(0, exchange.response.body_len);
    support.peer_events_len = 0;
    try support.pump_h2();
    try testing.expectEqual(h2.constants.protocol.error_protocol_error, peer_reset().?.error_code);
}

/// The encoder a test writes the representations it looks for with, as h2's own encoder writes
/// them, outside any stack frame. Test-only.
var test_encoder: h2.hpack.Encoder align(@alignOf(h2.hpack.Encoder)) = undefined;
var test_representation: [representation_len_max]u8 = undefined;
const representation_len_max: usize = 256;

/// How h2's encoder writes one field line `how`, with no size update before it. Test-only.
fn representation(name: []const u8, value: []const u8, how: h2.hpack.encoder.Indexing) ![]const u8 {
    test_encoder.init(h2.constants.protocol.header_table_size_initial, .when_shorter);
    var writer = h2.core.Writer.init(&test_representation);
    try test_encoder.write_field(&writer, name, value, how);
    return writer.written();
}

fn sent_holds(octets: []const u8) bool {
    return std.mem.indexOf(u8, support.to_peer[0..support.to_peer_len], octets) != null;
}

test "RFC 7541 §7.1.3: the path and a marked field line go out never-indexed, and the rest without indexing" {
    try start();
    const fields = [_]Header{ .{ .name = "authorization", .value = "secret" }, .{ .name = "accept", .value = "application/dns-message" } };
    const marks = [_]bool{ true, false };
    var exchange: Exchange = .{
        .request = .{
            .method = "GET",
            .path = "/dns-query?dns=AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE",
            .headers = &fields,
            .never_indexed = .{ .path = true, .headers = &marks },
        },
        .response = .{ .body = &bodies[0] },
    };
    _ = try connection.request(&exchange.request, &exchange.response);
    support.client_send();
    try testing.expect(sent_holds(try representation(":path", exchange.request.path, .never_indexed)));
    try testing.expect(sent_holds(try representation("authorization", "secret", .never_indexed)));
    try testing.expect(sent_holds(try representation("accept", "application/dns-message", .without_indexing)));
}

test "decision 138: a content longer than the connection's output goes out in cleartext in one send" {
    try start();
    @memset(&upload, 'x');
    var put: Exchange = .{ .request = .{ .method = "PUT", .path = "/", .body = upload[0..direct_len] }, .response = .{ .body = &bodies[0] } };
    _ = try connection.request(&put.request, &put.response);
    support.client_send();
    // https://github.com/c4milo/colibri/issues/105: the content is not copied through the
    // connection's output, which holds less than it.
    try testing.expectEqual(direct_len, put.response.body_sent);
    try support.peer_h2_read();
    var received: usize = 0;
    var ended = false;
    for (support.peer_events[0..support.peer_events_len]) |peer_event| {
        if (peer_event != .data) continue;
        for (peer_event.data.payload) |octet| try testing.expectEqual('x', octet);
        received += peer_event.data.payload.len;
        ended = peer_event.data.end_stream;
    }
    try testing.expectEqual(direct_len, received);
    // RFC 9113 §8.1: the frame of the last octet ends the request.
    try testing.expect(ended);
}
