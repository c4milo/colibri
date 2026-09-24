//! The tests of `connection_request.zig` and `connection_send.zig`: the rules RFC 9114 §4.1 and
//! §7 set for request streams, each broken by a peer that writes raw frames. The harness is
//! `connection_test.zig`'s.
const std = @import("std");
const core = @import("core");
const http = @import("http");
const qpack = @import("qpack");
const quic = @import("quic");
const constants = @import("../constants.zig");
const frame_write = @import("../frame_write.zig");
const connection_module = @import("connection.zig");
const harness = @import("connection_test.zig");

const Writer = core.Writer;
const FieldSection = http.FieldSection;
const Event = connection_module.Event;
const testing = std.testing;

const client = &harness.client;
const server = &harness.server;
const exchange = harness.exchange;
const next = harness.next;

const Line = harness.Line;

/// Room for the frames a test writes on one stream. Test-only.
const frames_len_max: usize = 512;

/// A static-table-only encoder that writes whatever section a test gives it. Test-only.
var raw_encoder: qpack.encoder.Encoder = undefined;
var raw_section: FieldSection = undefined;
var raw_octets: [constants.frame_length_max]u8 = undefined;

/// Writes a HEADERS frame carrying `lines`, unchecked, into `output`.
pub fn headers_frame(output: *Writer, lines: []const Line) !void {
    raw_encoder.init(.never);
    var encoded = Writer.init(&raw_octets);
    var no_stream = Writer.init(raw_octets[0..0]);
    try raw_encoder.write_section(0, &encoded, &no_stream, try harness.section_of(&raw_section, lines), &.{});
    try frame_write.write_header(output, constants.frame_headers, encoded.written().len);
    try output.write_bytes(encoded.written());
}

/// Opens the client's next request stream, writes `write`'s frames on it, and ends it when `fin`.
fn raw_request(frames: []const u8, fin: bool) !u64 {
    const id = try quic.connection_stream_send.open(&client.transport, .bidirectional);
    try client.send_raw(id.value, frames, fin);
    return id.value;
}

/// The client's request stream carrying a GET's HEADERS frame and then `after`.
fn get_then(after: []const u8, fin: bool) !u64 {
    var octets: [frames_len_max]u8 = undefined;
    var writer = Writer.init(&octets);
    try headers_frame(&writer, &harness.get_lines);
    try writer.write_bytes(after);
    return raw_request(writer.written(), fin);
}

fn expect_failure(endpoint: *harness.Endpoint, code: u64) !void {
    try testing.expectError(error.ConnectionFailed, next(endpoint));
    try testing.expectEqual(code, endpoint.h3.failure.?);
    try testing.expectEqual(code, endpoint.transport.pending_close.?.error_code);
}

test "§4.1: a DATA frame before any HEADERS frame is H3_FRAME_UNEXPECTED" {
    try harness.pair(.{ .role = .client }, .{ .role = .server });
    _ = try raw_request(&.{ 0x00, 0x01, 'x' }, true);
    try exchange();
    try expect_failure(server, constants.error_frame_unexpected);
}

test "§4.1: a HEADERS or DATA frame after the trailers is H3_FRAME_UNEXPECTED" {
    for ([_]u8{ constants.frame_headers, constants.frame_data }) |frame_type| {
        try harness.pair(.{ .role = .client }, .{ .role = .server });
        var octets: [256]u8 = undefined;
        var writer = Writer.init(&octets);
        try headers_frame(&writer, &.{.{ "x-trailer", "1" }});
        try writer.write_bytes(&.{ frame_type, 0x00 });
        const id = try get_then(writer.written(), true);
        try exchange();
        _ = (try next(server)).?.request;
        try testing.expectEqual(Event{ .trailers = id }, (try next(server)).?);
        try expect_failure(server, constants.error_frame_unexpected);
    }
}

test "§7.2.4, §7.2.8: SETTINGS or an HTTP/2 frame type on a request stream is H3_FRAME_UNEXPECTED" {
    for ([_]u8{ constants.frame_settings, 0x02 }) |frame_type| {
        try harness.pair(.{ .role = .client }, .{ .role = .server });
        _ = try raw_request(&.{ frame_type, 0x00 }, false);
        try exchange();
        try expect_failure(server, constants.error_frame_unexpected);
    }
}

test "§7.2.5: a PUSH_PROMISE is H3_FRAME_UNEXPECTED at a server and H3_ID_ERROR at a client" {
    const push_promise = [_]u8{ constants.frame_push_promise, 0x03, 0x00, 0x00, 0x00 };
    try harness.pair(.{ .role = .client }, .{ .role = .server });
    _ = try get_then(&push_promise, false);
    try exchange();
    _ = (try next(server)).?.request;
    try expect_failure(server, constants.error_frame_unexpected);
    // colibri's client allowed no push ID (decision 17).
    try harness.pair(.{ .role = .client }, .{ .role = .server });
    const id = try harness.request(&harness.get_lines, "");
    try exchange();
    try server.send_raw(id, &push_promise, false);
    try exchange();
    try expect_failure(client, constants.error_id_error);
}

test "§4.1.2: a malformed request refuses its stream with H3_MESSAGE_ERROR, and nothing else" {
    try harness.pair(.{ .role = .client }, .{ .role = .server });
    var octets: [256]u8 = undefined;
    var writer = Writer.init(&octets);
    // §4.2: an uppercase field name is malformed.
    try headers_frame(&writer, &.{ .{ ":method", "GET" }, .{ ":scheme", "https" }, .{ ":path", "/" }, .{ ":authority", "a" }, .{ "X-Upper", "1" } });
    // The request stream stays open, so the server has something to ask the client to stop.
    const id = try raw_request(writer.written(), false);
    try exchange();
    try testing.expectEqual(Event{ .refused = .{ .stream_id = id, .error_code = constants.error_message_error } }, (try next(server)).?);
    try testing.expectEqual(null, try next(server));
    // The server reset its side and asked the client to stop, both with H3_MESSAGE_ERROR.
    const refused = server.transport.streams.lookup(.{ .value = id }).live;
    try testing.expectEqual(constants.error_message_error, refused.reset_error_code);
    try testing.expect(refused.stop_sending.owed);
    try testing.expectEqual(constants.error_message_error, refused.stop_error_code);
    // Octets the client sends before it hears of the refusal are taken and dropped, so the
    // server's stream finishes, and the connection goes on with the next request.
    try client.send_raw(id, "more", true);
    try exchange();
    try testing.expectEqual(null, try next(server));
    try testing.expect(server.transport.streams.lookup(.{ .value = id }) != .live);
    try testing.expectEqual(constants.error_message_error, quic.connection_stream_read.reset_code(&client.transport, .{ .value = id }).?);
    const again = try harness.request(&harness.get_lines, "");
    try exchange();
    try testing.expectEqual(again, (try next(server)).?.request.stream_id);
}

/// The content-length `five_octets_then` sends. Test-only.
const content_length_five: u64 = 5;

/// A request saying content-length 5, followed by `after`, ended. Its request event is read.
fn five_octets_then(after: []const u8) !u64 {
    try harness.pair(.{ .role = .client }, .{ .role = .server });
    var octets: [frames_len_max]u8 = undefined;
    var writer = Writer.init(&octets);
    try headers_frame(&writer, &(harness.get_lines ++ [_]Line{.{ "content-length", "5" }}));
    try writer.write_bytes(after);
    const id = try raw_request(writer.written(), true);
    try exchange();
    try testing.expectEqual(content_length_five, (try next(server)).?.request.request.content_length.?);
    return id;
}

test "§4.1.2: content shorter than its content-length refuses the stream at its end" {
    const id = try five_octets_then(&.{ 0x00, 0x03, 'a', 'b', 'c' });
    try testing.expectEqualStrings("abc", (try next(server)).?.data.octets);
    try testing.expectEqual(Event{ .refused = .{ .stream_id = id, .error_code = constants.error_message_error } }, (try next(server)).?);
}

test "§4.1.2: content longer than its content-length refuses the stream at the DATA frame's header" {
    const id = try five_octets_then(&.{ 0x00, 0x06, 'a', 'b', 'c', 'd', 'e', 'f' });
    try testing.expectEqual(Event{ .refused = .{ .stream_id = id, .error_code = constants.error_message_error } }, (try next(server)).?);
}

test "§4.1.2: content short of its content-length when the trailers arrive refuses the stream" {
    var octets: [frames_len_max]u8 = undefined;
    var writer = Writer.init(&octets);
    try writer.write_bytes(&.{ 0x00, 0x03, 'a', 'b', 'c' });
    try headers_frame(&writer, &.{.{ "x-trailer", "1" }});
    const id = try five_octets_then(writer.written());
    _ = (try next(server)).?.data;
    try testing.expectEqual(Event{ .refused = .{ .stream_id = id, .error_code = constants.error_message_error } }, (try next(server)).?);
}

test "§4.1: a request stream that ends before its header section is H3_REQUEST_INCOMPLETE" {
    try harness.pair(.{ .role = .client }, .{ .role = .server });
    const id = try raw_request(&.{}, true);
    try exchange();
    try testing.expectEqual(Event{ .refused = .{ .stream_id = id, .error_code = constants.error_request_incomplete } }, (try next(server)).?);
}

test "§7.1: a stream that ends inside a frame is H3_FRAME_ERROR" {
    // Inside a frame header, right after a DATA frame's header, inside its payload, inside an
    // unknown frame's payload, and inside a HEADERS frame's.
    for ([_][]const u8{ &.{0x00}, &.{ 0x00, 0x05 }, &.{ 0x00, 0x05, 'a' }, &.{ 0x21, 0x05, 'a' }, &.{ 0x01, 0x05, 0x00 } }) |cut| {
        try harness.pair(.{ .role = .client }, .{ .role = .server });
        _ = try get_then(cut, true);
        try exchange();
        _ = (try next(server)).?.request;
        var event = next(server);
        if (event) |held| {
            try testing.expect(held.? == .data);
            event = next(server);
        } else |_| {}
        try testing.expectError(error.ConnectionFailed, event);
        try testing.expectEqual(constants.error_frame_error, server.h3.failure.?);
    }
}

test "§9: a frame of unknown type on a request stream is skipped" {
    try harness.pair(.{ .role = .client }, .{ .role = .server });
    // §7.2.8's reserved type 0x21, with a payload, before the content and inside it.
    const reserved = [_]u8{ 0x21, 0x03, 'z', 'z', 'z' };
    const id = try get_then(&(reserved ++ [_]u8{ 0x00, 0x02, 'h', 'i' } ++ reserved), true);
    try exchange();
    _ = (try next(server)).?.request;
    try testing.expectEqualStrings("hi", (try next(server)).?.data.octets);
    try testing.expectEqual(Event{ .end = id }, (try next(server)).?);
}

test "§4.1: interim responses come before the final one, and carry no content" {
    try harness.pair(.{ .role = .client }, .{ .role = .server });
    const id = try harness.request(&harness.get_lines, "");
    try exchange();
    var writer = server.writer_for(id);
    try server.h3.write_response(&server.transport, id, try harness.section_of(&harness.test_section, &.{.{ ":status", "103" }}), &.{}, &writer);
    try server.commit(id, writer.written(), false);
    try harness.respond(id, &harness.ok_lines, "ok");
    try exchange();
    try testing.expectEqual(103, (try next(client)).?.response.response.status.code);
    try testing.expectEqual(200, (try next(client)).?.response.response.status.code);
    try testing.expectEqualStrings("ok", (try next(client)).?.data.octets);
    try testing.expectEqual(Event{ .end = id }, (try next(client)).?);
}

test "§4.1.2: a response to HEAD carries a content-length and no content" {
    try harness.pair(.{ .role = .client }, .{ .role = .server });
    const head = [_]Line{ .{ ":method", "HEAD" }, .{ ":scheme", "https" }, .{ ":path", "/" }, .{ ":authority", "a" } };
    const id = try harness.request(&head, "");
    try exchange();
    try harness.respond(id, &.{ .{ ":status", "200" }, .{ "content-length", "1000" } }, "");
    try exchange();
    _ = (try next(client)).?.response;
    try testing.expectEqual(Event{ .end = id }, (try next(client)).?);
}

test {
    _ = @import("connection_request_limits_test.zig");
}

test "§4.1.1: a request the client cancels reaches the server as a reset with its code" {
    try harness.pair(.{ .role = .client }, .{ .role = .server });
    const lines = harness.get_lines;
    const section = try harness.section_of(&harness.test_section, &lines);
    var writer = client.writer_for(0);
    const id = try client.h3.write_request(&client.transport, section, &.{}, &writer);
    try client.commit(id, writer.written(), false);
    try exchange();
    _ = (try next(server)).?.request;
    client.h3.cancel(&client.transport, id, constants.error_request_cancelled);
    try exchange();
    try testing.expectEqual(Event{ .reset = .{ .stream_id = id, .error_code = constants.error_request_cancelled } }, (try next(server)).?);
    try testing.expectEqual(null, try next(server));
}

test "§5.2: after colibri's GOAWAY a server rejects later requests, and the client opens none" {
    try harness.pair(.{ .role = .client }, .{ .role = .server });
    const first = try harness.request(&harness.get_lines, "");
    try exchange();
    _ = (try next(server)).?.request;
    try server.h3.shutdown(&server.transport);
    // A request already on its way names a stream the GOAWAY did not take.
    const late = try harness.request(&harness.get_lines, "");
    try exchange();
    try testing.expectEqual(Event{ .end = first }, (try next(server)).?);
    try testing.expectEqual(null, try next(server));
    try exchange();
    try testing.expectEqual(constants.error_request_rejected, quic.connection_stream_read.reset_code(&client.transport, .{ .value = late }).?);
    try testing.expectEqual(Event{ .goaway = late }, (try next(client)).?);
    try testing.expectError(error.GoawayReceived, harness.request(&harness.get_lines, ""));
}

test "§4.2.2: a section past the peer's SETTINGS_MAX_FIELD_SECTION_SIZE is not sent" {
    try harness.pair(.{ .role = .client }, .{ .role = .server });
    server.h3.peer_settings.?.max_field_section_size = 64;
    const id = try harness.request(&harness.get_lines, "");
    try exchange();
    var writer = server.writer_for(id);
    const long = [_]Line{ .{ ":status", "200" }, .{ "x-long", "a" ** 64 } };
    try testing.expectError(error.FieldSectionTooLarge, server.h3.write_response(&server.transport, id, try harness.section_of(&harness.test_section, &long), &.{}, &writer));
    try testing.expectEqual(0, writer.written().len);
}
