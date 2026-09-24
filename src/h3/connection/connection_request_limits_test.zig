//! More tests of `connection_request.zig` and `connection_send.zig`: colibri's limits on what it
//! reads (RFC 9114 §4.2.2, §10.5.1), a response stream that ends early, the refusals of the send
//! side, and GOAWAY sent twice. The harness is `connection_test.zig`'s.
const std = @import("std");
const core = @import("core");
const quic = @import("quic");
const qpack = @import("qpack");
const constants = @import("../constants.zig");
const connection_module = @import("connection.zig");
const harness = @import("connection_test.zig");

const Writer = core.Writer;
const Event = connection_module.Event;
const Line = harness.Line;
const testing = std.testing;

const client = &harness.client;
const server = &harness.server;
const exchange = harness.exchange;
const next = harness.next;

/// A section of one line more than colibri holds: `:method: GET`, static entry 17 (RFC 9204
/// Appendix A), again and again. Test-only.
const lines_past: usize = core.constants.field_count_max + 1;
const static_method_get: u8 = 0xd1;
/// A value past `field_value_len_max`, 127 plus 8873, which a 7-bit prefix and the two octets
/// 0xa9 0x45 carry (RFC 9204 §4.1.1). Its line takes the prefix's two octets, the name's two and
/// the length's three. Test-only.
const long_value_len: usize = 9000;
const long_line_overhead: usize = 7;
const long_frame_len: usize = long_value_len + constants.frame_header_len_max;

comptime {
    std.debug.assert(long_value_len > core.constants.field_value_len_max);
}

fn refused(id: u64, code: u64) Event {
    return .{ .refused = .{ .stream_id = id, .error_code = code } };
}

test "§10.5.1: a HEADERS frame longer than colibri accepts refuses the stream" {
    try harness.pair(.{ .role = .client }, .{ .role = .server });
    // A Length of 0x5000 in four octets, past `frame_length_max`.
    const id = try quic.connection_stream_send.open(&client.transport, .bidirectional);
    try client.send_raw(id.value, &.{ constants.frame_headers, 0x80, 0x00, 0x50, 0x00 }, false);
    try exchange();
    try testing.expectEqual(refused(id.value, constants.error_message_error), (try next(server)).?);
}

test "§4.2.2: a section of more lines than colibri holds refuses the stream" {
    try harness.pair(.{ .role = .client }, .{ .role = .server });
    var octets: [lines_past + 8]u8 = undefined;
    var writer = Writer.init(&octets);
    // The Length is the prefix's two octets and one octet a line, in a two-octet varint.
    const length: u16 = @intCast(lines_past + 2);
    try writer.write_bytes(&.{ constants.frame_headers, 0x40 | @as(u8, @intCast(length >> 8)), @truncate(length), 0x00, 0x00 });
    for (0..lines_past) |_| try writer.write_byte(static_method_get);
    const id = try quic.connection_stream_send.open(&client.transport, .bidirectional);
    try client.send_raw(id.value, writer.written(), false);
    try exchange();
    try testing.expectEqual(refused(id.value, constants.error_message_error), (try next(server)).?);
}

test "RFC 9204 §7.4: a value longer than colibri accepts refuses the stream with QPACK_DECOMPRESSION_FAILED" {
    try harness.pair(.{ .role = .client }, .{ .role = .server });
    var octets: [long_frame_len]u8 = undefined;
    var writer = Writer.init(&octets);
    // A literal line named `x` (RFC 9204 §4.5.6) whose value is `long_value_len` octets, past
    // `field_value_len_max`: the value's length in a 7-bit prefix and two more octets.
    const length: u16 = @intCast(long_value_len + long_line_overhead);
    try writer.write_bytes(&.{ constants.frame_headers, 0x40 | @as(u8, @intCast(length >> 8)), @truncate(length), 0x00, 0x00, 0x21, 'x', 0x7f, 0xa9, 0x45 });
    for (0..long_value_len) |_| try writer.write_byte('a');
    const id = try quic.connection_stream_send.open(&client.transport, .bidirectional);
    try client.send_raw(id.value, writer.written(), false);
    try exchange();
    try testing.expectEqual(refused(id.value, qpack.constants.error_decompression_failed), (try next(server)).?);
}

test "§4.1.2: a response stream that ends after an interim response is malformed at a client" {
    try harness.pair(.{ .role = .client }, .{ .role = .server });
    const id = try harness.request(&harness.get_lines, "");
    try exchange();
    var writer = server.writer_for(id);
    try server.h3.write_response(&server.transport, id, try harness.section_of(&harness.test_section, &.{.{ ":status", "103" }}), &.{}, &writer);
    try server.commit(id, writer.written(), true);
    try exchange();
    try testing.expectEqual(103, (try next(client)).?.response.response.status.code);
    try testing.expectEqual(refused(id, constants.error_message_error), (try next(client)).?);
}

test "§7.1: a DATA frame cut short after the server's side of the stream has finished" {
    try harness.pair(.{ .role = .client }, .{ .role = .server });
    const section = try harness.section_of(&harness.test_section, &harness.get_lines);
    var writer = client.writer_for(0);
    const id = try client.h3.write_request(&client.transport, section, &.{}, &writer);
    try client.commit(id, writer.written(), false);
    try exchange();
    _ = (try next(server)).?.request;
    // The server answers in full before the request's content arrives (§4.1 permits it).
    try harness.respond(id, &harness.ok_lines, "");
    try exchange();
    // A DATA frame whose header promises five octets, and then the stream's end.
    try client.send_raw(id, &.{ constants.frame_data, 0x05 }, true);
    try exchange();
    try testing.expectError(error.ConnectionFailed, next(server));
    try testing.expectEqual(constants.error_frame_error, server.h3.failure.?);
}

test "§4.1.2: colibri sends no malformed request, and opens no stream for it" {
    try harness.pair(.{ .role = .client }, .{ .role = .server });
    const no_method = [_]Line{ .{ ":scheme", "https" }, .{ ":path", "/" }, .{ ":authority", "a" } };
    try testing.expectError(error.MessageInvalid, harness.request(&no_method, ""));
    try testing.expectEqual(0, client.transport.streams.next_index[0]);
}

test "RFC 9000 §4.6: colibri opens no request stream past the peer's limit" {
    try harness.pair(.{ .role = .client }, .{ .role = .server });
    client.transport.streams.local_limit[@intFromEnum(quic.stream.Directionality.bidirectional)] = .init(0);
    var octets: [harness.kept_len]u8 = undefined;
    var writer = Writer.init(&octets);
    const section = try harness.section_of(&harness.test_section, &harness.get_lines);
    try testing.expectError(error.StreamsExhausted, client.h3.write_request(&client.transport, section, &.{}, &writer));
    try testing.expectEqual(0, writer.written().len);
}

test "a HEADERS frame that may not fit the caller's buffer is not written, nor its stream opened" {
    try harness.pair(.{ .role = .client }, .{ .role = .server });
    var small: [8]u8 = undefined;
    var writer = Writer.init(&small);
    const section = try harness.section_of(&harness.test_section, &harness.get_lines);
    try testing.expectError(error.NoSpaceLeft, client.h3.write_request(&client.transport, section, &.{}, &writer));
    try testing.expectEqual(0, writer.written().len);
    try testing.expectEqual(0, client.transport.streams.next_index[0]);
}

test "§5.2: a second GOAWAY names no higher stream than the first" {
    try harness.pair(.{ .role = .client }, .{ .role = .server });
    try server.h3.shutdown(&server.transport);
    // A request that crosses the GOAWAY is rejected, and moves the server past its stream.
    const late = try harness.request(&harness.get_lines, "");
    try exchange();
    try testing.expectEqual(null, try next(server));
    try server.h3.shutdown(&server.transport);
    try exchange();
    try testing.expectEqual(Event{ .goaway = 0 }, (try next(client)).?);
    try testing.expectEqual(Event{ .goaway = 0 }, (try next(client)).?);
    // §4.1.1: the rejected request's stream is reset with H3_REQUEST_REJECTED.
    try testing.expectEqual(Event{ .reset = .{ .stream_id = late, .error_code = constants.error_request_rejected } }, (try next(client)).?);
    try testing.expectEqual(null, try next(client));
}
