//! The content and the skipped frames of a request stream (RFC 9114 §4.1, §7.2.1, §9). Part of
//! design §8 step 12, split from `connection_request.zig` in design §8 step 39.
//!
//! A DATA frame's payload goes straight from `quic` into the caller's buffer, and an unknown
//! frame's payload is taken unread. §4.1.2's content-length rule is checked here at each frame's
//! header.
//!
//! A stream opened with `hold_data` leaves its payload in `quic`, so the peer gets no credit for it
//! (RFC 9000 §4.1). The caller copies it with `peek_data` into its own memory, and `release_data`
//! takes it once the caller has used it (design §8 step 39d).
const std = @import("std");
const assert = std.debug.assert;
const quic = @import("quic");
const constants = @import("../constants.zig");
const frame = @import("../frame.zig");
const connection_module = @import("connection.zig");
const connection_qlog = @import("connection_qlog.zig");
const connection_request = @import("connection_request.zig");

const Connection = connection_module.Connection;
const Error = connection_module.Connection.Error;
const RequestStream = connection_request.RequestStream;
const Step = connection_request.Step;
const StreamId = quic.StreamId;
const QuicConnection = quic.Connection;

/// Takes a DATA frame's header (§7.2.1). Its payload is read next, in `read_data`.
pub fn start_data(connection: *Connection, request: *RequestStream, transport: *QuicConnection, header: frame.Header, header_len: usize) Error!Step {
    connection_qlog.frame_event(connection, .parsed, request.id, .{ .data = header.length });
    request.fin_read = (quic.Connection.consume(transport, .{ .value = request.id }, header_len) catch unreachable).fin;
    request.data_left = header.length;
    request.content_received +|= header.length;
    // §4.1.2: content past the content-length is malformed, which the frame's header shows.
    if (!request.no_content) {
        if (request.content_length) |expected| {
            if (request.content_received > expected) return connection_request.refuse(connection, transport, request, constants.protocol.error_message_error);
        }
    }
    // §7.1: the stream ended inside the DATA frame.
    if (request.fin_read and request.data_left > 0) return connection.fail(transport, constants.protocol.error_frame_error);
    return .again;
}

/// Hands the caller what has arrived of the current DATA frame's payload (§7.2.1).
pub fn read_data(connection: *Connection, transport: *QuicConnection, request: *RequestStream, body: []u8) Error!Step {
    const window = body[0..@intCast(@min(body.len, request.data_left))];
    const read = quic.Connection.read(transport, .{ .value = request.id }, window) catch return connection_request.on_closed(connection, request);
    request.data_left -= read.len;
    request.fin_read = read.fin;
    // §7.1: a stream that ended inside a DATA frame is H3_FRAME_ERROR.
    if (read.fin and request.data_left > 0) return connection.fail(transport, constants.protocol.error_frame_error);
    if (read.len == 0) return .wait;
    return .{ .event = .{ .data = .{ .stream_id = request.id, .octets = window[0..read.len] } } };
}

/// Reports what has arrived of the current DATA frame's payload, and copies none of it: the octets
/// stay unread in `quic` until `release_data` (RFC 9000 §4.1). The caller copies them with
/// `peek_data` straight into its own memory (decision 153 ruling 12).
pub fn hold_arrived(connection: *Connection, transport: *QuicConnection, request: *RequestStream) Error!Step {
    assert(request.hold_data and request.held_len == 0);
    const found = arrived(transport, .{ .value = request.id }) orelse return connection_request.on_closed(connection, request);
    // §7.1: a stream that ended inside a DATA frame is H3_FRAME_ERROR.
    if (found.fin and found.len < request.data_left) return connection.fail(transport, constants.protocol.error_frame_error);
    const len = @min(found.len, request.data_left);
    if (len == 0) return .wait;
    request.held_len = len;
    return .{ .event = .{ .data_available = .{ .stream_id = request.id, .len = len } } };
}

/// What `peek` would copy of stream `id` with no bound on its output, measured in `quic`'s
/// receive pool without a copy, or null when the stream is closed. `advance` reports a reset
/// before the stream gets here.
fn arrived(transport: *QuicConnection, id: StreamId) ?quic.Connection.StreamRead {
    const stream = switch (transport.streams.lookup(id)) {
        .live => |stream| stream,
        .closed, .unopened => return null,
    };
    const consumed = stream.receive_flow.consumed;
    // Design §8 step 29d.9: no octet past `consumed` arrived, so the pool holds none.
    const end = if (stream.receive_flow.used > consumed) stream.incoming.contiguous_end(transport.receive_storage.?, id.value, consumed) else consumed;
    assert(end >= consumed);
    const final_size = stream.receiving.final_size orelse return .{ .len = @intCast(end - consumed), .fin = false };
    assert(end <= final_size);
    return .{ .len = @intCast(end - consumed), .fin = end == final_size };
}

/// Copies the content the last `data_available` event on `stream_id` reported into `output`, as
/// much as it holds, and returns the octets copied. They stay unread in `quic` until
/// `release_data` takes them. It copies none on a stream that holds none: one reset, refused or
/// closed since the event.
pub fn peek_data(connection: *Connection, transport: *QuicConnection, stream_id: u64, output: []u8) usize {
    const request = connection.requests.find(stream_id) orelse return 0;
    if (request.held_len == 0) return 0;
    assert(request.hold_data);
    const id: StreamId = .{ .value = stream_id };
    // RFC 9000 §19.4: a reset stream delivers no octets, and a peek here would say the reset
    // first and lose it.
    if (quic.Connection.reset_code(transport, id) != null) return 0;
    const window = output[0..@intCast(@min(output.len, request.held_len))];
    // `hold_arrived` found the stream live, and only a reset or a close ends it since.
    const peeked = quic.Connection.peek(transport, id, window) catch return 0;
    // `hold_arrived` measured every held octet as arrived.
    assert(peeked.len == window.len);
    return peeked.len;
}

/// Takes the first `len` octets of the content a `data_available` event reported on `stream_id`,
/// which gives the peer credit for them (RFC 9000 §4.1). It does nothing on a stream that holds
/// none: one reset, refused or closed since the event.
pub fn release_data(connection: *Connection, transport: *QuicConnection, stream_id: u64, len: u64) void {
    const request = connection.requests.find(stream_id) orelse return;
    if (request.held_len == 0) return;
    assert(len <= request.held_len);
    request.held_len = 0;
    const id: StreamId = .{ .value = stream_id };
    // The next read reports the peer's reset, which a take here would say first and lose.
    if (quic.Connection.reset_code(transport, id) != null) return;
    const taken = quic.Connection.consume(transport, id, @intCast(len)) catch return;
    request.data_left -= len;
    request.fin_read = taken.fin;
    // `peek_data` refused a stream that ended inside the DATA frame.
    assert(!taken.fin or request.data_left == 0);
}

pub fn start_skip(connection: *Connection, transport: *QuicConnection, request: *RequestStream, header: frame.Header, header_len: usize) Step {
    connection_qlog.frame_event(connection, .parsed, request.id, .{ .other = .{ .frame_type = header.frame_type, .payload_len = header.length } });
    request.fin_read = (quic.Connection.consume(transport, .{ .value = request.id }, header_len) catch unreachable).fin;
    // §9: "Implementations MUST ignore unknown or unsupported values in all extensible protocol
    // elements", so an unknown frame's payload is skipped unread.
    request.skip_left = header.length;
    return .again;
}

/// Takes what has arrived of an unknown frame's payload.
pub fn skip(connection: *Connection, transport: *QuicConnection, request: *RequestStream) Error!Step {
    const id: StreamId = .{ .value = request.id };
    const window = connection.scratch[0..@intCast(@min(request.skip_left, connection.scratch.len))];
    const peeked = quic.Connection.peek(transport, id, window) catch return connection_request.on_closed(connection, request);
    const taken = quic.Connection.consume(transport, id, peeked.len) catch unreachable;
    request.skip_left -= peeked.len;
    request.fin_read = taken.fin;
    // §7.1: a stream that ended inside a frame is H3_FRAME_ERROR.
    if (taken.fin and request.skip_left > 0) return connection.fail(transport, constants.protocol.error_frame_error);
    if (peeked.len == 0) return .wait;
    return .again;
}

pub fn content_length_matches(request: *const RequestStream) bool {
    if (request.no_content) return true;
    const expected = request.content_length orelse return true;
    return expected == request.content_received;
}

const testing = std.testing;
const harness = @import("connection_test.zig");
const client = &harness.client;
const server = &harness.server;
const exchange = harness.exchange;
const next = harness.next;

/// The content the server sends on a held stream: more than half the stream's window, so a
/// release of all of it owes the peer a MAX_STREAM_DATA (RFC 9000 §4.1). Test-only.
const held_content_len: usize = 40000;
threadlocal var held_content: [held_content_len]u8 = undefined;

/// Opens a GET whose stream holds its content, and has the server answer it with `content` and no
/// FIN, so the stream stays open. Returns the stream's ID once the client has read the response's
/// head. Test-only.
fn held_exchange(content: []const u8) !u64 {
    // Each octet differs from the one before it, so a slice taken from the wrong offset differs.
    for (&held_content, 0..) |*octet, index| octet.* = @truncate(index);
    try harness.pair(.{ .role = .client }, .{ .role = .server });
    const section = try harness.section_of(&harness.test_section, &harness.get_lines);
    var writer = client.writer_for(0);
    const id = try client.h3.write_request(&client.transport, section, &.{}, true, &writer, harness.test_now_ns);
    try client.commit(id, writer.written(), true);
    try exchange();
    // Decision 116 as amended: a head the stream ended with reports the end itself.
    try testing.expect((try next(server)).?.request.end);
    var answer = server.writer_for(id);
    try server.h3.write_response(&server.transport, id, try harness.section_of(&harness.test_section, &harness.ok_lines), &.{}, &answer, harness.test_now_ns);
    try server.h3.write_data_header(id, content.len, &answer, harness.test_now_ns);
    try answer.write_bytes(content);
    try server.commit(id, answer.written(), false);
    try exchange();
    _ = (try next(client)).?.response;
    return id;
}

/// The octets of stream `id` that arrived and the client has not taken. Credit is measured from
/// what it took (RFC 9000 §4.1).
fn unread(id: u64) u64 {
    const flow = &client.transport.streams.lookup(.{ .value = id }).live.receive_flow;
    return flow.used - flow.consumed;
}

/// Whether the client owes the peer a MAX_STREAM_DATA on stream `id` (RFC 9000 §19.10).
fn owes_stream_credit(id: u64) bool {
    return client.transport.streams.lookup(.{ .value = id }).live.receive_flow.owes_credit();
}

/// Where the tests copy held content with `peek_data`. Test-only.
threadlocal var copied: [held_content_len]u8 = undefined;

/// The octet `receive`'s buffer is filled with, which no held stream may change. Test-only.
const untouched_octet: u8 = 0xa5;

test "RFC 9000 §4.1: a held stream gives no credit before release_data, and owes a MAX_STREAM_DATA after it" {
    const id = try held_exchange(&held_content);
    // Decision 153 ruling 12: the held content is copied once, by `peek_data`, and never into the
    // buffer `receive` was given.
    @memset(&client.body, untouched_octet);
    const held = (try next(client)).?.data_available;
    try testing.expectEqual(id, held.stream_id);
    try testing.expectEqual(held_content_len, held.len);
    try testing.expect(std.mem.allEqual(u8, &client.body, untouched_octet));
    try testing.expectEqual(held_content_len, client.h3.peek_data(&client.transport, id, &copied));
    try testing.expectEqualSlices(u8, &held_content, &copied);
    // A smaller output takes the first octets.
    try testing.expectEqual(10, client.h3.peek_data(&client.transport, id, copied[0..10]));
    // The stream reads nothing more while the caller holds its content.
    try testing.expectEqual(null, try next(client));
    try testing.expectEqual(held_content_len, unread(id));
    try testing.expect(!owes_stream_credit(id));
    client.h3.release_data(&client.transport, id, held.len);
    try testing.expectEqual(0, unread(id));
    try testing.expect(owes_stream_credit(id));
    try testing.expectEqual(null, try next(client));
}

test "a release of part of the content reports the rest next, from where the release stopped" {
    const id = try held_exchange(&held_content);
    const part: usize = 1000;
    _ = (try next(client)).?.data_available;
    client.h3.release_data(&client.transport, id, part);
    const rest = (try next(client)).?.data_available;
    try testing.expectEqual(held_content_len - part, rest.len);
    const len = client.h3.peek_data(&client.transport, id, &copied);
    try testing.expectEqualSlices(u8, held_content[part..], copied[0..len]);
    client.h3.release_data(&client.transport, id, rest.len);
    try testing.expectEqual(0, unread(id));
}

test "RFC 9000 §19.4: a reset while content is held is reported once the content is released" {
    const id = try held_exchange(held_content[0..10]);
    _ = (try next(client)).?.data_available;
    try quic.Connection.reset_stream(&server.transport, .{ .value = id }, constants.protocol.error_internal);
    try exchange();
    try testing.expectEqual(null, try next(client));
    // The reset stream delivers no octets, and a peek keeps the reset to report.
    try testing.expectEqual(0, client.h3.peek_data(&client.transport, id, &copied));
    client.h3.release_data(&client.transport, id, 10);
    const reset = (try next(client)).?.reset;
    try testing.expectEqual(constants.protocol.error_internal, reset.error_code);
    // The stream is gone, so a late release does nothing.
    client.h3.release_data(&client.transport, id, 10);
}

test "§7.1: a held stream that ends inside a DATA frame is H3_FRAME_ERROR" {
    try harness.pair(.{ .role = .client }, .{ .role = .server });
    const section = try harness.section_of(&harness.test_section, &harness.get_lines);
    var writer = client.writer_for(0);
    const id = try client.h3.write_request(&client.transport, section, &.{}, true, &writer, harness.test_now_ns);
    try client.commit(id, writer.written(), true);
    try exchange();
    var answer = server.writer_for(id);
    try server.h3.write_response(&server.transport, id, try harness.section_of(&harness.test_section, &harness.ok_lines), &.{}, &answer, harness.test_now_ns);
    // A DATA frame whose header promises five octets, two of them, and then the stream's end.
    try answer.write_bytes(&.{ constants.protocol.frame_data, 0x05, 'a', 'b' });
    try server.commit(id, answer.written(), true);
    try exchange();
    _ = (try next(client)).?.response;
    try testing.expectError(error.ConnectionFailed, next(client));
    try testing.expectEqual(constants.protocol.error_frame_error, client.h3.failure.?);
}

test "§4.1.1: a cancel while content is held drops the hold, and the stream's slot goes once it ends" {
    const id = try held_exchange(held_content[0..10]);
    _ = (try next(client)).?.data_available;
    client.h3.cancel(&client.transport, id, constants.protocol.error_request_cancelled);
    // RFC 9000 §3.5: the server answers STOP_SENDING with a RESET_STREAM.
    try exchange();
    try exchange();
    try testing.expectEqual(null, try next(client));
    try testing.expectEqual(null, client.h3.requests.find(id));
    // The caller's release after the cancel finds nothing to take.
    client.h3.release_data(&client.transport, id, 10);
}

/// Two DATA frames of five octets each, as the server's content. Test-only.
const two_frames = [_]u8{ constants.protocol.frame_data, frame_payload_len } ++ "hello" ++ [_]u8{ constants.protocol.frame_data, frame_payload_len } ++ "world";
const frame_payload_len: u8 = 5;

/// Has the client's QUIC receive `two_frames[from..to]` on stream `id`, after the `head_len`
/// octets of the response's head, in a STREAM frame of its own (RFC 9000 §19.8). Test-only.
fn arrive(id: u64, head_len: usize, from: usize, to: usize) !void {
    try quic.connection_stream_frames.apply(&client.transport, .{ .stream = .{
        .stream_id = id,
        .offset = head_len + from,
        .data = two_frames[from..to],
        .fin = false,
        .has_length = true,
    } });
}

test "RFC 9000 §2.2: a held stream reports its content up to the first octet missing, and no further than its DATA frame" {
    try harness.pair(.{ .role = .client }, .{ .role = .server });
    var writer = client.writer_for(0);
    const id = try client.h3.write_request(&client.transport, try harness.section_of(&harness.test_section, &harness.get_lines), &.{}, true, &writer, harness.test_now_ns);
    try client.commit(id, writer.written(), true);
    try exchange();
    try testing.expect((try next(server)).?.request.end);
    var answer = server.writer_for(id);
    try server.h3.write_response(&server.transport, id, try harness.section_of(&harness.test_section, &harness.ok_lines), &.{}, &answer, harness.test_now_ns);
    try server.commit(id, answer.written(), false);
    try exchange();
    _ = (try next(client)).?.response;
    const head_len = answer.written().len;
    // The first frame's header alone reports no content.
    try arrive(id, head_len, 0, 2);
    try testing.expectEqual(null, try next(client));
    // The first frame's header and "he" arrive, then "world"'s frame, and "ll" is missing.
    try arrive(id, head_len, 0, 4);
    try arrive(id, head_len, 6, two_frames.len);
    try testing.expectEqual(2, (try next(client)).?.data_available.len);
    try testing.expectEqual(2, client.h3.peek_data(&client.transport, id, &copied));
    try testing.expectEqualStrings("he", copied[0..2]);
    client.h3.release_data(&client.transport, id, 2);
    try arrive(id, head_len, 4, 6);
    // The rest of the first frame, and not the second frame's header.
    try testing.expectEqual(3, (try next(client)).?.data_available.len);
    try testing.expectEqual(3, client.h3.peek_data(&client.transport, id, &copied));
    try testing.expectEqualStrings("llo", copied[0..3]);
    client.h3.release_data(&client.transport, id, 3);
    try testing.expectEqual(5, (try next(client)).?.data_available.len);
    try testing.expectEqual(5, client.h3.peek_data(&client.transport, id, &copied));
    try testing.expectEqualStrings("world", copied[0..5]);
}
