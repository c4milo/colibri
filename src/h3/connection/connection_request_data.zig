//! The content and the skipped frames of a request stream (RFC 9114 §4.1, §7.2.1, §9). Part of
//! design §8 step 12, split from `connection_request.zig` in design §8 step 39.
//!
//! A DATA frame's payload goes straight from `quic` into the caller's buffer, and an unknown frame's
//! payload is taken unread. §4.1.2's content-length rule is checked here at each frame's header.
const quic = @import("quic");
const constants = @import("../constants.zig");
const frame = @import("../frame.zig");
const connection_module = @import("connection.zig");
const connection_qlog = @import("connection_qlog.zig");
const connection_request = @import("connection_request.zig");

const Connection = connection_module.Connection;
const Error = connection_module.Error;
const RequestStream = connection_request.RequestStream;
const Step = connection_request.Step;
const StreamId = quic.stream.StreamId;
const QuicConnection = quic.Connection;
const stream_read = quic.connection_stream_read;

/// Takes a DATA frame's header (§7.2.1). Its payload is read next, in `read_data`.
pub fn start_data(connection: *Connection, request: *RequestStream, transport: *QuicConnection, header: frame.Header, header_len: usize) Error!Step {
    connection_qlog.frame_event(connection, .parsed, request.id, .{ .data = header.length });
    request.fin_read = (stream_read.consume(transport, .{ .value = request.id }, header_len) catch unreachable).fin;
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
    const read = stream_read.read(transport, .{ .value = request.id }, window) catch return connection_request.on_closed(connection, request);
    request.data_left -= read.len;
    request.fin_read = read.fin;
    // §7.1: a stream that ended inside a DATA frame is H3_FRAME_ERROR.
    if (read.fin and request.data_left > 0) return connection.fail(transport, constants.protocol.error_frame_error);
    if (read.len == 0) return .wait;
    return .{ .event = .{ .data = .{ .stream_id = request.id, .octets = window[0..read.len] } } };
}

pub fn start_skip(connection: *Connection, transport: *QuicConnection, request: *RequestStream, header: frame.Header, header_len: usize) Step {
    connection_qlog.frame_event(connection, .parsed, request.id, .{ .other = .{ .frame_type = header.frame_type, .payload_len = header.length } });
    request.fin_read = (stream_read.consume(transport, .{ .value = request.id }, header_len) catch unreachable).fin;
    // §9: "Implementations MUST ignore unknown or unsupported values in all extensible protocol
    // elements", so an unknown frame's payload is skipped unread.
    request.skip_left = header.length;
    return .again;
}

/// Takes what has arrived of an unknown frame's payload.
pub fn skip(connection: *Connection, transport: *QuicConnection, request: *RequestStream) Error!Step {
    const id: StreamId = .{ .value = request.id };
    const window = connection.scratch[0..@intCast(@min(request.skip_left, connection.scratch.len))];
    const peeked = stream_read.peek(transport, id, window) catch return connection_request.on_closed(connection, request);
    const taken = stream_read.consume(transport, id, peeked.len) catch unreachable;
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
