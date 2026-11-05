//! The head of a message on a request stream (RFC 9114 §4.1): a request at a server, or a response
//! at a client. Split from `connection_request.zig` for length.
const http = @import("http");
const quic = @import("quic");
const message = @import("../message/message.zig");
const connection_module = @import("connection.zig");
const connection_request = @import("connection_request.zig");

const Connection = connection_module.Connection;
const Error = connection_module.Error;
const QuicConnection = quic.Connection;
const RequestStream = connection_request.RequestStream;
const Step = connection_request.Step;
const refuse = connection_request.refuse;

/// A request's header section, at a server. A head that the stream ended with is the whole
/// request: it is reported with `end`, and no `end` event follows (decision 116 as amended).
pub fn on_request(connection: *Connection, transport: *QuicConnection, request: *RequestStream) Error!Step {
    const found = message.validate_request(&connection.section) catch |reason| return refuse(connection, transport, request, message.verdict(reason));
    request.content_length = found.content_length;
    request.phase = .content;
    if (!request.fin_read) return .{ .event = .{ .request = .{ .stream_id = request.id, .request = found, .end = false } } };
    // RFC 9114 §4.1.2: the end's checks run at once, and a refusal comes in place of the request.
    const ended = try connection_request.on_end(connection, transport, request);
    if (ended.event != .end) return ended;
    return .{ .event = .{ .request = .{ .stream_id = ended.event.end, .request = found, .end = true } } };
}

/// A response's header section, at a client: an interim one, or the final one.
pub fn on_response(connection: *Connection, transport: *QuicConnection, request: *RequestStream) Error!Step {
    const found = message.validate_response(&connection.section) catch |reason|
        return refuse(connection, transport, request, message.verdict(reason));
    // §4.1: interim responses precede the final one and carry no content, so the stream stays
    // at its head.
    if (!found.status.is_interim()) {
        request.phase = .content;
        request.content_length = found.content_length;
        // RFC 9110 §15: any three-digit status may arrive, so it is compared, never converted.
        const code = found.status.code;
        // §4.1.2: "A response that is defined as never having content, even when a
        // Content-Length is present, can have a non-zero Content-Length header field", which
        // RFC 9110 §6.4.1 says of a response to HEAD and of 204 and 304.
        request.no_content = request.head_request or code == @intFromEnum(http.status.Code.no_content) or
            code == @intFromEnum(http.status.Code.not_modified);
    }
    return .{ .event = .{ .response = .{ .stream_id = request.id, .response = found } } };
}
