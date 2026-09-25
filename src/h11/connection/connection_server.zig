//! A server's side of an h11 connection: requests read one at a time, and the responses the
//! application writes to them, in order (RFC 9112 §9.3.2, decision 92).
//!
//! The next request is read only after the current one's final response is written, so the octets
//! of a pipelined request stay unread in the caller's buffer until then. A response written
//! before the request's body has all been read ends the connection after it, because RFC 9112 §9.3
//! has a server read the whole body or close.
//!
//! A malformed request fails the connection, and the error response colibri owes is written by
//! `write_pending` with `Connection: close` (decision 92).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const http = @import("http");
const constants = @import("../constants.zig");
const message = @import("../message/message.zig");
const connection = @import("connection.zig");
const connection_body = @import("connection_body.zig");

const Connection = connection.Connection;
const Received = connection.Received;
const Field = http.field.Field;
const Code = http.status.Code;

/// 431 Request Header Fields Too Large (RFC 6585 §5), which RFC 9110 §15 does not define.
const status_fields_too_large: u16 = 431;

/// The field line colibri adds to the last response on a connection (RFC 9112 §9.6).
const close_field: Field = .{ .name = "Connection", .value = "close" };

pub fn receive(target: *Connection, input: []const u8) connection.Error!Received {
    return switch (target.phase) {
        .closed, .waiting => .{ .consumed = 0, .event = null },
        .tunnel => .{ .consumed = input.len, .event = if (input.len == 0) null else .{ .tunnel = input } },
        .head => read_request(target, input),
        .body => read_body(target, input),
    };
}

fn read_request(target: *Connection, input: []const u8) connection.Error!Received {
    const read = message.read_request(&target.scanner, input, &target.section) catch |failure| {
        return target.fail(failure, status_of(failure));
    };
    const request = read orelse return .{ .consumed = 0, .event = null };
    // RFC 9112 §9.3 and §9.6: a request with the close option is the last, and so is an HTTP/1.0
    // one, because colibri honours no HTTP/1.0 keep-alive (decision 92).
    target.close_after = request.line.version.minor == 0 or connection.section_asks_close(&target.section);
    target.asked = connection.asked_of(request.line.method);
    target.answered = false;
    target.responded = false;
    target.reader = connection_body.Reader.start(request.body.length);
    target.phase = if (target.reader.open()) .body else .waiting;
    return .{ .consumed = request.head_len, .event = .{ .request = .{
        .line = request.line,
        .form = request.form,
        .body = request.body,
    } } };
}

fn read_body(target: *Connection, input: []const u8) connection.Error!Received {
    const read = connection_body.read(&target.reader, .request, input, &target.trailers) catch |failure| {
        return target.fail(failure, status_of(failure));
    };
    // decision 92: the next request waits for this one's final response.
    if (read.ended) target.phase = .waiting;
    if (read.data.len > 0) {
        target.end_owed = read.ended;
        return .{ .consumed = read.consumed, .event = .{ .data = read.data } };
    }
    return .{ .consumed = read.consumed, .event = if (read.ended) .end else null };
}

/// Writes a response head to the request read last. An interim response (1xx) may come first;
/// the final one decides how the body is framed (RFC 9112 §6.3), and the connection's last final
/// response carries `Connection: close` (RFC 9112 §9.6).
pub fn write_response(target: *Connection, output: []u8, status: u16, reason: []const u8, fields: []const Field) connection.SendError!usize {
    // RFC 9112 §9.6: a server that closes the connection sends nothing after its last response.
    if (target.phase == .closed or target.failure != null) return error.ConnectionClosed;
    // RFC 9112 §9.2: each response answers the request read last, and one final response does.
    if (target.phase == .head or target.phase == .tunnel or target.answered) return error.NoRequest;
    // RFC 9110 §15.2.2: 101 switches to the protocol Upgrade names, which h11 does not implement.
    if (status == @intFromEnum(Code.switching_protocols)) return error.UpgradeUnsupported;
    // RFC 9110 §15: a status code is three digits from 100 to 599.
    const code = http.status.Status.from_code(status) catch return error.StatusInvalid;
    if (code.is_interim()) return message.write_response_head(output, status, reason, fields);
    const writer = response_body(target, code, fields);
    // RFC 9112 §6.3 rule 8: a response with no declared length ends with the connection.
    if (writer.kind == .close_delimited) target.close_after = true;
    const written = try write_final_head(target, output, status, reason, fields);
    target.answered = true;
    target.writer = writer;
    if (writer.kind == .tunnel) target.phase = .tunnel;
    if (!writer.open()) finish_response(target);
    return written;
}

/// How the final response's body is framed (RFC 9112 §6.3 rules 1 and 2, then its own fields).
fn response_body(target: *const Connection, code: http.status.Status, fields: []const Field) connection_body.Writer {
    const no_content = code.code == @intFromEnum(Code.no_content) or code.code == @intFromEnum(Code.not_modified);
    // RFC 9112 §6.3 rule 1: a response to HEAD, and a 204 or 304, has no body.
    if (target.asked == .head or no_content) return .{ .kind = .none };
    // RFC 9112 §6.3 rule 2: a 2xx to CONNECT makes the connection a tunnel.
    if (target.asked == .connect and code.class() == .successful) return .{ .kind = .tunnel };
    return connection_body.declared(fields, .close_delimited);
}

/// The final head, with `Connection: close` added when the connection closes after it and the
/// fields do not say so already (RFC 9112 §9.6).
fn write_final_head(target: *const Connection, output: []u8, status: u16, reason: []const u8, fields: []const Field) connection.SendError!usize {
    if (!target.close_after or connection.fields_ask_close(fields)) {
        return message.write_response_head(output, status, reason, fields);
    }
    var with_close: [core.constants.field_count_max]Field = undefined;
    // RFC 9110 §5.4: no predefined limit on a section, so colibri's applies to what it sends.
    if (fields.len >= with_close.len) return error.TooManyFields;
    @memcpy(with_close[0..fields.len], fields);
    with_close[fields.len] = close_field;
    return message.write_response_head(output, status, reason, with_close[0 .. fields.len + 1]);
}

/// The final response is written whole. The connection reads the next request, or closes.
pub fn finish_response(target: *Connection) void {
    assert(target.role == .server and target.answered);
    target.responded = true;
    if (target.phase == .tunnel) return;
    // RFC 9112 §9.3: a server MUST read the whole request body or close after its response.
    if (target.phase == .body) target.close_after = true;
    if (target.close_after) {
        target.phase = .closed;
        return;
    }
    assert(target.phase == .waiting);
    target.phase = .head;
    target.answered = false;
}

/// The error response colibri owes for a refused request (decision 92): no content, and the close.
pub fn write_error_response(output: []u8, status: u16) message.WriteError!usize {
    const fields = [_]Field{ close_field, .{ .name = "Content-Length", .value = "0" } };
    return message.write_response_head(output, status, reason_of(status), &fields);
}

/// The status a refusal is answered with (decision 92).
fn status_of(failure: anyerror) u16 {
    return switch (failure) {
        // RFC 9112 §3: a request-target longer than the server will parse is a 414.
        error.StartLineTooLong => @intFromEnum(Code.uri_too_long),
        // RFC 6585 §5: header fields too large, in total or one at a time.
        error.HeadTooLarge, error.SectionTooLarge, error.TooManyLines => status_fields_too_large,
        // RFC 9112 §6.1: a transfer coding the server does not understand is a 501.
        error.CodingUnsupported, error.CodingsStacked => @intFromEnum(Code.not_implemented),
        // RFC 9110 §15.6.6: a major version the server does not support.
        error.VersionUnsupported => @intFromEnum(Code.http_version_not_supported),
        // RFC 9112 §2.2, §3.2, §5.1 and §6.3: a malformed request is a 400.
        else => @intFromEnum(Code.bad_request),
    };
}

/// The reason phrase of each status `status_of` returns (RFC 9110 §15, RFC 6585 §5).
fn reason_of(status: u16) []const u8 {
    if (status == status_fields_too_large) return "Request Header Fields Too Large";
    return switch (@as(Code, @enumFromInt(status))) {
        .uri_too_long => "URI Too Long",
        .not_implemented => "Not Implemented",
        .http_version_not_supported => "HTTP Version Not Supported",
        else => "Bad Request",
    };
}
