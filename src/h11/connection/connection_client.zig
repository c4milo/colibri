//! A client's side of an h11 connection: requests written in order, kept in a queue until each
//! has its final response, and responses given to the oldest one (RFC 9112 §9.2).
//!
//! The client pipelines as decision 88 rules it (RFC 9112 §9.3.2): it writes no request while one
//! whose method is not idempotent waits for its final response, and none after the first on a
//! connection opened to retry, until that first request has its final response. A request's body
//! goes out before the next head. A request carrying `Connection: close` is the last (§9.6).
//!
//! A response that arrives with no request outstanding is refused, unless it is only CRLF, which
//! §2.2 lets the client discard (§9.2). 101 Switching Protocols is refused: h11 implements no
//! upgrade.
const std = @import("std");
const assert = std.debug.assert;
const http = @import("http");
const constants = @import("../constants.zig");
const message = @import("../message/message.zig");
const connection = @import("connection.zig");
const connection_body = @import("connection_body.zig");

const Connection = connection.Connection;
const Received = connection.Received;
const Field = http.field.Field;
const Code = http.status.Code;

pub const Error = error{
    /// Octets other than CRLF with no request outstanding (RFC 9112 §9.2).
    ResponseUnexpected,
    /// 101 Switching Protocols, which h11 does not implement (RFC 9110 §15.2.2).
    UpgradeUnsupported,
};

/// The line end a client may discard before a response it has no request for (RFC 9112 §2.2).
const line_end = "\r\n";

/// Writes a request head and puts the request at the back of the queue.
pub fn write_request(target: *Connection, output: []u8, method: []const u8, target_uri: []const u8, fields: []const Field) connection.SendError!usize {
    // RFC 9112 §9.6: a client that sent the close option sends no further request.
    if (target.phase == .closed or target.failure != null or target.close_sent) return error.ConnectionClosed;
    // RFC 9112 §9.3.2: requests go out in order, so a body is finished before the next head.
    if (target.writer.open()) return error.BodyInProgress;
    // RFC 9112 §9.2: a client keeps its outstanding requests in order, in a queue colibri bounds.
    if (target.outstanding_len == constants.pipeline_depth_max) return error.PipelineFull;
    if (target.outstanding_len > 0) try check_pipelining(target);
    const written = try message.write_request_head(output, method, target_uri, fields);
    push(target, .{ .asked = connection.asked_of(method), .idempotent = connection.is_idempotent(method) });
    target.writer = connection_body.declared(fields, .none);
    target.close_sent = connection.fields_ask_close(fields);
    return written;
}

/// Decision 88: whether another request may follow those outstanding (RFC 9112 §9.3.2).
fn check_pipelining(target: *const Connection) connection.SendError!void {
    // RFC 9112 §9.3.2: after a failed connection, a client MUST NOT pipeline immediately.
    if (target.retrying) return error.PipelineBlocked;
    for (0..target.outstanding_len) |offset| {
        // RFC 9112 §9.3.2: a user agent SHOULD NOT pipeline after a non-idempotent method until
        // its final response arrives; colibri does not.
        if (!at(target, @intCast(offset)).idempotent) return error.PipelineBlocked;
    }
}

pub fn receive(target: *Connection, input: []const u8) connection.Error!Received {
    return switch (target.phase) {
        .closed => .{ .consumed = 0, .event = null },
        .tunnel => .{ .consumed = input.len, .event = if (input.len == 0) null else .{ .tunnel = input } },
        .head => read_response(target, input),
        .body => read_body(target, input),
        .waiting => unreachable,
    };
}

fn read_response(target: *Connection, input: []const u8) connection.Error!Received {
    if (target.outstanding_len == 0) return read_unrequested(target, input);
    const oldest = at(target, 0);
    const read = message.read_response(&target.scanner, oldest.asked, input, &target.section) catch |failure| {
        return target.fail(failure, null);
    };
    const response = read orelse return .{ .consumed = 0, .event = null };
    // RFC 9110 §15.2.2: 101 switches to the protocol Upgrade names, which h11 does not implement.
    if (response.line.status.code == @intFromEnum(Code.switching_protocols)) {
        return target.fail(error.UpgradeUnsupported, null);
    }
    // RFC 9112 §9.2: an interim response precedes the final one to the same request.
    if (response.line.status.is_interim()) return .{ .consumed = response.head_len, .event = .{ .interim = response.line } };
    // RFC 9112 §9.3: a response with the close option, or an HTTP/1.0 one, is the last.
    if (response.line.version.minor == 0 or connection.section_asks_close(&target.section)) target.close_after = true;
    target.reader = connection_body.Reader.start(response.body.length);
    if (response.body.length == .tunnel) {
        // RFC 9112 §6.3 rule 2: after a 2xx to CONNECT, every octet each way is the tunnel's.
        pop(target);
        target.phase = .tunnel;
        target.writer = .{ .kind = .tunnel };
    } else if (target.reader.open()) {
        target.phase = .body;
    } else {
        complete_response(target);
    }
    return .{ .consumed = response.head_len, .event = .{ .response = .{ .line = response.line, .body = response.body } } };
}

/// Octets that arrived with no request outstanding (RFC 9112 §9.2).
fn read_unrequested(target: *Connection, input: []const u8) connection.Error!Received {
    if (input.len == 0) return .{ .consumed = 0, .event = null };
    // RFC 9112 §2.2 and §9.2: CRLF alone may be discarded; anything else is no valid response.
    if (std.mem.startsWith(u8, input, line_end)) return .{ .consumed = line_end.len, .event = null };
    // RFC 9112 §9.2: a CR that may begin a CRLF waits for its LF.
    if (std.mem.eql(u8, input, "\r")) return .{ .consumed = 0, .event = null };
    return target.fail(error.ResponseUnexpected, null);
}

fn read_body(target: *Connection, input: []const u8) connection.Error!Received {
    const read = connection_body.read(&target.reader, .response, input, &target.trailers) catch |failure| {
        return target.fail(failure, null);
    };
    if (read.ended) complete_response(target);
    if (read.data.len > 0) {
        target.end_owed = read.ended;
        return .{ .consumed = read.consumed, .event = .{ .data = read.data } };
    }
    return .{ .consumed = read.consumed, .event = if (read.ended) .end else null };
}

/// The oldest request has its whole final response: it leaves the queue, and the connection reads
/// the next response or closes (RFC 9112 §9.3, §9.6).
fn complete_response(target: *Connection) void {
    pop(target);
    target.retrying = false;
    target.phase = if (target.close_after) .closed else .head;
}

fn at(target: *const Connection, offset: u32) connection.Outstanding {
    assert(offset < target.outstanding_len);
    return target.outstanding[(target.outstanding_first + offset) % constants.pipeline_depth_max];
}

fn push(target: *Connection, request: connection.Outstanding) void {
    assert(target.outstanding_len < constants.pipeline_depth_max);
    const index = (target.outstanding_first + target.outstanding_len) % constants.pipeline_depth_max;
    target.outstanding[index] = request;
    target.outstanding_len += 1;
}

fn pop(target: *Connection) void {
    assert(target.outstanding_len > 0);
    target.outstanding_first = (target.outstanding_first + 1) % constants.pipeline_depth_max;
    target.outstanding_len -= 1;
}
