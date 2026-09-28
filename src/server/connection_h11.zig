//! The h11 half of a server connection (decision 100): h11's events turned into the server's, and
//! the server's responses framed as RFC 9112 §6 requires. A request's id is its place on the
//! connection, counting from 1, and h11 answers one request at a time, in order (RFC 9112 §9.3.2).
//!
//! The caller names no framing field. A final response that ends with its head carries
//! `Content-Length: 0`, and one whose content follows is chunked when the request came as HTTP/1.1
//! (RFC 9112 §7.1) and runs until the close when it came as HTTP/1.0 (RFC 9112 §6.3 rule 8). A
//! caller that gives its own Content-Length or Transfer-Encoding keeps it.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const http = @import("http");
const h11 = @import("h11");
const constants = @import("constants.zig");
const event = @import("event.zig");
const reason = @import("reason.zig");
const connection_module = @import("connection.zig");

const Connection = connection_module.Connection;
const SendError = connection_module.SendError;
const Error = connection_module.Error;
const Field = http.field.Field;
const Event = event.Event;
const Received = event.Received;
const Id = event.Id;
const Code = http.status.Code;

/// The framing fields colibri adds (RFC 9112 §6.1, RFC 9110 §8.6).
const content_length_zero: Field = .{ .name = "content-length", .value = "0" };
const transfer_encoding_chunked: Field = .{ .name = "transfer-encoding", .value = "chunked" };

/// The schemes of a target URI h11 reconstructs (RFC 9112 §3.3).
const scheme_http = "http";
const scheme_https = "https";

/// The separator between an absolute-URI's scheme and its authority (RFC 3986 §3).
const authority_prefix = "://";

/// RFC 9110 §4.2.3: an empty path is the same as "/".
const path_empty = "/";

/// Reads at most one event from `plaintext`. h11 reports one event a call at most, and takes the
/// octets of none at times, such as an empty line before a request (RFC 9112 §2.2).
pub fn receive(connection: *Connection, plaintext: []const u8) Error!Received {
    const session = &connection.session.h11;
    var consumed: usize = 0;
    // Bounded: a pass that reports nothing takes an octet at least, or ends the loop.
    for (0..plaintext.len + 1) |_| {
        const received = session.receive(plaintext[consumed..], connection.config.decoded) catch return connection.fail();
        consumed += received.consumed;
        if (received.event) |h11_event| return .{ .consumed = consumed, .event = report(connection, h11_event) };
        if (received.consumed == 0) break;
    }
    return .{ .consumed = consumed, .event = null };
}

fn report(connection: *Connection, h11_event: h11.connection.Event) Event {
    const session = &connection.session.h11;
    const id = connection.current_id;
    return switch (h11_event) {
        .request => |request| start_request(connection, request),
        .data, .tunnel => |octets| .{ .body = .{ .id = id, .octets = octets, .end = false } },
        // RFC 9112 §7.1.2: a chunked body's trailer section ends it.
        .end => if (session.trailers.len() > 0)
            .{ .trailers = .{ .id = id, .fields = .{ .section = &session.trailers, .first = 0 } } }
        else
            .{ .body = .{ .id = id, .octets = &.{}, .end = true } },
        // A server's h11 connection reads requests alone.
        .interim, .response => unreachable,
    };
}

fn start_request(connection: *Connection, request: h11.connection.Request) Event {
    const session = &connection.session.h11;
    connection.current_id = connection.next_id;
    connection.next_id += 1;
    // RFC 9112 §7.1: a recipient that is not HTTP/1.1 does not know the chunked coding.
    connection.chunked_allowed = request.line.version.minor > 0;
    connection.head_request = session.asked == .head;
    const target = target_of(request, &session.section, connection.config.tls != null);
    return .{
        .request = .{
            .id = connection.current_id,
            .method = request.line.method,
            .version = .{ .major = request.line.version.major, .minor = request.line.version.minor },
            .target = request.line.target,
            .scheme = target.scheme,
            .authority = target.authority,
            .path = target.path,
            .fields = .{ .section = &session.section, .first = 0 },
            // h11 reads no body for a request that declared none.
            .end = session.phase == .waiting,
        },
    };
}

const Target = struct {
    scheme: ?[]const u8,
    authority: ?[]const u8,
    path: ?[]const u8,
};

/// The parts of the target URI (RFC 9112 §3.3), from the request-target's form (§3.2).
fn target_of(request: h11.connection.Request, section: *const http.FieldSection, secure: bool) Target {
    const target = request.line.target;
    const host = if (section.find("host")) |line| line.value else null;
    return switch (request.form) {
        // RFC 9112 §3.3: the scheme is https for a secured connection and http otherwise, and the
        // authority is Host's.
        .origin, .asterisk => .{ .scheme = if (secure) scheme_https else scheme_http, .authority = host, .path = target },
        // RFC 9112 §3.2.2: a server ignores Host for an absolute-form target, whose authority
        // replaces it.
        .absolute => absolute_target(target),
        // RFC 9112 §3.2.3: CONNECT's target is an authority alone.
        .authority => .{ .scheme = null, .authority = target, .path = null },
    };
}

fn absolute_target(target: []const u8) Target {
    const uri = http.uri.absolute_uri(target) orelse return .{ .scheme = null, .authority = null, .path = target };
    const authority = uri.authority orelse return .{ .scheme = uri.scheme, .authority = null, .path = target[uri.scheme.len + 1 ..] };
    const rest = target[uri.scheme.len + authority_prefix.len + authority.len ..];
    return .{ .scheme = uri.scheme, .authority = authority, .path = if (rest.len == 0) path_empty else rest };
}

pub fn respond(connection: *Connection, id: Id, status: u16, fields: []const Field, end: bool) SendError!void {
    try check_current(connection, id);
    const session = &connection.session.h11;
    defer note_done(connection, id);
    var lines: [core.constants.field_count_max]Field = undefined;
    const framed = try framing(connection, status, fields, end, &lines);
    const interim = status >= http.constants.status_code_min and status < @intFromEnum(Code.ok);
    // A response that ends with its head keeps room for the last chunk a caller's own
    // Transfer-Encoding would need, so the end never fails after the head went out.
    const reserve: usize = if (end and !interim) constants.last_chunk_len else 0;
    const room = connection.room();
    if (room.len <= reserve) return error.NoSpaceLeft;
    const written = session.write_response(room[0 .. room.len - reserve], status, reason.of(status), framed) catch |failure| {
        return send_error(connection, failure);
    };
    connection.output_len += written;
    // An interim response leaves no body open, and neither does one without content.
    if (!end or !session.writer.open()) return;
    connection.output_len += session.write_end(connection.room(), &.{}) catch |failure| return send_error(connection, failure);
}

/// The caller's fields, and the framing field the response needs when it names none.
fn framing(connection: *const Connection, status: u16, fields: []const Field, end: bool, lines: *[core.constants.field_count_max]Field) SendError![]const Field {
    const session = &connection.session.h11;
    // RFC 9110 §15: a status code is three digits from 100 to 599.
    const code = http.status.Status.from_code(status) catch return error.StatusInvalid;
    // RFC 9112 §6.3 rules 1 and 2: an interim response, a response to HEAD, a 204 or 304, and a
    // 2xx to CONNECT have no content to frame.
    const unframed = code.is_interim() or connection.head_request or
        status == @intFromEnum(Code.no_content) or status == @intFromEnum(Code.not_modified) or
        (session.asked == .connect and code.class() == .successful);
    if (unframed or names_framing(fields)) return fields;
    const added = if (end) content_length_zero else if (connection.chunked_allowed) transfer_encoding_chunked else return fields;
    // RFC 9110 §5.4: a section has no predefined limit, so colibri's applies to what it sends.
    if (fields.len >= lines.len) return error.SectionTooLarge;
    @memcpy(lines[0..fields.len], fields);
    lines[fields.len] = added;
    return lines[0 .. fields.len + 1];
}

/// Whether the caller framed the content itself (RFC 9112 §6.1, RFC 9110 §8.6).
fn names_framing(fields: []const Field) bool {
    for (fields) |field| {
        if (http.field.names_equal(field.name, content_length_zero.name)) return true;
        if (http.field.names_equal(field.name, transfer_encoding_chunked.name)) return true;
    }
    return false;
}

pub fn write_body(connection: *Connection, id: Id, octets: []const u8, end: bool) SendError!usize {
    try check_current(connection, id);
    const session = &connection.session.h11;
    defer note_done(connection, id);
    // RFC 9112 §6: content follows only a final response that declared some, and ends once. h11
    // refuses the rest with `NoBody`.
    const chunked = session.writer.kind == .chunked;
    const framing_len: usize = if (chunked) constants.chunk_framing_len_max else 0;
    const reserve: usize = if (end and chunked) constants.last_chunk_len else 0;
    const room = connection.room();
    // RFC 9112 §7.1: a chunk is its size line, its data and a CRLF, so room for less holds none.
    if (room.len <= framing_len + reserve) return error.Blocked;
    const taken = @min(octets.len, room.len - framing_len - reserve);
    var written: usize = 0;
    if (taken > 0) written = session.write_body(room, octets[0..taken]) catch |failure| return send_error(connection, failure);
    connection.output_len += written;
    if (end and taken == octets.len) {
        connection.output_len += session.write_end(connection.room(), &.{}) catch |failure| return send_error(connection, failure);
    }
    return taken;
}

pub fn write_trailers(connection: *Connection, id: Id, fields: []const Field) SendError!void {
    try check_current(connection, id);
    defer note_done(connection, id);
    // RFC 9110 §6.5: a trailer section follows the content, after a final response. h11 refuses
    // one anywhere else with `NoBody`.
    connection.output_len += connection.session.h11.write_end(connection.room(), fields) catch |failure| return send_error(connection, failure);
}

/// h11 cannot end one request and keep the connection (RFC 9112 §9.6), so a cancel ends both.
pub fn cancel(connection: *Connection, id: Id) void {
    if (id != connection.current_id or connection.current_id == 0) return;
    connection.stopped = true;
}

/// Ends the connection after the current response, or now when no request is being read or
/// answered (RFC 9112 §9.6).
pub fn shutdown(connection: *Connection) void {
    if (idle(connection)) {
        connection.stopped = true;
        return;
    }
    connection.session.h11.close_after = true;
}

/// Whether no request is being read or answered.
pub fn idle(connection: *const Connection) bool {
    const session = &connection.session.h11;
    return session.phase == .head and session.scanner.scanned == 0;
}

/// Owes the `done` event of request `id` once its response is whole: h11 finished it, and no
/// `done` is owed for it yet (decision 103). h11 finishes a response with its head when it has no
/// content, such as a response to HEAD (RFC 9112 §6.3 rule 1).
fn note_done(connection: *Connection, id: Id) void {
    if (!connection.session.h11.responded or connection.done_id == id) return;
    connection.done_id = id;
    connection.done_owed.push(id);
}

fn check_current(connection: *const Connection, id: Id) SendError!void {
    // RFC 9112 §9.3.2: h11 answers the request it read last, and no other.
    if (id == 0 or id != connection.current_id) return error.RequestUnknown;
}

fn send_error(connection: *const Connection, failure: h11.connection.SendError) SendError {
    return switch (failure) {
        // A head that does not fit an empty output never will.
        error.OutputTooSmall => if (connection.output_len == 0) error.SectionTooLarge else error.NoSpaceLeft,
        error.StatusInvalid, error.UpgradeUnsupported => error.StatusInvalid,
        error.FieldNameInvalid, error.FieldValueInvalid, error.FramingInvalid => error.FieldLineInvalid,
        error.TrailerFieldForbidden, error.TrailersWithoutChunked => error.TrailersRefused,
        error.BodyTooLong, error.BodyIncomplete => error.ContentLengthMismatch,
        error.NoRequest, error.BodyInProgress, error.NoBody => error.SectionOutOfOrder,
        error.ConnectionClosed => error.ConnectionClosed,
        error.TooManyFields => error.SectionTooLarge,
        // A server writes no request line, counts no body octets it did not write, and pipelines
        // nothing.
        error.MethodInvalid, error.TargetInvalid, error.ReasonInvalid, error.HostInvalid => unreachable,
        error.BodyChunked, error.PipelineFull, error.PipelineBlocked => unreachable,
    };
}

/// Writes the 100 (Continue) the current request is owed (RFC 9110 §10.1.1), an interim response.
pub fn write_continue(connection: *Connection) SendError!usize {
    return connection.session.h11.write_response(connection.room(), continue_status, reason.of(continue_status), &.{}) catch |failure| {
        return send_error(connection, failure);
    };
}

/// RFC 9110 §15.2.1: 100 (Continue).
const continue_status: u16 = @intFromEnum(Code.@"continue");
