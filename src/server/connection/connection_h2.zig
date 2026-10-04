//! The h2 half of a server connection (decision 100): h2's events turned into the server's, and
//! the server's responses written through h2's send path (RFC 9113 §8.1). A request's id is the
//! stream it arrived on.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const http = @import("http");
const h2 = @import("h2");
const constants = @import("../constants.zig");
const event = @import("../event.zig");
const connection_module = @import("connection.zig");
const internal = @import("connection_internal.zig");
const connection_sends = @import("connection_sends.zig");

const Connection = connection_module.Connection;
const SendError = connection_module.SendError;
const Error = connection_module.Error;
const Field = http.Field;
const Event = event.Event;
const Received = event.Received;
const Id = event.Id;

/// RFC 9113 is HTTP/2, which RFC 9110 §2.5 numbers 2.0.
const version: event.Version = .{ .major = version_major, .minor = 0 };
const version_major: u8 = 2;

/// Reads frames from `plaintext` until one means something to the caller, h2 needs more octets,
/// or the replies h2 owes must be written first and `output` has no room for them.
pub fn receive(connection: *Connection, plaintext: []const u8, now_ns: u64) Error!Received {
    const session = &connection.session.h2;
    // RFC 9113 §3.4: the server's SETTINGS "MUST be the first frame the server sends", so it goes
    // into the output before any frame is read that could bring a request the caller answers.
    if (!session.preface_done() and !internal.write_owed(connection, now_ns)) return .{ .consumed = 0, .event = null };
    var consumed: usize = 0;
    for (0..constants.frames_per_receive_max) |_| {
        const received = session.receive(plaintext[consumed..], now_ns) catch return internal.fail(connection);
        consumed += received.consumed;
        if (received.consumed == 0) {
            // RFC 9113 §3.4, §6.5.3: h2 reads nothing more until what it owes is written, such as
            // the server's SETTINGS and the acknowledgment of the peer's.
            if (!session.has_pending() or !internal.write_owed(connection, now_ns)) return .{ .consumed = consumed, .event = null };
            continue;
        }
        const reported = report(session, received.event orelse continue) orelse continue;
        return .{ .consumed = consumed, .event = reported };
    }
    return .{ .consumed = consumed, .event = null };
}

/// The server's event for h2's, or null for one that concerns the connection alone.
fn report(session: *const h2.Connection, h2_event: h2.Event) ?Event {
    return switch (h2_event) {
        .request => |arrived| .{
            .request = .{
                .id = arrived.stream_id,
                .method = arrived.request.method,
                .version = version,
                // RFC 9113 §8.3.1, §8.5: h2 reads a request only with a `:path`, or CONNECT's
                // `:authority`.
                .target = arrived.request.path orelse arrived.request.authority.?,
                .scheme = arrived.request.scheme,
                .authority = arrived.request.authority,
                .path = arrived.request.path,
                .fields = event.Fields.of(session.field_section()),
                .end = arrived.end_stream,
            },
        },
        .data => |data| .{ .body = .{ .id = data.stream_id, .octets = data.payload, .end = data.end_stream } },
        .trailers => |trailers| .{ .trailers = .{ .id = trailers.stream_id, .fields = event.Fields.of(session.field_section()) } },
        // RFC 9113 §6.4: the peer ended the stream; §5.4.2: colibri did, on a stream error.
        .stream_reset => |reset| .{ .cancelled = .{ .id = reset.stream_id, .reason = .peer_reset } },
        .stream_refused => |refused| .{ .cancelled = .{ .id = refused.stream_id, .reason = .refused } },
        // RFC 9113 §8.1: a server receives no response; h2 refuses one before it is an event. RFC
        // 7838 §4: a server ignores ALTSVC, and h2 reports none to one.
        .settings_acknowledged, .settings_applied, .ping_acknowledged, .goaway, .response, .alt_svc => null,
    };
}

/// Writes what h2 owes ahead of a frame of the caller's, as `client.Connection` does. A full
/// reply queue stops the reading, and two endpoints that each write their own frames first can
/// fill the transport both ways so that neither queue ever empties (decision 39 as amended,
/// https://github.com/c4milo/colibri/issues/85).
fn write_owed_first(connection: *Connection) void {
    const session = &connection.session.h2;
    const update_owed = session.owes_window_update();
    internal.take_owed(connection, session.write_replies(internal.room(connection)), update_owed);
}

pub fn respond(connection: *Connection, id: Id, status: u16, fields: []const Field, end: bool) SendError!void {
    const stream_id = try stream_of(id);
    var lines: [core.constants.field_count_max]h2.hpack.Field = undefined;
    const converted = try convert(fields, &lines);
    write_owed_first(connection);
    // RFC 9113 §8.1: only the final response ends the stream, so an interim one carries no
    // END_STREAM whatever the caller asked.
    const interim = status >= http.constants.status_code_min and status < @intFromEnum(http.status.Code.ok);
    if (!interim) try advertise(connection, stream_id);
    const written = connection.session.h2.write_response(internal.room(connection), stream_id, status, converted, end and !interim) catch |failure| {
        return send_error(connection, failure);
    };
    connection.output_len += written;
    // RFC 9113 §8.1: a final response's END_STREAM ends it.
    if (end and !interim) connection.done_owed.push(id);
}

/// Writes the ALTSVC frame that advertises h3, once per connection, on the stream of its first
/// final response and before that response can end the stream (RFC 7838 §3, §4).
fn advertise(connection: *Connection, stream_id: u32) SendError!void {
    if (connection.advert.sent) return;
    const value = connection.advert.value() orelse return;
    const written = connection.session.h2.write_alt_svc(internal.room(connection), stream_id, value) catch |failure| {
        return send_error(connection, failure);
    };
    connection.output_len += written;
    connection.advert.sent = true;
}

/// Writes as much of `octets` as the room and h2's windows allow, in as many DATA frames as the
/// peer's largest frame cuts it into (https://github.com/c4milo/colibri/issues/91).
pub fn write_body(connection: *Connection, id: Id, octets: []const u8, end: bool) SendError!usize {
    const stream_id = try stream_of(id);
    write_owed_first(connection);
    var consumed: usize = 0;
    var written: usize = 0;
    for (0..constants.data_frames_per_write_max) |_| {
        const sent = connection.session.h2.write_data(internal.room(connection), stream_id, octets[consumed..], end) catch |failure| {
            // A frame cut at the frame size leaves the stream open, so only the first call fails.
            assert(written == 0);
            return send_error(connection, failure);
        };
        connection.output_len += sent.written;
        connection_sends.on_write(connection, id, octets.len - consumed, sent);
        consumed += sent.consumed;
        written += sent.written;
        // RFC 9113 §4.2: the frame stopped at the peer's SETTINGS_MAX_FRAME_SIZE, and the windows
        // and the room may take another.
        if (sent.short_by != .frame_size) break;
    }
    // RFC 9113 §6.9: no window, or no room for a frame, and nothing moved.
    if (written == 0) return error.Blocked;
    // h2 sets END_STREAM on the frame that carries the last octet, and only then.
    if (end and consumed == octets.len) connection.done_owed.push(id);
    return consumed;
}

pub fn write_trailers(connection: *Connection, id: Id, fields: []const Field) SendError!void {
    const stream_id = try stream_of(id);
    var lines: [core.constants.field_count_max]h2.hpack.Field = undefined;
    const converted = try convert(fields, &lines);
    write_owed_first(connection);
    const written = connection.session.h2.write_trailers(internal.room(connection), stream_id, converted) catch |failure| {
        return send_error(connection, failure);
    };
    connection.output_len += written;
    // RFC 9113 §8.1: a trailer section ends the stream.
    connection.done_owed.push(id);
    connection_sends.remove(connection, id);
}

pub fn cancel(connection: *Connection, id: Id) void {
    const stream_id = stream_of(id) catch return;
    // RFC 9113 §6.4: CANCEL says the stream is no longer needed. A stream h2 no longer holds needs
    // no reset.
    connection.session.h2.reset_stream(stream_id, h2.constants.error_cancel) catch |failure| {
        assert(failure == error.StreamNotSendable);
    };
}

/// Whether no stream the peer opened is active.
pub fn idle(connection: *const Connection) bool {
    return connection.session.h2.streams.peer_active == 0;
}

/// The stream an id names, or `RequestUnknown` for one no stream can have. h2 refuses a stream
/// the client did not open.
fn stream_of(id: Id) SendError!u32 {
    // RFC 9113 §5.1.1: a stream identifier is 31 bits, and 0 names the connection.
    if (id == 0 or id > h2.constants.stream_id_max) return error.RequestUnknown;
    return @intCast(id);
}

/// The caller's field lines as h2's encoder takes them.
fn convert(fields: []const Field, lines: *[core.constants.field_count_max]h2.hpack.Field) SendError![]const h2.hpack.Field {
    // RFC 9110 §5.4: a section has no predefined limit, so colibri's applies to what it sends.
    if (fields.len > lines.len) return error.SectionTooLarge;
    for (fields, lines[0..fields.len]) |field, *line| line.* = .{ .name = field.name, .value = field.value };
    return lines[0..fields.len];
}

fn send_error(connection: *const Connection, failure: h2.connection.SendError) SendError {
    return switch (failure) {
        error.StreamNotSendable => error.RequestUnknown,
        // A section that does not fit an empty output never will.
        error.OutputTooSmall => if (connection.output_len == 0) error.SectionTooLarge else error.NoSpaceLeft,
        error.StatusInvalid => error.StatusInvalid,
        error.FieldLineInvalid => error.FieldLineInvalid,
        error.SectionOutOfOrder => error.SectionOutOfOrder,
        // `respond` asks for END_STREAM on a final response alone.
        error.InterimEndsStream => unreachable,
    };
}

/// Writes the 100 (Continue) request `id` is owed (RFC 9110 §10.1.1), an interim response.
pub fn write_continue(connection: *Connection, id: Id) SendError!usize {
    const stream_id = try stream_of(id);
    write_owed_first(connection);
    return connection.session.h2.write_response(internal.room(connection), stream_id, continue_status, &.{}, false) catch |failure| {
        return send_error(connection, failure);
    };
}

/// RFC 9110 §15.2.1: 100 (Continue).
const continue_status: u16 = @intFromEnum(http.status.Code.@"continue");
