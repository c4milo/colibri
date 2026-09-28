//! The h2 half of a server connection (decision 100): h2's events turned into the server's, and
//! the server's responses written through h2's send path (RFC 9113 §8.1). A request's id is the
//! stream it arrived on.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const http = @import("http");
const h2 = @import("h2");
const constants = @import("constants.zig");
const event = @import("event.zig");
const connection_module = @import("connection.zig");

const Connection = connection_module.Connection;
const SendError = connection_module.SendError;
const Error = connection_module.Error;
const Field = http.field.Field;
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
    var consumed: usize = 0;
    for (0..constants.frames_per_receive_max) |_| {
        const received = session.receive(plaintext[consumed..], now_ns) catch return connection.fail();
        consumed += received.consumed;
        if (received.consumed == 0) {
            // RFC 9113 §3.4, §6.5.3: h2 reads nothing more until what it owes is written, such as
            // the server's SETTINGS and the acknowledgment of the peer's.
            if (!session.has_pending() or !connection.write_owed(now_ns)) return .{ .consumed = consumed, .event = null };
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
        .stream_reset, .stream_refused => |reset| .{ .cancelled = .{ .id = reset.stream_id } },
        // RFC 9113 §8.1: a server receives no response; h2 refuses one before it is an event.
        .settings_acknowledged, .settings_applied, .ping_acknowledged, .goaway, .response => null,
    };
}

pub fn respond(connection: *Connection, id: Id, status: u16, fields: []const Field, end: bool) SendError!void {
    const stream_id = try stream_of(id);
    var lines: [core.constants.field_count_max]h2.hpack.Field = undefined;
    const converted = try convert(fields, &lines);
    // RFC 9113 §8.1: only the final response ends the stream, so an interim one carries no
    // END_STREAM whatever the caller asked.
    const interim = status >= http.constants.status_code_min and status < @intFromEnum(http.status.Code.ok);
    const written = connection.session.h2.write_response(connection.room(), stream_id, status, converted, end and !interim) catch |failure| {
        return send_error(connection, failure);
    };
    connection.output_len += written;
}

pub fn write_body(connection: *Connection, id: Id, octets: []const u8, end: bool) SendError!usize {
    const stream_id = try stream_of(id);
    const sent = connection.session.h2.write_data(connection.room(), stream_id, octets, end) catch |failure| {
        return send_error(connection, failure);
    };
    connection.output_len += sent.written;
    // RFC 9113 §6.9: no window, or no room for a frame, and nothing moved.
    if (sent.written == 0) return error.Blocked;
    return sent.consumed;
}

pub fn write_trailers(connection: *Connection, id: Id, fields: []const Field) SendError!void {
    const stream_id = try stream_of(id);
    var lines: [core.constants.field_count_max]h2.hpack.Field = undefined;
    const converted = try convert(fields, &lines);
    const written = connection.session.h2.write_trailers(connection.room(), stream_id, converted) catch |failure| {
        return send_error(connection, failure);
    };
    connection.output_len += written;
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
    return connection.session.h2.write_response(connection.room(), stream_id, continue_status, &.{}, false) catch |failure| {
        return send_error(connection, failure);
    };
}

/// RFC 9110 §15.2.1: 100 (Continue).
const continue_status: u16 = @intFromEnum(http.status.Code.@"continue");
