//! The h3 half of a server QUIC connection (decision 103): h3's events turned into the server's
//! (RFC 9114 §4.1), and each response written as its request stream's octets. The stream carries
//! the frames the connection keeps (decision 79) and runs of the caller's content, which QUIC
//! reads by offset through the stream provider until the peer acknowledges them (decision 57).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const quic = @import("quic");
const h3 = @import("h3");
const constants = @import("../constants.zig");
const event = @import("../event.zig");
const quic_request = @import("quic_request.zig");
const quic_connection = @import("quic_connection.zig");

const QuicConnection = quic_connection.QuicConnection;
const Request = quic_request.Request;
const SendError = quic_connection.SendError;
const Field = quic_connection.Field;
const Id = event.Id;
const StreamId = quic.stream.StreamId;
const Indexing = h3.qpack.encoder.Indexing;

/// RFC 9114 is HTTP/3, which RFC 9110 §2.5 numbers 3.0.
const version: event.Version = .{ .major = version_major, .minor = 0 };
const version_major: u8 = 3;

/// The digits of a status code (RFC 9110 §15).
const status_digits_len: usize = 3;

/// Every line of a response goes out without entering QPACK's dynamic table, so no request
/// stream waits on the encoder stream (RFC 9204 §2.1.2): `:status`, then the caller's lines.
const no_insert: [core.constants.field_count_max + 1]Indexing = @splat(.no_insert);

/// Brings each request up to date with its stream: drops the runs the peer acknowledged, reports
/// a response that is done or a stream the peer stopped, and frees each record whose stream
/// closed. A connection shut down ends once it holds none.
pub fn settle(connection: *QuicConnection) void {
    if (connection.closed or connection.stopped) return;
    for (&connection.requests.records) |*record| {
        if (record.in_use) settle_one(connection, record);
    }
    finish_if_drained(connection);
}

fn settle_one(connection: *QuicConnection, record: *Request) void {
    const id: StreamId = .{ .value = record.stream_id };
    const stream = switch (connection.transport.streams.lookup(id)) {
        .live => |stream| stream,
        .closed, .unopened => {
            // RFC 9000 §3: a stream closes once each part is finished. `settle` runs after every
            // datagram, and saw any reset of the response first, so one not over was acknowledged
            // whole.
            if (!record.over) {
                assert(record.finished);
                end(connection, record, .done);
            }
            record.in_use = false;
            return;
        },
    };
    switch (stream.sending.state) {
        // RFC 9000 §3.1: "Data Recvd" means the peer acknowledged every octet.
        .data_recvd => if (!record.over) end(connection, record, .done),
        // RFC 9000 §3.5: the peer's STOP_SENDING reset the stream, whose octets are read no more.
        .reset_sent, .reset_recvd => if (!record.over) end(connection, record, .cancelled),
        .ready, .send, .data_sent => {},
    }
    const acknowledged = quic.connection_stream_acknowledged.acknowledged_end(&connection.transport, id) orelse return;
    record.response.release_below(@min(acknowledged, record.response.end));
}

fn end(connection: *QuicConnection, record: *Request, kind: @FieldType(quic_request.Ending, "kind")) void {
    assert(!record.over);
    record.over = true;
    connection.owed.push(.{ .kind = kind, .id = record.stream_id });
}

/// Reads h3's events until one means something to the caller, and returns it, or null.
pub fn read_event(connection: *QuicConnection, now_ns: u64) quic_connection.Error!?event.Event {
    // Bounded: every event reads at least one octet the pool holds, or ends a stream.
    for (0..constants.quic_events_per_read_max) |_| {
        const read = connection.h3.receive(&connection.transport, &connection.body, now_ns) catch {
            connection.fail();
            connection.failure_owed = false;
            // RFC 9114 §8: h3 failed the connection, and QUIC owes the CONNECTION_CLOSE.
            return error.ConnectionFailed;
        };
        const h3_event = read orelse return null;
        if (report(connection, h3_event)) |reported| return reported;
    }
    return null;
}

/// The server's event for h3's, or null for one the caller does not see.
fn report(connection: *QuicConnection, h3_event: h3.connection.Event) ?event.Event {
    return switch (h3_event) {
        .request => |arrived| on_request(connection, arrived),
        .data => |data| if (reading(connection, data.stream_id)) |_|
            .{ .body = .{ .id = data.stream_id, .octets = data.octets, .end = false } }
        else
            null,
        .trailers => |stream_id| on_trailers(connection, stream_id),
        .end => |stream_id| on_end(connection, stream_id),
        .reset => |ended| on_reset(connection, ended.stream_id),
        .refused => |ended| on_refused(connection, ended.stream_id),
        // The client's SETTINGS and GOAWAY concern the connection alone, and colibri pushes
        // nothing a GOAWAY could limit (RFC 9114 §5.2).
        .settings, .goaway => null,
        // RFC 9114 §4.1: a server reads requests; h3 refuses a response before it is an event.
        .response => unreachable,
    };
}

fn on_request(connection: *QuicConnection, arrived: h3.connection.Request) ?event.Event {
    _ = connection.requests.take(arrived.stream_id) orelse {
        // RFC 9114 §4.1.1: a request cancelled "without performing any application processing"
        // is rejected, which the client may send again.
        connection.h3.cancel(&connection.transport, arrived.stream_id, h3.constants.error_request_rejected);
        return null;
    };
    const request = arrived.request;
    return .{
        .request = .{
            .id = arrived.stream_id,
            .method = request.method,
            .version = version,
            // RFC 9114 §4.4: CONNECT names an authority and no path.
            .target = request.path orelse request.authority.?,
            .scheme = request.scheme,
            .authority = request.authority,
            .path = request.path,
            .fields = event.Fields.of(connection.h3.field_section()),
            // RFC 9114 §4.1: h3 reports the request's end apart from its head, as a `body` event.
            .end = false,
        },
    };
}

fn on_trailers(connection: *QuicConnection, stream_id: u64) ?event.Event {
    const record = reading(connection, stream_id) orelse return null;
    // RFC 9110 §6.5: a trailer section ends the request.
    record.ended = true;
    return .{ .trailers = .{ .id = stream_id, .fields = event.Fields.of(connection.h3.field_section()) } };
}

fn on_end(connection: *QuicConnection, stream_id: u64) ?event.Event {
    const record = reading(connection, stream_id) orelse return null;
    record.ended = true;
    return .{ .body = .{ .id = stream_id, .octets = &.{}, .end = true } };
}

/// RFC 9114 §4.1.1: the client cancelled the request. The server resets its response too, so
/// nothing reads the caller's octets once `cancelled` says so.
fn on_reset(connection: *QuicConnection, stream_id: u64) ?event.Event {
    const record = live(connection, stream_id) orelse return null;
    connection.h3.cancel(&connection.transport, stream_id, h3.constants.error_request_cancelled);
    record.over = true;
    return .{ .cancelled = .{ .id = stream_id } };
}

/// RFC 9114 §4.1.2: h3 refused a malformed request and reset its stream.
fn on_refused(connection: *QuicConnection, stream_id: u64) ?event.Event {
    const record = live(connection, stream_id) orelse return null;
    record.over = true;
    return .{ .cancelled = .{ .id = stream_id } };
}

/// The record of a request the caller still hears of, or null.
fn live(connection: *QuicConnection, stream_id: u64) ?*Request {
    const record = connection.requests.of(stream_id) orelse return null;
    return if (record.over) null else record;
}

/// The record of a request whose content the caller still reads, or null.
fn reading(connection: *QuicConnection, stream_id: u64) ?*Request {
    const record = live(connection, stream_id) orelse return null;
    return if (record.ended) null else record;
}

pub fn respond(connection: *QuicConnection, id: Id, status: u16, fields: []const Field, end_stream: bool) SendError!void {
    const record = try writable(connection, id);
    // RFC 9110 §15: a status code is three digits from 100 to 599; RFC 9114 §4.5: h3 has no 101.
    if (status < status_min or status > status_max or status == switching_protocols) return error.StatusInvalid;
    // RFC 9110 §15: one final response answers a request, after any interim ones.
    if (record.answered) return error.SectionOutOfOrder;
    try build_section(connection, status, fields);
    try keep_head(connection, record, .response);
    const interim = status < final_min;
    if (!interim) record.answered = true;
    // RFC 9114 §4.1: only the final response ends the stream.
    try supply(connection, record, end_stream and !interim);
}

const status_min: u16 = 100;
const status_max: u16 = 599;
const final_min: u16 = 200;
const switching_protocols: u16 = 101;

pub fn write_body(connection: *QuicConnection, id: Id, octets: []const u8, end_stream: bool) SendError!usize {
    const record = try writable(connection, id);
    // RFC 9114 §4.1: DATA frames follow the final response's HEADERS frame.
    if (!record.answered) return error.SectionOutOfOrder;
    if (octets.len == 0 and !end_stream) return 0;
    if (octets.len > 0) {
        const pieces = &record.response;
        // RFC 9000 §3.1: a run leaves only once the peer acknowledges it, and a DATA frame takes two:
        // its header, which the connection keeps, and the caller's octets.
        if (pieces.runs_len + data_runs > pieces.runs.len) return error.Blocked;
        var writer = quic.core.Writer.init(pieces.kept_room());
        // RFC 9114 §7.2.1: the frame's header goes before its content, when the kept frames have room.
        connection.h3.write_data_header(record.stream_id, octets.len, &writer, connection.last_ns) catch return error.Blocked;
        pieces.add_kept(writer.written().len);
        pieces.add_caller(octets);
    }
    try supply(connection, record, end_stream);
    return octets.len;
}

/// The runs one DATA frame takes.
const data_runs: usize = 2;

pub fn write_trailers(connection: *QuicConnection, id: Id, fields: []const Field) SendError!void {
    const record = try writable(connection, id);
    // RFC 9114 §4.1: a trailer section follows the final response.
    if (!record.answered) return error.SectionOutOfOrder;
    const section = &connection.section;
    section.init();
    // RFC 9110 §5.4: a section has no predefined limit, so colibri's applies to what it sends.
    for (fields) |field| section.append(field.name, field.value) catch return error.SectionTooLarge;
    try keep_head(connection, record, .trailers);
    try supply(connection, record, true);
}

pub fn cancel(connection: *QuicConnection, id: Id) void {
    if (connection.stopped or connection.closed) return;
    const record = live(connection, id) orelse return;
    // RFC 9114 §4.1.1: a server that abandons a response after processing "SHOULD abort its
    // response stream with the error code H3_REQUEST_CANCELLED".
    connection.h3.cancel(&connection.transport, id, h3.constants.error_request_cancelled);
    record.over = true;
}

/// Sends a GOAWAY naming the first request stream not taken, after which h3 refuses every later
/// one (RFC 9114 §5.2).
pub fn shut_down(connection: *QuicConnection, now_ns: u64) void {
    if (connection.stopped or !connection.started) return;
    connection.h3.shutdown(&connection.transport, now_ns) catch return connection.fail();
    finish_if_drained(connection);
}

/// The last request of a connection shut down is over, so QUIC closes with H3_NO_ERROR. RFC 9114
/// §5.2: once "all accepted requests ... have been processed", an endpoint "MAY initiate an
/// immediate closure", and "SHOULD use the H3_NO_ERROR error code".
fn finish_if_drained(connection: *QuicConnection) void {
    if (!connection.shutting_down or connection.stopped or !connection.requests.idle()) return;
    connection.stopped = true;
    if (connection.transport.termination.state != .active) return;
    quic.connection_close.owe(&connection.transport, .{
        .layer = .application,
        .error_code = connection.h3.no_error_code(),
        // RFC 9000 §19.19: only a transport close carries the Frame Type field.
        .frame_type = null,
        .reason = "",
    });
}

/// The record of request `id`, whose response the caller may still write.
fn writable(connection: *QuicConnection, id: Id) SendError!*Request {
    // RFC 9000 §10.2 and RFC 9114 §8: a connection that closed or failed sends no response.
    if (connection.stopped or connection.closed) return error.ConnectionClosed;
    // RFC 9110 §3.4: a response answers a request the connection still holds.
    const record = live(connection, id) orelse return error.RequestUnknown;
    // RFC 9114 §4.1: nothing follows the frame that ended the response.
    if (record.finished) return error.SectionOutOfOrder;
    return record;
}

/// The response's `:status` and the caller's lines, in the connection's section.
fn build_section(connection: *QuicConnection, status: u16, fields: []const Field) SendError!void {
    const section = &connection.section;
    section.init();
    var digits: [status_digits_len]u8 = undefined;
    const written = std.fmt.bufPrint(&digits, "{d}", .{status}) catch unreachable;
    // RFC 9110 §5.4: a section has no predefined limit, so colibri's applies to what it sends.
    section.append(":status", written) catch return error.SectionTooLarge;
    // RFC 9110 §5.4: the same limit covers the caller's lines.
    for (fields) |field| section.append(field.name, field.value) catch return error.SectionTooLarge;
}

/// Writes the section as a HEADERS frame the response keeps: a head or a trailer section.
fn keep_head(connection: *QuicConnection, record: *Request, kind: enum { response, trailers }) SendError!void {
    const pieces = &record.response;
    const empty = pieces.runs_len == 0;
    if (!pieces.has_room()) return error.NoSpaceLeft;
    var writer = quic.core.Writer.init(pieces.kept_room());
    const section = &connection.section;
    const written = switch (kind) {
        .response => connection.h3.write_response(&connection.transport, record.stream_id, section, no_insert[0..section.len()], &writer, connection.last_ns),
        .trailers => connection.h3.write_trailers(&connection.transport, record.stream_id, section, &writer, connection.last_ns),
    };
    written catch |failure| return head_error(connection, failure, empty);
    pieces.add_kept(writer.written().len);
}

fn head_error(connection: *QuicConnection, failure: h3.connection.SendError, empty: bool) SendError {
    return switch (failure) {
        // A section that does not fit the room an empty response keeps never will.
        error.NoSpaceLeft => if (empty) error.SectionTooLarge else error.NoSpaceLeft,
        // RFC 9114 §4.2.2: the peer's SETTINGS_MAX_FIELD_SECTION_SIZE.
        error.FieldSectionTooLarge => error.SectionTooLarge,
        // RFC 9114 §4.1.2, §4.2: a field line h3 refuses to send, such as an uppercase name.
        error.MessageInvalid => error.FieldLineInvalid,
        error.ConnectionFailed => blk: {
            connection.fail();
            break :blk error.ConnectionClosed;
        },
        // A server opens no request stream, and h3 started before any request arrived.
        error.NotStarted, error.GoawayReceived, error.StreamsExhausted => unreachable,
    };
}

/// Tells QUIC how far the stream's octets reach, and that it ends there with `fin` (RFC 9000
/// §2.2).
fn supply(connection: *QuicConnection, record: *Request, fin: bool) SendError!void {
    const id: StreamId = .{ .value = record.stream_id };
    quic.connection_stream_send.supply(&connection.transport, id, record.response.end, fin) catch |failure| return switch (failure) {
        // RFC 9000 §3.5: the peer's STOP_SENDING reset the stream, which takes no more octets.
        error.NotWritable => error.RequestUnknown,
        // RFC 9000 §19.8: a stream reaches no further than 2^62-1.
        error.OffsetTooLarge => error.ContentLengthMismatch,
        error.NotReadable => unreachable,
    };
    if (fin) record.finished = true;
}

/// The provider QUIC reads the request streams from: h3 serves its own streams, and the rest come
/// from the responses (decision 79).
pub fn provider(connection: *QuicConnection) quic.stream.StreamProvider {
    return connection.h3.provider(.{ .context = connection, .vtable = &vtable });
}

const vtable: quic.stream.stream_provider.VTable = .{ .read = read_response };

fn read_response(context: *anyopaque, stream_id: u64, offset: u64, output: []u8) usize {
    const connection: *QuicConnection = @ptrCast(@alignCast(context));
    const record = connection.requests.of(stream_id) orelse return 0;
    return record.response.read(offset, output);
}
