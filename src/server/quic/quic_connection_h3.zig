//! The h3 half of a server QUIC connection (decision 103): h3's events turned into the server's
//! (RFC 9114 §4.1), and each response written as its request stream's octets. The stream carries
//! the frames the connection keeps (decision 79) and runs of the caller's content, which QUIC
//! reads by offset through the stream provider until the peer acknowledges them (decision 57).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const quic = @import("quic");
const h3 = @import("h3");
const quic_deadline = @import("quic_deadline.zig");
const quic_body = @import("quic_body.zig");
const quic_sends = @import("quic_sends.zig");
const http = @import("http");
const constants = @import("../constants.zig");
const event = @import("../event.zig");
const quic_request = @import("quic_request.zig");
const quic_connection = @import("quic_connection.zig");
const internal = @import("quic_connection_internal.zig");
const quic_coding = @import("quic_coding.zig");
const quic_continue = @import("quic_continue.zig");
const coding_rules = @import("../coding/coding_rules.zig");
const coding_fields = @import("../coding/coding_fields.zig");

const QuicConnection = quic_connection.QuicConnection;
const Request = quic_request.Request;
const SendError = quic_connection.SendError;
const Field = quic_connection.Field;
const Number = event.Number;
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
/// a response that is done or a stream the peer stopped, writes the 100 (Continue) a request is
/// owed, and frees each record whose stream closed. A connection shut down ends once it holds
/// none.
pub fn settle(connection: *QuicConnection) void {
    if (connection.closed or connection.stopped) return;
    // A 100 (Continue) that finds no room in this pass sets it again (`quic_continue.zig`).
    connection.continue_owed = false;
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
            // Each way a request ends gave its encoder back, and each way its stream's receiving
            // part ends stopped the wait for its content.
            assert(record.coded == null);
            assert(!quic_body.waits(connection, record));
            quic_sends.forget(connection, record);
            record.in_use = false;
            return;
        },
    };
    quic_sends.look(connection, record, stream);
    switch (stream.sending.state) {
        // RFC 9000 §3.1: "Data Recvd" means the peer acknowledged every octet.
        .data_recvd => if (!record.over) end(connection, record, .done),
        // RFC 9000 §3.5: the peer's STOP_SENDING reset the stream, whose octets are read no more.
        // RFC 9114 §4.1.1: that is the client cancelling its request, which the limit counts.
        .reset_sent, .reset_recvd => if (!record.over) {
            end(connection, record, .{ .cancelled = .peer_reset });
            if (!count_peer_reset(connection)) return;
        },
        .ready, .send, .data_sent => {},
    }
    if (quic.connection_stream_acknowledged.acknowledged_end(&connection.transport, id)) |acknowledged| {
        const freed = record.response.release_below(@min(acknowledged, record.response.end));
        // A coded response's runs are its ring's, which frees what the peer acknowledged.
        if (record.coded) |*coded| coded.ring.free(freed);
    }
    quic_coding.go_on(connection, record);
    quic_continue.write(connection, record, stream);
}

/// Counts one request stream the client opened and then cancelled, in the period the latest
/// instant falls in, and returns whether the connection goes on: past the limit it closes
/// (decision 110 as amended). A client cancels with a RESET_STREAM, or with a STOP_SENDING that
/// stops its response (RFC 9114 §4.1.1). Either cost the application a request's work, which
/// CVE-2023-44487 made the peer's to spend at line rate.
fn count_peer_reset(connection: *QuicConnection) bool {
    const now_ns = connection.last_ns;
    assert(now_ns >= connection.peer_reset_period_start_ns);
    if (now_ns - connection.peer_reset_period_start_ns >= constants.quic_peer_reset_rate_period_ns) {
        connection.peer_reset_period_start_ns = now_ns;
        connection.peer_resets = 0;
    }
    // RFC 9114 §10.5: an endpoint SHOULD track the use of features that cost it work and set
    // limits on it, and "MAY treat activity that is suspicious as a connection error of type
    // H3_EXCESSIVE_LOAD".
    if (connection.peer_resets == constants.quic_peer_reset_rate_max) {
        connection.peer_resets_passed = true;
        const failed = connection.h3.fail(&connection.transport, h3.constants.error_excessive_load);
        assert(failed == error.ConnectionFailed);
        internal.fail(connection);
        return false;
    }
    connection.peer_resets += 1;
    return true;
}

pub fn end(connection: *QuicConnection, record: *Request, kind: @FieldType(quic_request.Ending, "kind")) void {
    assert(!record.over);
    record.over = true;
    quic_coding.give_back(connection, record);
    connection.owed.push(.{ .kind = kind, .id = record.stream_id });
}

/// Reads h3's events until one means something to the caller, and returns it, or null.
pub fn read_event(connection: *QuicConnection, now_ns: u64) quic_connection.Error!?event.Event {
    // Bounded: every event reads at least one octet the pool holds, or ends a stream.
    for (0..constants.quic_events_per_read_max) |_| {
        const read = connection.h3.receive(&connection.transport, &connection.body, now_ns) catch {
            internal.fail(connection);
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
        .data => |data| on_data(connection, data),
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
    quic_deadline.on_request(connection);
    const record = connection.requests.take(arrived.stream_id) orelse {
        // RFC 9114 §4.1.1: a request cancelled "without performing any application processing"
        // is rejected, which the client may send again.
        connection.h3.cancel(&connection.transport, arrived.stream_id, h3.constants.error_request_rejected);
        return null;
    };
    quic_body.add(connection, record, connection.last_ns);
    const request = arrived.request;
    const reported: event.Event = .{
        .request = .{
            .id = event.id_of(arrived.stream_id),
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
    if (connection.config.encoders != null) record.asked = coding_rules.asked(connection.config.codings, reported.request);
    quic_continue.note(connection, record, reported.request);
    return reported;
}

/// RFC 9114 §7.2.1: a DATA frame's data is the request's content, which the body's rate counts.
fn on_data(connection: *QuicConnection, data: h3.connection.Data) ?event.Event {
    const record = reading(connection, data.stream_id) orelse return null;
    quic_body.count(connection, record, data.octets.len);
    return .{ .body = .{ .id = event.id_of(data.stream_id), .octets = data.octets, .end = false } };
}

fn on_trailers(connection: *QuicConnection, stream_id: u64) ?event.Event {
    stop_waiting(connection, stream_id);
    const record = reading(connection, stream_id) orelse return null;
    // RFC 9110 §6.5: a trailer section ends the request.
    record.ended = true;
    return .{ .trailers = .{ .id = event.id_of(stream_id), .fields = event.Fields.of(connection.h3.field_section()) } };
}

fn on_end(connection: *QuicConnection, stream_id: u64) ?event.Event {
    stop_waiting(connection, stream_id);
    const record = reading(connection, stream_id) orelse return null;
    record.ended = true;
    return .{ .body = .{ .id = event.id_of(stream_id), .octets = &.{}, .end = true } };
}

/// RFC 9114 §4.1.1: the client cancelled the request. The server resets its response too, so
/// nothing reads the caller's octets once `cancelled` says so.
fn on_reset(connection: *QuicConnection, stream_id: u64) ?event.Event {
    // A stream reset before its head was whole has no record, and still counts. One whose record
    // is over was counted when `settle` saw its STOP_SENDING, or was ended by the server.
    // RFC 9000 §3.2: a stream the client reset brings no more of the request.
    stop_waiting(connection, stream_id);
    const known = connection.requests.of(stream_id);
    if (known) |held| if (held.over) return null;
    if (!count_peer_reset(connection)) return null;
    const record = known orelse return null;
    connection.h3.cancel(&connection.transport, stream_id, h3.constants.error_request_cancelled);
    record.over = true;
    quic_coding.give_back(connection, record);
    return .{ .cancelled = .{ .id = event.id_of(stream_id), .reason = .peer_reset } };
}

/// RFC 9114 §4.1.2: h3 refused a malformed request and reset its stream.
fn on_refused(connection: *QuicConnection, stream_id: u64) ?event.Event {
    stop_waiting(connection, stream_id);
    const record = live(connection, stream_id) orelse return null;
    record.over = true;
    quic_coding.give_back(connection, record);
    return .{ .cancelled = .{ .id = event.id_of(stream_id), .reason = .refused } };
}

/// The request on `stream_id` brings no more content, whether the caller still hears of it or
/// not, so the wait for its body ends.
fn stop_waiting(connection: *QuicConnection, stream_id: u64) void {
    const record = connection.requests.of(stream_id) orelse return;
    quic_body.remove(connection, record);
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

pub fn respond(connection: *QuicConnection, id: Number, response: event.Response) SendError!void {
    const record = try writable(connection, id);
    const status = response.status;
    // RFC 9110 §15: a status code is three digits from 100 to 599; RFC 9114 §4.5: h3 has no 101.
    if (status < status_min or status > status_max or status == switching_protocols) return error.StatusInvalid;
    // RFC 9110 §15: one final response answers a request, after any interim ones.
    if (record.answered) return error.SectionOutOfOrder;
    var rewritten: coding_fields.Rewritten = undefined;
    const head = try quic_coding.plan_head(connection, record, response, &rewritten);
    errdefer if (head.slot) |slot| connection.config.encoders.?.give_back(slot);
    try build_section(connection, status, head.fields);
    try keep_head(connection, record, .response);
    const interim = status < final_min;
    if (!interim) record.answered = true;
    // RFC 9114 §4.1: only the final response ends the stream.
    try supply(connection, record, response.end and !interim);
    if (head.slot) |slot| record.coded = .{ .slot = slot };
    quic_continue.on_response(record, status);
}

const status_min: u16 = 100;
const status_max: u16 = 599;
const final_min: u16 = 200;
const switching_protocols: u16 = 101;

pub fn write_body(connection: *QuicConnection, id: Number, content: event.Content) SendError!usize {
    const record = try writable(connection, id);
    // RFC 9114 §4.1: DATA frames follow the final response's HEADERS frame.
    if (!record.answered) return error.SectionOutOfOrder;
    const octets = content.octets;
    const end_stream = content.end;
    if (octets.len == 0 and !end_stream) return 0;
    if (record.coded != null) return quic_coding.write_body(connection, record, content);
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

pub fn write_trailers(connection: *QuicConnection, id: Number, fields: []const Field) SendError!void {
    const record = try writable(connection, id);
    // RFC 9114 §4.1: a trailer section follows the final response.
    if (!record.answered) return error.SectionOutOfOrder;
    if (record.coded != null) try quic_coding.end_before_trailers(connection, record);
    const section = &connection.section;
    section.init();
    // RFC 9110 §5.4: a section has no predefined limit, so colibri's applies to what it sends.
    for (fields) |field| section.append(field.name, field.value) catch return error.SectionTooLarge;
    try keep_head(connection, record, .trailers);
    try supply(connection, record, true);
}

pub fn cancel(connection: *QuicConnection, id: Number) void {
    if (connection.stopped or connection.closed) return;
    const record = live(connection, id) orelse return;
    // RFC 9114 §4.1.1: a server that abandons a response after processing "SHOULD abort its
    // response stream with the error code H3_REQUEST_CANCELLED".
    connection.h3.cancel(&connection.transport, id, h3.constants.error_request_cancelled);
    record.over = true;
    quic_body.remove(connection, record);
    quic_coding.give_back(connection, record);
}

/// Answers request `id` with a 408 that ends its response, and returns whether its stream took
/// it. RFC 9110 §15.5.9: the server "did not receive a complete request message within the time
/// that it was prepared to wait".
pub fn respond_timeout(connection: *QuicConnection, id: Number) bool {
    respond(connection, id, .{ .status = @intFromEnum(http.status.Code.request_timeout), .end = true }) catch return false;
    return true;
}

/// Sends a GOAWAY naming the first request stream not taken, after which h3 refuses every later
/// one (RFC 9114 §5.2), and rejects each request whose head has not arrived whole.
pub fn shut_down(connection: *QuicConnection, now_ns: u64) void {
    if (connection.stopped) return;
    if (connection.started) {
        connection.h3.shutdown(&connection.transport, now_ns) catch return internal.fail(connection);
        reject_unread(connection);
    }
    finish_if_drained(connection);
}

/// Rejects each request stream that still waits for its head, on a connection that takes no more
/// requests. Such a stream is below the identifier the GOAWAY named, and the connection closes
/// without waiting for it, so its client could not tell whether the server took the request.
/// RFC 9114 §4.1.1: a request the server cancels "without performing any application
/// processing" is rejected, with H3_REQUEST_REJECTED, and the client may send it again. §5.2
/// lets a server reject requests below the GOAWAY's identifier "if these requests were not
/// processed".
fn reject_unread(connection: *QuicConnection) void {
    // Bounded: each pass rejects one stream, and h3 holds `request_streams_max` of them.
    for (0..h3.constants.request_streams_max) |_| {
        const wait = connection.h3.oldest_head_wait() orelse return;
        connection.h3.cancel(&connection.transport, wait.stream_id, h3.constants.error_request_rejected);
    }
}

/// The last request of a connection shut down is over, so QUIC closes with H3_NO_ERROR. RFC 9114
/// §5.2: once "all accepted requests ... have been processed", an endpoint "MAY initiate an
/// immediate closure", and "SHOULD use the H3_NO_ERROR error code".
fn finish_if_drained(connection: *QuicConnection) void {
    if (!connection.shutting_down or connection.stopped or !connection.requests.idle()) return;
    // RFC 9114 §5.2: the GOAWAY tells the client which requests the server did not take. QUIC
    // writes a CONNECTION_CLOSE alone once it owes one, so the close waits until the client
    // acknowledged the GOAWAY, and the drain deadline bounds that wait (decision 110 as amended).
    // A connection whose h3 never started has no stream to send one on.
    if (connection.started and !connection.h3.goaway_acknowledged(&connection.transport)) return;
    // RFC 9114 §4.1.1: the client may send a rejected request again, which it learns only from
    // the RESET_STREAM, and QUIC sends nothing but the close once it owes one. So the close also
    // waits until the client acknowledged every reset (decision 110 as amended).
    if (!quic.connection_stream_acknowledged.resets_acknowledged(&connection.transport)) return;
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
fn writable(connection: *QuicConnection, id: Number) SendError!*Request {
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
            internal.fail(connection);
            break :blk error.ConnectionClosed;
        },
        // A server opens no request stream, and h3 started before any request arrived.
        error.NotStarted, error.GoawayReceived, error.StreamsExhausted => unreachable,
    };
}

/// Tells QUIC how far the stream's octets reach, and that it ends there with `fin` (RFC 9000
/// §2.2).
pub fn supply(connection: *QuicConnection, record: *Request, fin: bool) SendError!void {
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
