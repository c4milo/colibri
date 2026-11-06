//! The h3 half of a QUIC client connection (decision 100): exchanges written as request streams
//! through h3's send path, the streams' octets supplied to QUIC, and h3's events recorded in the
//! response whose stream they name (RFC 9114 §4.1).
//!
//! A request stream carries the HEADERS frame, then, when the request has content, one DATA frame
//! for each piece, whose header the connection keeps with it (decision 79) and whose content is the
//! piece's: the request's whole body, or each piece of a streamed one (decision 153). QUIC reads
//! them by offset and may read them again until the stream closes (RFC 9000 §3.1), so an ended
//! exchange holds its octets, and its `finished` event, until then.
const std = @import("std");
const assert = std.debug.assert;
const quic = @import("quic");
const h3 = @import("h3");
const constants = @import("../constants.zig");
const event = @import("../event.zig");
const event_internal = @import("../event_internal.zig");
const slots_module = @import("../slots.zig");
const response_write = @import("../response_write.zig");
const coding = @import("../coding.zig");
const quic_connection = @import("quic_connection.zig");
const quic_streamed = @import("quic_connection_streamed.zig");
const internal = @import("quic_connection_internal.zig");

const QuicConnection = quic_connection.QuicConnection;
const Request = event.Request;
const Slot = slots_module.Slot;
const Indexing = h3.qpack.encoder.Indexing;

/// Writes the heads of the exchanges waiting at `now_ns`, oldest first, so the streams open in the
/// order `request` took them (RFC 9000 §2.1).
pub fn write_requests(connection: *QuicConnection, now_ns: u64) void {
    // Bounded: each pass writes or ends an exchange, or stops.
    for (0..constants.limits.requests_max) |_| {
        const slot = connection.slots.oldest(.queued) orelse return;
        if (!open(connection, slot, now_ns)) return;
    }
}

/// Opens the stream of `slot`'s request, writes its frames and supplies them with the content to
/// QUIC. Returns whether the next exchange may be written: false when this one waits for the
/// server's stream limit (RFC 9000 §4.6).
fn open(connection: *QuicConnection, slot: *Slot, now_ns: u64) bool {
    var indexing: [constants.limits.request_fields_max + pseudo_fields]Indexing = undefined;
    const lines = build_section(connection, slot, &indexing) orelse {
        slots_module.end(slot, .invalid);
        return true;
    };
    const stream = &connection.streams[connection.slots.index_of(slot)];
    var writer = quic.core.Writer.init(&stream.prefix);
    // RFC 9000 §4.1: a streamed response's content stays in QUIC, which gives no credit for it,
    // until the caller releases each piece (decision 153 ruling 7).
    const hold_data = slot.request.streamed.response;
    const id = connection.h3.write_request(&connection.transport, &connection.section, indexing[0..lines], hold_data, &writer, now_ns) catch |failure| {
        return refused(connection, slot, failure);
    };
    stream.prefix_len = writer.written().len;
    stream.supplied_end = stream.prefix_len;
    slot.stream_id = id;
    slot.stage = .sent;
    slot.holds_octets = true;
    // The stream just opened, so its sending part takes octets (RFC 9000 §3.1).
    quic_streamed.supply_piece(connection, slot, now_ns) catch unreachable;
    return true;
}

/// What a refused head means for its exchange. Returns whether the next exchange may be written.
fn refused(connection: *QuicConnection, slot: *Slot, failure: h3.connection.SendError) bool {
    switch (failure) {
        // RFC 9000 §4.6: the server's limit, or h3's slots, are taken: the exchange waits for the
        // server's MAX_STREAMS or a stream to close.
        error.StreamsExhausted => return false,
        // RFC 9114 §5.2: no request opens after a GOAWAY. `on_goaway` refused every exchange
        // not yet written when the GOAWAY arrived, so none is left to try.
        error.GoawayReceived => unreachable,
        // RFC 9114 §8: h3 failed the connection while it wrote.
        error.ConnectionFailed => internal.fail(connection),
        // RFC 9114 §4.1.2 and §4.2.2: a request h3 would send malformed, or too large for the
        // server's SETTINGS_MAX_FIELD_SECTION_SIZE.
        else => slots_module.end(slot, .invalid),
    }
    return true;
}

/// The pseudo-header fields of a request (RFC 9114 §4.3.1): `:method`, `:scheme`, `:authority`
/// and `:path`.
const pseudo_fields: usize = 4;

/// Builds `slot`'s field section in the connection's section, and how each line is written: the
/// pseudo-header fields first (RFC 9114 §4.3), then the caller's lines and the content-length and
/// accept-encoding the client adds (decision 101). Returns the line count, or null when the
/// section does not fit.
fn build_section(connection: *QuicConnection, slot: *Slot, indexing: *[constants.limits.request_fields_max + pseudo_fields]Indexing) ?usize {
    const request = slot.request;
    const section = &connection.section;
    section.init();
    append_pseudo(connection, request, indexing) orelse return null;
    append_fields(section, request, indexing) orelse return null;
    var count = pseudo_fields + request.headers.len;
    var digits: [constants.limits.content_length_digits_max]u8 = undefined;
    if (event_internal.content_length(request, &digits)) |value| {
        section.append("content-length", value) catch return null;
        indexing[count] = .no_insert;
        count += 1;
    }
    var offer: [coding.offer_len_max]u8 = undefined;
    if (coding.offer(connection.config.codings, .of(connection.config), slot, &offer)) |value| {
        section.append("accept-encoding", value) catch return null;
        indexing[count] = .no_insert;
        count += 1;
    }
    assert(count == section.len());
    return count;
}

/// Appends the request's pseudo-header fields (RFC 9114 §4.3.1), `:path` never-indexed when the
/// caller marked it (RFC 9204 §4.5.4).
fn append_pseudo(connection: *QuicConnection, request: *const Request, indexing: []Indexing) ?void {
    const section = &connection.section;
    // RFC 9114 §4.3.1: `https` is the scheme of every request an h3 connection carries.
    const lines = [pseudo_fields]event.Header{
        .{ .name = ":method", .value = request.method },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = connection.config.authority },
        .{ .name = ":path", .value = request.path },
    };
    for (lines, 0..) |line, index| {
        section.append(line.name, line.value) catch return null;
        indexing[index] = .no_insert;
    }
    if (request.never_indexed.path) indexing[pseudo_fields - 1] = .never_indexed;
}

/// Appends the caller's field lines after the pseudo-header fields, each marked one written
/// never-indexed (RFC 9204 §4.5.4, §7.1.3).
fn append_fields(section: *h3.http.FieldSection, request: *const Request, indexing: []Indexing) ?void {
    const marked = request.never_indexed.headers;
    for (request.headers, 0..) |field, index| {
        section.append(field.name, field.value) catch return null;
        const never = marked.len > 0 and marked[index];
        indexing[pseudo_fields + index] = if (never) .never_indexed else .no_insert;
    }
}

/// Notes that a response began on each written exchange whose stream holds a HEADERS frame's
/// header first, which h3 has not taken: a field section that fails to decode, waits for QPACK's
/// entries, or never arrives whole (RFC 9204 §2.2.1). Called as the connection ends its exchanges
/// (decision 124).
pub fn note_heads(connection: *QuicConnection) void {
    for (&connection.slots.slots) |*slot| {
        if (slot.stage != .sent or slot.response_began) continue;
        slot.response_began = headers_first(connection, slot.stream_id);
    }
}

/// Whether stream `stream_id` holds the header of a HEADERS frame first (RFC 9114 §7.1): its type
/// and its length.
fn headers_first(connection: *QuicConnection, stream_id: u64) bool {
    var window: [h3.constants.protocol.frame_header_len_max]u8 = undefined;
    const peeked = quic.connection_stream_read.peek(&connection.transport, .{ .value = stream_id }, &window) catch return false;
    var reader = h3.core.Reader.init(window[0..peeked.len]);
    const frame_type = h3.wire.varint.decode(&reader) catch return false;
    _ = h3.wire.varint.decode(&reader) catch return false;
    return frame_type.value == h3.constants.protocol.frame_headers;
}

/// Reads every event h3 has at `now_ns`, and records what each means for the exchange it names.
pub fn read_events(connection: *QuicConnection, now_ns: u64) void {
    // Bounded: every event reads at least one octet the pool holds, or ends a stream.
    for (0..constants.limits.h3_events_per_read_max) |_| {
        const read = connection.h3.receive(&connection.transport, &connection.body, now_ns) catch {
            // RFC 9114 §8: h3 failed the connection, and QUIC owes the CONNECTION_CLOSE.
            internal.fail(connection);
            return;
        };
        record(connection, read orelse return);
    }
}

fn record(connection: *QuicConnection, h3_event: h3.connection.Event) void {
    switch (h3_event) {
        .response => |head| on_response(connection, head),
        .data => |data| on_data(connection, data),
        // RFC 9114 §4.1: a trailer section comes last, and the stream's end follows.
        .trailers => |stream_id| on_trailers(connection, stream_id),
        .settings => {},
        .end => |stream_id| end_response(connection, stream_id),
        .reset => |ended| on_reset(connection, ended),
        // RFC 9114 §4.1.2: colibri refused a response that broke the rules.
        .refused => |ended| end_stream(connection, ended.stream_id, .malformed),
        .goaway => |stream_id| on_goaway(connection, stream_id),
        // RFC 9114 §6.1: a client receives no request; h3 refuses one before it is an event.
        .request => unreachable,
        .data_available => |held| on_piece(connection, held.stream_id, held.len),
    }
}

fn on_response(connection: *QuicConnection, head: h3.connection.Response) void {
    const slot = connection.slots.of_stream(head.stream_id) orelse return;
    // Decision 124: once a HEADERS frame arrived, the pool does not send the request again.
    slot.response_began = true;
    // RFC 9114 §4.1: a client reads any number of interim responses before the final one.
    if (head.response.status.is_interim()) {
        slot.response.interims += 1;
        return;
    }
    const section = connection.h3.field_section();
    response_write.record_head(slot, head.response.status.code, section, first_regular(section)) catch |failure| {
        return refuse(connection, slot, response_write.outcome_of(failure));
    };
    // Decision 153 ruling 7: a streamed response's head is an event of its own, and its content
    // comes in pieces, so no length is too large.
    if (slot.request.streamed.response) {
        slot.headers_owed = true;
        return;
    }
    // RFC 9114 §4.1.1: a content that cannot fit ends its stream with H3_REQUEST_CANCELLED at the
    // head (https://github.com/c4milo/colibri/issues/106).
    if (response_write.too_large_at_head(slot, head.response.status.code, section)) refuse(connection, slot, .too_large);
}

/// RFC 9110 §6.5.1: a trailer section's fields are kept apart from the header section, in the
/// response's `trailers` (decision 152).
fn on_trailers(connection: *QuicConnection, stream_id: u64) void {
    const slot = connection.slots.of_stream(stream_id) orelse return;
    const section = connection.h3.field_section();
    response_write.record_trailers(slot, section) catch |failure| refuse(connection, slot, response_write.outcome_of(failure));
}

fn on_data(connection: *QuicConnection, data: h3.connection.Data) void {
    const slot = connection.slots.of_stream(data.stream_id) orelse return;
    response_write.append_body(slot, data.octets) catch |failure| refuse(connection, slot, response_write.outcome_of(failure));
}

/// Content of a streamed response, which h3 left in QUIC (RFC 9000 §4.1): its first octets, as
/// many as `Response.body` holds, are the next piece. h3 copies them from QUIC straight into
/// `Response.body`, the one copy (decision 153 ruling 12). QUIC takes them when the caller releases
/// the piece, and h3 reads nothing more of the stream until then (decision 153 ruling 7).
fn on_piece(connection: *QuicConnection, stream_id: u64, len: u64) void {
    const slot = connection.slots.of_stream(stream_id) orelse {
        // No exchange reads the stream any more, so QUIC takes the content at once.
        connection.h3.release_data(&connection.transport, stream_id, len);
        return;
    };
    const copied = connection.h3.peek_data(&connection.transport, stream_id, response_write.piece_room(slot));
    response_write.hold_len(slot, copied);
}

/// The caller gave back the piece of exchange `id` its `Response.body` held: QUIC takes its
/// octets, which gives the server credit for them (RFC 9000 §4.1), and h3 reads the stream on.
pub fn release_body(connection: *QuicConnection, id: event.RequestId) void {
    // The pool releases only a piece the connection reported.
    const slot = connection.slots.of_id(id).?;
    const len = response_write.release_piece(slot);
    // A connection that ended holds no content for the piece.
    if (connection.stopped) return;
    // The exchange may have ended while the caller held the piece: RFC 9114 §5.2's GOAWAY refuses
    // a stream that h3 still reads, so QUIC takes the piece's octets all the same. h3 takes
    // nothing of a stream that was reset or closed since.
    connection.h3.release_data(&connection.transport, slot.stream_id, len);
    connection.read_owed = true;
}

/// The response ended whole. Decision 101: coded content ends with its stream, or the exchange
/// ends malformed. A request whose content has not all gone out needs none of the rest, so its
/// stream is reset (RFC 9114 §4.1.1), which would otherwise stay open.
fn end_response(connection: *QuicConnection, stream_id: u64) void {
    const slot = connection.slots.of_stream(stream_id) orelse return;
    if (!slot.content_done()) cancel_stream(connection, stream_id);
    const outcome: event.Result = if (response_write.end_body(slot)) .response else |failure| response_write.outcome_of(failure);
    slots_module.end(slot, outcome);
}

fn on_reset(connection: *QuicConnection, ended: h3.connection.Ended) void {
    // RFC 9114 §4.1.1: H3_REQUEST_REJECTED says the server processed none of the request, which
    // "can be retried".
    if (ended.error_code == h3.constants.protocol.error_request_rejected) return end_stream(connection, ended.stream_id, .refused);
    const slot = connection.slots.of_stream(ended.stream_id) orelse return;
    slot.response.error_code = @truncate(ended.error_code);
    slots_module.end(slot, .reset);
}

/// RFC 9114 §5.2: the server processes no request stream at or above `stream_id`, so each
/// exchange on one, and each not yet written, may go on another connection.
fn on_goaway(connection: *QuicConnection, stream_id: u64) void {
    internal.start_draining(connection);
    for (&connection.slots.slots) |*slot| {
        const unprocessed = slot.stage == .sent and slot.stream_id >= stream_id;
        if (slot.stage == .queued or unprocessed) slots_module.end(slot, .refused);
    }
}

fn end_stream(connection: *QuicConnection, stream_id: u64, outcome: event.Result) void {
    const slot = connection.slots.of_stream(stream_id) orelse return;
    slots_module.end(slot, outcome);
}

/// The response did not fit the caller's memory, or its coding is corrupt: the exchange ends with
/// `outcome`, and H3_REQUEST_CANCELLED tells the server to send no more of it (RFC 9114 §4.1.1).
fn refuse(connection: *QuicConnection, slot: *Slot, outcome: event.Result) void {
    cancel_stream(connection, slot.stream_id);
    slots_module.end(slot, outcome);
}

/// Resets the stream of a request the client no longer needs (RFC 9114 §4.1.1).
pub fn cancel_stream(connection: *QuicConnection, stream_id: u64) void {
    connection.h3.cancel(&connection.transport, stream_id, h3.constants.protocol.error_request_cancelled);
}

/// The index of the first regular field line of `section`, past the pseudo-header fields RFC
/// 9114 §4.3 places first.
fn first_regular(section: *const h3.http.FieldSection) u32 {
    var first: u32 = 0;
    // Bounded: the section holds `len()` lines.
    for (0..section.len()) |_| {
        const name = section.get(first).name;
        // RFC 9114 §4.3: a pseudo-header field's name starts with a colon.
        if (name.len == 0 or name[0] != ':') break;
        first += 1;
    }
    assert(first <= section.len());
    return first;
}

const testing = std.testing;
const support = @import("quic_test_support.zig");

test "RFC 9114 §5.2: a GOAWAY refuses the streams at or past its ID and those not yet written" {
    const connection = &support.connection;
    connection.slots.init();
    connection.owed = .{};
    connection.draining = false;
    const request: Request = .{ .method = "GET", .path = "/" };
    var responses: [3]event.Response = @splat(.{});
    for (&responses) |*response| _ = connection.slots.take(&request, response).?;
    // Streams 0 and 4 are written; the third waits.
    for (connection.slots.slots[0..2], [_]u64{ 0, 4 }) |*slot, id| {
        slot.stage = .sent;
        slot.stream_id = id;
    }
    record(connection, .{ .goaway = 4 });
    try testing.expectEqual(.pending, responses[0].result);
    try testing.expectEqual(.refused, responses[1].result);
    try testing.expectEqual(.refused, responses[2].result);
    try testing.expect(connection.draining and connection.owed.draining);
}

/// Where the pieces of the tests' streamed responses land: two octets, so the server's content
/// comes in more than one. Test-only.
threadlocal var piece: [piece_len]u8 = undefined;
const piece_len: usize = 2;

/// Starts a connection and writes a streamed GET to a server that holds its answer. Test-only.
fn start_streamed_get(exchange: *support.Exchange) !event.RequestId {
    try support.start(&support.alpn_h3, &support.alpn_h3, false);
    support.server_answers = false;
    exchange.* = .{ .request = .{ .method = "GET", .path = "/", .streamed = .{ .response = true } }, .response = .{ .body = &piece } };
    const id = try support.connection.request(&exchange.request, &exchange.response);
    try support.pump(support.rounds_default);
    try testing.expectEqual(1, support.answers_len);
    return id;
}

/// Moves datagrams until the exchange `id` finishes, and requires it to end `refused`. Test-only.
fn expect_refused(id: event.RequestId, exchange: *const support.Exchange) !void {
    try support.pump(support.rounds_default);
    try testing.expectEqual(id, support.find(.finished).?.finished.id);
    try testing.expectEqual(.refused, exchange.response.result);
}

test "RFC 9114 §5.2: content on a stream a GOAWAY refused goes to QUIC unread, so the exchange finishes" {
    var exchange: support.Exchange = undefined;
    const id = try start_streamed_get(&exchange);
    // The server refuses the stream in a GOAWAY, and answers it all the same.
    record(&support.connection, .{ .goaway = 0 });
    support.server_answers = true;
    // No exchange reads the content, and the stream closes only once QUIC took all of it.
    try expect_refused(id, &exchange);
    try testing.expectEqual(null, support.find(.body));
}

test "RFC 9114 §5.2: a piece held when a GOAWAY refuses its stream goes back to QUIC at its release" {
    var exchange: support.Exchange = undefined;
    const id = try start_streamed_get(&exchange);
    support.server_answers = true;
    try support.pump(support.rounds_default);
    try testing.expectEqual(id, support.find(.body).?.body.id);
    record(&support.connection, .{ .goaway = 0 });
    support.connection.release_body(id);
    try expect_refused(id, &exchange);
}

test "decision 153 ruling 12: h3 copies a streamed piece once, into `Response.body`, and not into the connection's buffer" {
    var exchange: support.Exchange = undefined;
    const id = try start_streamed_get(&exchange);
    @memset(&support.connection.body, untouched_octet);
    support.server_answers = true;
    try support.pump(support.rounds_default);
    try testing.expectEqual(id, support.find(.body).?.body.id);
    try testing.expectEqualStrings(support.answer_content[0..piece_len], exchange.response.body[0..exchange.response.body_len]);
    try testing.expect(std.mem.allEqual(u8, &support.connection.body, untouched_octet));
}

/// The octet the connection's buffer is filled with, which a streamed piece may not change.
/// Test-only.
const untouched_octet: u8 = 0xa5;
