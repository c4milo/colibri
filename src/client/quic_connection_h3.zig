//! The h3 half of a QUIC client connection (decision 100): exchanges written as request streams
//! through h3's send path, the streams' octets supplied to QUIC, and h3's events recorded in the
//! exchange whose stream they name (RFC 9114 §4.1).
//!
//! A request stream carries the HEADERS frame, then, when the request has content, one DATA frame
//! whose header the connection keeps with it (decision 79) and whose content is the exchange's.
//! QUIC reads them by offset and may read them again until the stream closes (RFC 9000 §3.1), so
//! an ended exchange holds its octets, and its `finished` event, until then.
const std = @import("std");
const assert = std.debug.assert;
const quic = @import("quic");
const h3 = @import("h3");
const constants = @import("constants.zig");
const event = @import("event.zig");
const slots_module = @import("slots.zig");
const response = @import("response.zig");
const quic_connection = @import("quic_connection.zig");

const QuicConnection = quic_connection.QuicConnection;
const Exchange = event.Exchange;
const Slot = slots_module.Slot;
const Indexing = h3.qpack.encoder.Indexing;
const StreamProvider = quic.stream.StreamProvider;

/// The frames of one request stream the connection keeps (decision 79).
pub const RequestStream = struct {
    /// The HEADERS frame, then the DATA frame's header when the request has content.
    prefix: [constants.request_prefix_len_max]u8,
    prefix_len: usize,
};

/// Writes the heads of the exchanges waiting, oldest first, so the streams open in the order
/// `request` took them (RFC 9000 §2.1).
pub fn write_requests(connection: *QuicConnection) void {
    // Bounded: each pass writes or ends an exchange, or stops.
    for (0..constants.exchanges_max) |_| {
        const slot = connection.slots.oldest(.queued) orelse return;
        if (!open(connection, slot)) return;
    }
}

/// Opens the stream of `slot`'s request, writes its frames and supplies them with the content to
/// QUIC. Returns whether the next exchange may be written: false when this one waits for the
/// server's stream limit (RFC 9000 §4.6).
fn open(connection: *QuicConnection, slot: *Slot) bool {
    const exchange = slot.exchange;
    var indexing: [constants.request_fields_max + pseudo_fields]Indexing = undefined;
    const lines = build_section(connection, exchange, &indexing) orelse {
        slots_module.end(slot, .invalid);
        return true;
    };
    const stream = &connection.streams[connection.slots.index_of(slot)];
    var writer = quic.core.Writer.init(&stream.prefix);
    const id = connection.h3.write_request(&connection.transport, &connection.section, indexing[0..lines], &writer) catch |failure| {
        return refused(connection, slot, failure);
    };
    // RFC 9114 §4.1: the content goes in DATA frames after the header section, here one.
    if (exchange.content.len > 0) h3.connection.write_data_header(exchange.content.len, &writer) catch unreachable;
    stream.prefix_len = writer.written().len;
    slot.stream_id = id;
    slot.stage = .sent;
    slot.holds_octets = true;
    // RFC 9000 §2.2: the stream ends with the last octet of the content, which carries FIN.
    const stream_len = stream.prefix_len + exchange.content.len;
    quic.connection_stream_send.supply(&connection.transport, .{ .value = id }, stream_len, true) catch unreachable;
    exchange.content_sent = exchange.content.len;
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
        error.ConnectionFailed => connection.fail(),
        // RFC 9114 §4.1.2 and §4.2.2: a request h3 would send malformed, or too large for the
        // server's SETTINGS_MAX_FIELD_SECTION_SIZE.
        else => slots_module.end(slot, .invalid),
    }
    return true;
}

/// The pseudo-header fields of a request (RFC 9114 §4.3.1): `:method`, `:scheme`, `:authority`
/// and `:path`.
const pseudo_fields: usize = 4;

/// Builds `exchange`'s field section in the connection's section, and how each line is written:
/// the pseudo-header fields first (RFC 9114 §4.3), then the caller's lines and the content-length
/// the client adds. Returns the line count, or null when the section does not fit.
fn build_section(connection: *QuicConnection, exchange: *const Exchange, indexing: *[constants.request_fields_max + pseudo_fields]Indexing) ?usize {
    const section = &connection.section;
    section.init();
    append_pseudo(connection, exchange, indexing) orelse return null;
    append_fields(section, exchange, indexing) orelse return null;
    var count = pseudo_fields + exchange.fields.len;
    var digits: [constants.content_length_digits_max]u8 = undefined;
    if (exchange.content_length(&digits)) |value| {
        section.append("content-length", value) catch return null;
        indexing[count] = .no_insert;
        count += 1;
    }
    assert(count == section.len());
    return count;
}

/// Appends the request's pseudo-header fields (RFC 9114 §4.3.1), `:path` never-indexed when the
/// caller marked it (RFC 9204 §4.5.4).
fn append_pseudo(connection: *QuicConnection, exchange: *const Exchange, indexing: []Indexing) ?void {
    const section = &connection.section;
    // RFC 9114 §4.3.1: `https` is the scheme of every request an h3 connection carries.
    const lines = [pseudo_fields]event.Field{
        .{ .name = ":method", .value = exchange.method },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = connection.config.authority },
        .{ .name = ":path", .value = exchange.path },
    };
    for (lines, 0..) |line, index| {
        section.append(line.name, line.value) catch return null;
        indexing[index] = .no_insert;
    }
    if (exchange.never_indexed.path) indexing[pseudo_fields - 1] = .never_indexed;
}

/// Appends the caller's field lines after the pseudo-header fields, each marked one written
/// never-indexed (RFC 9204 §4.5.4, §7.1.3).
fn append_fields(section: *h3.http.FieldSection, exchange: *const Exchange, indexing: []Indexing) ?void {
    const marked = exchange.never_indexed.fields;
    for (exchange.fields, 0..) |field, index| {
        section.append(field.name, field.value) catch return null;
        const never = marked.len > 0 and marked[index];
        indexing[pseudo_fields + index] = if (never) .never_indexed else .no_insert;
    }
}

/// The provider QUIC reads the request streams from: h3 serves its own streams, and the rest come
/// from the exchanges (decision 79).
pub fn provider(connection: *QuicConnection) StreamProvider {
    return connection.h3.provider(.{ .context = connection, .vtable = &vtable });
}

const vtable: quic.stream.stream_provider.VTable = .{ .read = read_request };

/// A request stream's octets from `offset`: its kept frames, then the exchange's content. Every
/// call at one offset answers the same octets, which RFC 9000 §2.2 asks of a retransmission.
fn read_request(context: *anyopaque, stream_id: u64, offset: u64, output: []u8) usize {
    const connection: *QuicConnection = @ptrCast(@alignCast(context));
    const slot = holding(connection, stream_id) orelse return 0;
    const stream = &connection.streams[connection.slots.index_of(slot)];
    const content = slot.exchange.content;
    const from: usize = @intCast(offset);
    if (from >= stream.prefix_len + content.len) return 0;
    var written: usize = 0;
    if (from < stream.prefix_len) {
        written = @min(output.len, stream.prefix_len - from);
        @memcpy(output[0..written], stream.prefix[from..][0..written]);
        // The output filled before the kept frames ended.
        if (written < stream.prefix_len - from) return written;
    }
    // The content follows the kept frames in the same call, as far as `output` holds.
    const content_from = from + written - stream.prefix_len;
    const len = @min(output.len - written, content.len - content_from);
    @memcpy(output[written..][0..len], content[content_from..][0..len]);
    return written + len;
}

/// The slot whose stream is `stream_id` and may still send its octets, or null: an exchange the
/// caller cancelled holds none, so QUIC reads nothing of its memory.
fn holding(connection: *QuicConnection, stream_id: u64) ?*Slot {
    for (&connection.slots.slots) |*slot| {
        if (slot.holds_octets and slot.stream_id == stream_id) return slot;
    }
    return null;
}

/// Releases the octets of every stream that closed: QUIC sends nothing on it again (RFC 9000
/// §3.1), so its exchange's `finished` event may go out.
pub fn release_closed(connection: *QuicConnection) void {
    for (&connection.slots.slots) |*slot| {
        if (!slot.holds_octets) continue;
        if (connection.transport.streams.lookup(.{ .value = slot.stream_id }) == .live) continue;
        slot.holds_octets = false;
    }
}

/// Reads every event h3 has, and records what each means for the exchange it names.
pub fn read_events(connection: *QuicConnection) void {
    // Bounded: every event reads at least one octet the pool holds, or ends a stream.
    for (0..constants.h3_events_per_read_max) |_| {
        const read = connection.h3.receive(&connection.transport, &connection.body) catch {
            // RFC 9114 §8: h3 failed the connection, and QUIC owes the CONNECTION_CLOSE.
            connection.fail();
            return;
        };
        record(connection, read orelse return);
    }
}

fn record(connection: *QuicConnection, h3_event: h3.connection.Event) void {
    switch (h3_event) {
        .response => |head| on_response(connection, head),
        .data => |data| on_data(connection, data),
        // RFC 9110 §6.5.1: a trailer section's fields are kept apart from the header section, and
        // the client reads none. The stream's end follows.
        .trailers, .settings => {},
        .end => |stream_id| end_stream(connection, stream_id, .response),
        .reset => |ended| on_reset(connection, ended),
        // RFC 9114 §4.1.2: colibri refused a response that broke the rules.
        .refused => |ended| end_stream(connection, ended.stream_id, .malformed),
        .goaway => |stream_id| on_goaway(connection, stream_id),
        // RFC 9114 §6.1: a client receives no request; h3 refuses one before it is an event.
        .request => unreachable,
    }
}

fn on_response(connection: *QuicConnection, head: h3.connection.Response) void {
    const slot = connection.slots.of_stream(head.stream_id) orelse return;
    // RFC 9114 §4.1: a client reads any number of interim responses before the final one.
    if (head.response.status.is_interim()) {
        slot.exchange.interims += 1;
        return;
    }
    const section = connection.h3.field_section();
    response.record_head(slot.exchange, head.response.status.code, section, first_regular(section)) catch too_large(connection, slot);
}

fn on_data(connection: *QuicConnection, data: h3.connection.Data) void {
    const slot = connection.slots.of_stream(data.stream_id) orelse return;
    response.append_body(slot.exchange, data.octets) catch too_large(connection, slot);
}

fn on_reset(connection: *QuicConnection, ended: h3.connection.Ended) void {
    // RFC 9114 §4.1.1: H3_REQUEST_REJECTED says the server processed none of the request, which
    // "can be retried".
    if (ended.error_code == h3.constants.error_request_rejected) return end_stream(connection, ended.stream_id, .refused);
    const slot = connection.slots.of_stream(ended.stream_id) orelse return;
    slot.exchange.error_code = @truncate(ended.error_code);
    slots_module.end(slot, .reset);
}

/// RFC 9114 §5.2: the server processes no request stream at or above `stream_id`, so each
/// exchange on one, and each not yet written, may go on another connection.
fn on_goaway(connection: *QuicConnection, stream_id: u64) void {
    connection.start_draining();
    for (&connection.slots.slots) |*slot| {
        const unprocessed = slot.stage == .sent and slot.stream_id >= stream_id;
        if (slot.stage == .queued or unprocessed) slots_module.end(slot, .refused);
    }
}

fn end_stream(connection: *QuicConnection, stream_id: u64, outcome: event.Outcome) void {
    const slot = connection.slots.of_stream(stream_id) orelse return;
    slots_module.end(slot, outcome);
}

/// The response did not fit the caller's memory: the exchange ends, and H3_REQUEST_CANCELLED
/// tells the server to send no more of it (RFC 9114 §4.1.1).
fn too_large(connection: *QuicConnection, slot: *Slot) void {
    cancel_stream(connection, slot.stream_id);
    slots_module.end(slot, .too_large);
}

/// Resets the stream of a request the client no longer needs (RFC 9114 §4.1.1).
pub fn cancel_stream(connection: *QuicConnection, stream_id: u64) void {
    connection.h3.cancel(&connection.transport, stream_id, h3.constants.error_request_cancelled);
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
    var exchanges: [3]Exchange = @splat(.{ .method = "GET", .path = "/" });
    for (&exchanges) |*exchange| _ = connection.slots.take(exchange).?;
    // Streams 0 and 4 are written; the third waits.
    for (connection.slots.slots[0..2], [_]u64{ 0, 4 }) |*slot, id| {
        slot.stage = .sent;
        slot.stream_id = id;
    }
    record(connection, .{ .goaway = 4 });
    try testing.expectEqual(.pending, exchanges[0].outcome);
    try testing.expectEqual(.refused, exchanges[1].outcome);
    try testing.expectEqual(.refused, exchanges[2].outcome);
    try testing.expect(connection.draining and connection.owed.draining);
}
