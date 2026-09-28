//! The h2 half of a client connection (decision 100): exchanges written as streams through h2's
//! send path, and h2's events recorded in the exchange whose stream they name (RFC 9113 §8.1).
//!
//! Heads go out oldest first, so the stream identifiers follow the order `request` took the
//! exchanges (RFC 9113 §5.1.1), and each exchange's content follows its head as the windows allow
//! (§6.9). A response's interim heads are counted, its final head and content are written into the
//! exchange, and its trailer section is read and dropped: RFC 9110 §6.5.1 lets no trailer field
//! into the header section the caller's wanted values come from.
const std = @import("std");
const assert = std.debug.assert;
const http = @import("http");
const h2 = @import("h2");
const constants = @import("constants.zig");
const connection_module = @import("connection.zig");
const slots_module = @import("slots.zig");
const response = @import("response.zig");
const event = @import("event.zig");

const Connection = connection_module.Connection;
const Exchange = connection_module.Exchange;
const Slot = slots_module.Slot;

/// Reads frames from `plaintext` until an exchange ends or the connection owes the caller an
/// event, h2 needs more octets, or the replies h2 owes must be written first and `output` has no
/// room for them. Returns the octets taken.
pub fn receive(connection: *Connection, plaintext: []const u8, now_ns: u64) usize {
    const session = &connection.session.h2;
    var consumed: usize = 0;
    for (0..constants.frames_per_receive_max) |_| {
        const received = session.receive(plaintext[consumed..], now_ns) catch {
            // RFC 9113 §5.4.1: a connection error ends every exchange, and h2's GOAWAY goes out.
            connection.fail();
            return consumed;
        };
        consumed += received.consumed;
        if (received.consumed == 0) {
            // RFC 9113 §3.4, §6.5.3: h2 reads nothing more until what it owes is written, such as
            // the acknowledgment of the server's SETTINGS.
            if (!session.has_pending() or !connection.write_owed(now_ns)) return consumed;
            continue;
        }
        const h2_event = received.event orelse continue;
        if (record(connection, h2_event)) return consumed;
    }
    return consumed;
}

/// Records what h2's event means for the exchange it names. Returns whether the caller is owed an
/// event, which `Connection.receive` reports before reading on.
fn record(connection: *Connection, h2_event: h2.Event) bool {
    return switch (h2_event) {
        .response => |head| on_response(connection, head),
        .data => |data| on_data(connection, data),
        // RFC 9113 §8.1: a trailer section ends the stream. RFC 9110 §6.5.1: its fields are kept
        // apart from the header section, and the client reads none.
        .trailers => |trailers| end_response(connection, trailers.stream_id),
        .stream_reset => |reset| on_reset(connection, reset),
        // RFC 9113 §5.4.2, §8.1.1: colibri reset a stream whose response broke the rules.
        .stream_refused => |refusal| end_stream(connection, refusal.stream_id, .malformed),
        .goaway => |goaway| on_goaway(connection, goaway.last_stream_id),
        .settings_acknowledged, .settings_applied, .ping_acknowledged => false,
        // RFC 9113 §8.1: a client receives no request; h2 refuses one before it is an event.
        .request => unreachable,
    };
}

fn on_response(connection: *Connection, head: h2.connection.Response) bool {
    const slot = connection.slots.of_stream(head.stream_id) orelse return false;
    const exchange = slot.exchange;
    // RFC 9110 §15.2: a client reads any number of interim responses before the final one.
    if (head.response.status.is_interim()) {
        exchange.interims += 1;
        return false;
    }
    const section = connection.session.h2.field_section();
    response.record_head(exchange, head.response.status.code, section, first_regular(section)) catch {
        return too_large(connection, slot);
    };
    if (!head.end_stream) return false;
    return finish(connection, slot);
}

fn on_data(connection: *Connection, data: h2.connection.Data) bool {
    const slot = connection.slots.of_stream(data.stream_id) orelse return false;
    response.append_body(slot.exchange, data.payload) catch return too_large(connection, slot);
    if (!data.end_stream) return false;
    return finish(connection, slot);
}

fn on_reset(connection: *Connection, reset: h2.connection.StreamReset) bool {
    const slot = connection.slots.of_stream(reset.stream_id) orelse return false;
    // RFC 9113 §8.7: REFUSED_STREAM says the server processed none of the request, which may then
    // be sent again.
    if (reset.error_code == h2.constants.error_refused_stream) {
        slots_module.end(slot, .refused);
        return true;
    }
    slot.exchange.error_code = reset.error_code;
    slots_module.end(slot, .reset);
    return true;
}

/// RFC 9113 §6.8: the server processed no stream past `last_stream_id` and opens none, so each
/// exchange on one, and each not yet written, may go on another connection.
fn on_goaway(connection: *Connection, last_stream_id: u32) bool {
    connection.start_draining();
    for (&connection.slots.slots) |*slot| {
        const unprocessed = slot.stage == .sent and slot.stream_id > last_stream_id;
        if (slot.stage == .queued or unprocessed) slots_module.end(slot, .refused);
    }
    return true;
}

fn end_response(connection: *Connection, stream_id: u32) bool {
    const slot = connection.slots.of_stream(stream_id) orelse return false;
    return finish(connection, slot);
}

/// The response ended whole. A request whose content has not all gone out needs none of the rest,
/// so CANCEL closes its stream (RFC 9113 §8.1, §6.4), which would otherwise stay open.
fn finish(connection: *Connection, slot: *Slot) bool {
    if (!slot.content_done()) cancel_stream(connection, slot.stream_id);
    slots_module.end(slot, .response);
    return true;
}

fn end_stream(connection: *Connection, stream_id: u32, outcome: event.Outcome) bool {
    const slot = connection.slots.of_stream(stream_id) orelse return false;
    slots_module.end(slot, outcome);
    return true;
}

/// The response did not fit the caller's memory: the exchange ends, and CANCEL tells the server to
/// send no more of it (RFC 9113 §6.4).
fn too_large(connection: *Connection, slot: *Slot) bool {
    cancel_stream(connection, slot.stream_id);
    slots_module.end(slot, .too_large);
    return true;
}

/// Ends the stream of `slot` with CANCEL, and frees the slot: its caller cancelled it.
pub fn cancel(connection: *Connection, slot: *Slot) void {
    assert(slot.stage == .sent);
    cancel_stream(connection, slot.stream_id);
    slots_module.release(slot);
}

fn cancel_stream(connection: *Connection, stream_id: u32) void {
    // RFC 9113 §6.4: CANCEL says the stream is no longer needed. A stream h2 already closed needs
    // no reset.
    connection.session.h2.reset_stream(stream_id, h2.constants.error_cancel) catch |failure| {
        assert(failure == error.StreamNotSendable);
    };
}

/// The index of the first regular field line of `section`, past the pseudo-header fields RFC
/// 9113 §8.3 places first.
fn first_regular(section: *const http.FieldSection) u32 {
    var first: u32 = 0;
    // Bounded: the section holds `len()` lines.
    for (0..section.len()) |_| {
        const name = section.get(first).name;
        // RFC 9113 §8.3: a pseudo-header field's name starts with a colon.
        if (name.len == 0 or name[0] != ':') break;
        first += 1;
    }
    assert(first <= section.len());
    return first;
}

/// Writes the heads of the exchanges waiting, oldest first, then as much of each written
/// exchange's content as the windows and the room allow.
pub fn write_requests(connection: *Connection) void {
    // Bounded: each pass writes or ends an exchange, or stops.
    for (0..constants.exchanges_max) |_| {
        const slot = connection.slots.oldest(.queued) orelse break;
        if (!open(connection, slot)) break;
    }
    for (&connection.slots.slots) |*slot| {
        if (slot.stage == .sent and !slot.content_done()) write_content(connection, slot);
    }
}

/// Writes the head of `slot`'s request, which opens its stream. Returns whether the next exchange
/// may be written: false when this one waits for room or for the server's stream limit.
fn open(connection: *Connection, slot: *Slot) bool {
    const exchange = slot.exchange;
    var lines: [constants.request_fields_max]h2.hpack.Field = undefined;
    var indexing: [constants.request_fields_max]h2.connection.RequestIndexing = undefined;
    var digits: [constants.content_length_digits_max]u8 = undefined;
    const fields = request_fields(exchange, &lines, &indexing, &digits) orelse {
        slots_module.end(slot, .invalid);
        return true;
    };
    // RFC 9113 §8.3.1: `:scheme` is the target URI's, https over TLS (RFC 9110 §4.2.2).
    const scheme: []const u8 = if (connection.config.tls == null) "http" else "https";
    const head: h2.connection.Request_ = .{
        .method = exchange.method,
        .scheme = scheme,
        .path = exchange.path,
        .authority = connection.config.authority,
        // RFC 7541 §7.1.3: a value an intermediary must not index goes out never-indexed.
        .indexing = .{ .path = if (exchange.never_indexed.path) .never_indexed else .without_indexing },
    };
    const sent = connection.session.h2.write_request(connection.room(), head, fields, indexing[0..fields.len], exchange.content.len == 0) catch |failure| {
        return refused(connection, slot, failure);
    };
    connection.output_len += sent.written;
    slot.stream_id = sent.stream_id;
    slot.stage = .sent;
    return true;
}

/// What a refused head means for its exchange. Returns whether the next exchange may be written.
fn refused(connection: *Connection, slot: *Slot, failure: h2.connection.RequestError) bool {
    switch (failure) {
        // RFC 9113 §5.1.2: the server's limit, or colibri's slots, are taken: the exchange waits.
        error.PeerLimitReached, error.Full => return false,
        // A section that does not fit an empty output never will.
        error.OutputTooSmall => if (connection.output_len > 0) return false else slots_module.end(slot, .invalid),
        // RFC 9113 §6.8: no stream opens after a GOAWAY, so the server never saw the request.
        error.AfterGoawayReceived => slots_module.end(slot, .refused),
        // RFC 9113 §5.1.1: with no identifier left, the requests go on a new connection.
        error.IdentifiersExhausted => {
            slots_module.end(slot, .refused);
            connection.start_draining();
        },
        // RFC 9113 §8.3.1, §8.2: a request h2 would put on the wire malformed.
        error.MethodInvalid,
        error.SchemeMissing,
        error.PathMissing,
        error.PseudoHeaderInvalid,
        error.ConnectWithSchemeOrPath,
        error.ConnectWithoutAuthority,
        error.FieldLineInvalid,
        => slots_module.end(slot, .invalid),
    }
    return true;
}

/// The field lines of `exchange`'s request as h2 writes them, with the content-length the client
/// adds, and how each is written, or null when they pass `request_fields_max`.
fn request_fields(
    exchange: *const Exchange,
    lines: *[constants.request_fields_max]h2.hpack.Field,
    indexing: *[constants.request_fields_max]h2.connection.RequestIndexing,
    digits: *[constants.content_length_digits_max]u8,
) ?[]const h2.hpack.Field {
    if (exchange.fields.len + constants.added_fields_max > lines.len) return null;
    const marked = exchange.never_indexed.fields;
    for (exchange.fields, lines[0..exchange.fields.len], indexing[0..exchange.fields.len], 0..) |field, *line, *how, index| {
        line.* = .{ .name = field.name, .value = field.value };
        // RFC 7541 §7.1.3: a line the caller marked goes out never-indexed.
        const never = marked.len > 0 and marked[index];
        how.* = if (never) .never_indexed else .without_indexing;
    }
    var count = exchange.fields.len;
    if (exchange.content_length(digits)) |length| {
        lines[count] = .{ .name = "content-length", .value = length };
        indexing[count] = .without_indexing;
        count += 1;
    }
    return lines[0..count];
}

/// Writes as much of `slot`'s content as the windows and the room allow (RFC 9113 §6.9.1).
fn write_content(connection: *Connection, slot: *Slot) void {
    const content = slot.exchange.content;
    // Bounded: each pass writes a frame, or stops.
    for (0..content.len + 1) |_| {
        if (slot.content_done()) return;
        const exchange = slot.exchange;
        const sent = connection.session.h2.write_data(connection.room(), slot.stream_id, content[exchange.content_sent..], true) catch {
            // RFC 9113 §5.1: the stream is no longer one the client may send on.
            slot.content_stopped = true;
            return;
        };
        connection.output_len += sent.written;
        exchange.content_sent += sent.consumed;
        // RFC 9113 §6.9: no window, or no room for a frame.
        if (sent.written == 0) return;
    }
}
