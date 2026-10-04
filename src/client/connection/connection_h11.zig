//! The h11 half of a client connection (decision 100): exchanges written in the order `request`
//! took them, each head with its content before the next head (RFC 9112 §9.3.2), and each response
//! given to the oldest exchange awaiting one (RFC 9112 §9.2). h11's client pipelines as decision 88
//! rules, so an exchange after a POST waits for the POST's final response.
//!
//! h11 cannot end one exchange alone: a response the caller cancelled, or one whose content did not
//! fit, is read to its end and dropped, and the connection goes on. A cancel while the request's
//! content is going out ends the connection, because the server waits for the octets the head
//! declared (RFC 9112 §6.2).
const std = @import("std");
const assert = std.debug.assert;
const h11 = @import("h11");
const constants = @import("../constants.zig");
const connection_module = @import("connection.zig");
const internal = @import("connection_internal.zig");
const slots_module = @import("../slots.zig");
const response = @import("../response.zig");
const coding = @import("../coding.zig");
const event = @import("../event.zig");

const Connection = connection_module.Connection;
const HttpExchange = event.HttpExchange;
const Field = event.Field;
const Slot = slots_module.Slot;

/// Passes of the reading per octet of input: one that consumes it, and one that ends a response.
const passes_per_octet: usize = 2;

/// Reads responses from `plaintext` until an exchange ends or the octets run out, and returns the
/// octets taken.
pub fn receive(connection: *Connection, plaintext: []const u8) usize {
    const session = &connection.session.h11;
    var consumed: usize = 0;
    // Every pass consumes an octet or ends a response, and a response takes at least one octet,
    // so n octets take at most 2n passes, and one more finds them short.
    for (0..passes_per_octet * plaintext.len + 1) |_| {
        const received = session.receive(plaintext[consumed..], &.{}) catch {
            fail(connection);
            return consumed;
        };
        consumed += received.consumed;
        const h11_event = received.event orelse return consumed;
        if (record(connection, h11_event)) return consumed;
    }
    return consumed;
}

/// Records what h11's event means for the exchange it answers. Returns whether the caller is owed
/// an event, which `Connection.receive` reports before reading on.
fn record(connection: *Connection, h11_event: h11.connection.Event) bool {
    // RFC 9112 §9.2: a response answers the oldest request awaiting one, and h11 refuses one that
    // arrives with none outstanding, so an exchange awaits it.
    const slot = connection.slots.oldest_awaiting().?;
    switch (h11_event) {
        .interim => {
            // RFC 9110 §15.2: a client reads any number of interim responses before the final one.
            if (slot.stage == .sent) slot.exchange.interims += 1;
            return false;
        },
        .response => |head| return on_response(connection, slot, head.line.status.code),
        .data => |octets| {
            if (slot.stage == .dropping) return false;
            response.append_body(slot, octets) catch |failure| start_dropping(slot, response.outcome_of(failure));
            return false;
        },
        .end => return finish(connection, slot),
        // A client reads no request, and sends no CONNECT to be tunnelled (`check_request`).
        .request, .tunnel => unreachable,
    }
}

fn on_response(connection: *Connection, slot: *Slot, status: u16) bool {
    internal.note_alt_svc(connection, &connection.session.h11.section, 0);
    if (slot.stage == .sent) {
        const section = &connection.session.h11.section;
        response.record_head(slot, status, section, 0) catch |failure| {
            start_dropping(slot, response.outcome_of(failure));
        };
    }
    // A response without a body is read whole with its head (RFC 9112 §6.3).
    if (connection.session.h11.phase == .body) return false;
    return finish(connection, slot);
}

/// The content did not fit the caller's memory, or its coding is corrupt: the exchange ends with
/// `outcome`, and the rest of the response is read and dropped.
fn start_dropping(slot: *Slot, outcome: event.Outcome) void {
    slot.exchange.outcome = outcome;
    slots_module.drop(slot, true);
}

/// The response to `slot` ended. Returns whether the caller is owed an event.
fn finish(connection: *Connection, slot: *Slot) bool {
    if (slot.stage == .dropping) {
        slots_module.settle_drop(slot);
    } else {
        // Decision 101: coded content ends with its stream, or the exchange ends malformed.
        const outcome: event.Outcome = if (response.end_body(slot)) .response else |failure| response.outcome_of(failure);
        slots_module.end(slot, outcome);
    }
    // RFC 9112 §9.6: after a response that closes the connection, h11 reads and writes nothing
    // more, so no exchange left awaits a response and none waiting is written.
    if (connection.session.h11.phase == .closed) close(connection);
    return true;
}

/// RFC 9112 §9.6: the server closes the connection. The requests it never saw may go on another
/// connection, and it "SHOULD NOT assume" the ones written after the close were processed.
fn close(connection: *Connection) void {
    internal.start_draining(connection);
    connection.slots.end_all(.refused, .closed);
}

/// The response being read broke h11's rules, and the connection is over (RFC 9112 §8).
fn fail(connection: *Connection) void {
    const slot = connection.slots.oldest_awaiting();
    if (slot) |reading| {
        if (reading.stage == .sent) slots_module.end(reading, .malformed) else slots_module.settle_drop(reading);
    }
    internal.fail(connection);
}

/// The transport closed. A body that runs until the close ends with it (RFC 9112 §6.3 rule 8), and
/// a response cut short leaves its exchange `closed` (RFC 9112 §8).
pub fn transport_closed(connection: *Connection) void {
    const closed = connection.session.h11.transport_closed();
    const slot = connection.slots.oldest_awaiting() orelse return;
    if (closed.ended_body) _ = finish(connection, slot);
}

/// Cancels a written exchange. Its response is read and dropped, or, while its content is going
/// out, the connection ends: the server waits for what the head declared (RFC 9112 §6.2).
pub fn cancel(connection: *Connection, slot: *Slot) void {
    assert(slot.stage == .sent);
    if (slot.content_done()) {
        slots_module.drop(slot, false);
        return;
    }
    slots_module.release(slot);
    internal.fail(connection);
}

/// Writes exchanges in order while h11, the room and decision 88 allow: the rest of the content
/// being written, then the next head and its content.
pub fn write_requests(connection: *Connection) void {
    // Bounded: each pass finishes an exchange's request, or stops.
    for (0..constants.exchanges_max + 1) |_| {
        const slot = writing(connection) orelse (connection.slots.oldest(.queued) orelse return);
        if (!write_request(connection, slot)) return;
    }
}

/// The written exchange whose content is still going out, or null. h11 writes the next head only
/// after it, so there is one at most (RFC 9112 §9.3.2).
fn writing(connection: *Connection) ?*Slot {
    for (&connection.slots.slots) |*slot| {
        if (slot.stage == .sent and !slot.content_done()) return slot;
    }
    return null;
}

/// Writes what is left of `slot`'s request: its head, its content and its end. Returns whether the
/// next exchange may be written.
fn write_request(connection: *Connection, slot: *Slot) bool {
    if (slot.stage == .queued) {
        if (!write_head(connection, slot)) return false;
        // A request h11 refused ended its exchange, and the next one may go.
        if (slot.stage != .sent) return true;
    }
    write_content(connection, slot);
    if (!slot.content_done()) return false;
    const session = &connection.session.h11;
    // RFC 9112 §6.2: a body of a declared length ends with its last octet, and the next head may
    // follow.
    if (session.writer.open()) connection.output_len += session.write_end(internal.room(connection), &.{}) catch return false;
    return true;
}

/// Writes the head of `slot`'s request. Returns false when it must wait: for room, or for
/// decision 88 to let it follow the requests outstanding.
fn write_head(connection: *Connection, slot: *Slot) bool {
    var lines: [constants.request_fields_max]Field = undefined;
    var digits: [constants.content_length_digits_max]u8 = undefined;
    var offer: [coding.offer_len_max]u8 = undefined;
    const fields = request_fields(connection, slot, &lines, &digits, &offer) orelse {
        slots_module.end(slot, .invalid);
        return true;
    };
    const written = connection.session.h11.write_request(internal.room(connection), slot.exchange.method, slot.exchange.path, fields) catch |failure| {
        return refused(connection, slot, failure);
    };
    connection.output_len += written;
    slot.stage = .sent;
    return true;
}

/// What a refused head means for its exchange. Returns whether the exchange was settled.
fn refused(connection: *Connection, slot: *Slot, failure: h11.connection.SendError) bool {
    switch (failure) {
        // RFC 9112 §9.3.2: decision 88 holds the request back until the ones before it are
        // answered, or the pipeline is full.
        error.PipelineBlocked, error.PipelineFull => return false,
        // A head that does not fit an empty output never will.
        error.OutputTooSmall => if (connection.output_len > 0) return false else slots_module.end(slot, .invalid),
        // RFC 9112 §9.6: the server said it closes, so it never sees this request.
        error.ConnectionClosed => close(connection),
        // RFC 9112 §3 and RFC 9110 §5.5: a request h11 would put on the wire malformed.
        else => slots_module.end(slot, .invalid),
    }
    return true;
}

/// The field lines of `slot`'s request as h11 writes them: Host first, which RFC 9110 §7.2 asks
/// of a user agent, the caller's, then the Content-Length and the Accept-Encoding the client adds
/// (RFC 9110 §8.6, decision 101). Null when they pass `request_fields_max`.
fn request_fields(
    connection: *const Connection,
    slot: *Slot,
    lines: *[constants.request_fields_max]Field,
    digits: *[constants.content_length_digits_max]u8,
    offer: *[coding.offer_len_max]u8,
) ?[]const Field {
    const exchange = slot.exchange;
    if (exchange.fields.len + constants.added_fields_max > lines.len) return null;
    // RFC 9112 §3.2: "A client MUST send a Host header field in all HTTP/1.1 request messages."
    lines[0] = .{ .name = "Host", .value = connection.config.authority };
    @memcpy(lines[1..][0..exchange.fields.len], exchange.fields);
    var count = 1 + exchange.fields.len;
    if (exchange.content_length(digits)) |length| {
        lines[count] = .{ .name = "Content-Length", .value = length };
        count += 1;
    }
    if (coding.offer(connection.config.codings, .of(connection.config), slot, offer)) |value| {
        lines[count] = .{ .name = "Accept-Encoding", .value = value };
        count += 1;
    }
    return lines[0..count];
}

/// Writes as much of `slot`'s content as the room holds, which h11 takes whole (RFC 9112 §2.1).
fn write_content(connection: *Connection, slot: *Slot) void {
    const exchange = slot.exchange;
    const left = exchange.content.len - exchange.content_sent;
    const take = @min(left, internal.room(connection).len);
    if (take == 0) return;
    const written = connection.session.h11.write_body(internal.room(connection), exchange.content[exchange.content_sent..][0..take]) catch {
        // RFC 9112 §9.6: the connection closed, and no more of the body goes out.
        slot.content_stopped = true;
        return;
    };
    connection.output_len += written;
    exchange.content_sent += take;
    assert(exchange.content_sent <= exchange.content.len);
}
