//! The h11 half of a client connection (decision 100): exchanges written in the order `request`
//! took them, each head with its content before the next head (RFC 9112 §9.3.2), and each response
//! given to the oldest exchange awaiting one (RFC 9112 §9.2). h11's client pipelines as decision 88
//! rules, so an exchange after a POST waits for the POST's final response.
//!
//! h11 cannot end one exchange alone: a response the caller cancelled, or one whose content did not
//! fit, is read to its end and dropped, and the connection goes on. A cancel while the request's
//! content is going out ends the connection, because the server waits for the octets the head
//! declared (RFC 9112 §6.2). A final response that ends, or that the client drops, while the
//! content is going out ends the connection too, and the rest of the content is not written (RFC
//! 9112 §9.5, decision 124). A drop is bounded (decision 146): it fails the connection when the
//! response closes the connection, when more content is left than `drop_len_max`, or when its time
//! runs out.
const std = @import("std");
const assert = std.debug.assert;
const h11 = @import("h11");
const constants = @import("../constants.zig");
const connection_module = @import("connection.zig");
const internal = @import("connection_internal.zig");
const connection_h11_streamed = @import("connection_h11_streamed.zig");
const connection_body = @import("connection_body.zig");
const slots_module = @import("../slots.zig");
const response_write = @import("../response_write.zig");
const coding = @import("../coding.zig");
const event = @import("../event.zig");
const event_internal = @import("../event_internal.zig");

const Connection = connection_module.Connection;
const Header = event.Header;
const Slot = slots_module.Slot;

/// Passes of the reading per octet of input: one that consumes it, and one that ends a response.
const passes_per_octet: usize = 2;

/// Reads responses from `plaintext` until an exchange ends or the octets run out, and returns the
/// octets taken.
pub fn receive(connection: *Connection, plaintext: []const u8, now_ns: u64) usize {
    const session = &connection.session.h11;
    // h11 requires each call's octets to start with every octet it left unconsumed. The caller
    // passes them again, so a call with none waits for that one.
    if (plaintext.len == 0 and connection.unread_len > 0) return 0;
    var consumed: usize = 0;
    defer connection.unread_len = plaintext.len - consumed;
    // A drop's time starts once its response is the one being read (decision 146).
    defer start_drop_time(connection, now_ns);
    // The octets left after a response that ended are the next response's.
    defer note_arrival(connection, plaintext.len - consumed);
    note_arrival(connection, plaintext.len);
    // Every pass consumes an octet or ends a response, and a response takes at least one octet,
    // so n octets take at most 2n passes, and one more finds them short.
    for (0..passes_per_octet * plaintext.len + 1) |_| {
        const received = session.receive(plaintext[consumed..], &.{}) catch {
            fail(connection);
            return consumed;
        };
        consumed += received.consumed;
        const h11_event = received.event orelse return consumed;
        if (record(connection, h11_event, now_ns)) {
            // Decision 153: the run's octets after a piece that `Response.body` holds are the
            // last h11 took, and wait for the next call.
            consumed -= connection.tail.len;
            return consumed;
        }
    }
    return consumed;
}

/// Notes that some of a response arrived when `left` octets wait to be read, whether or not h11
/// takes them yet. RFC 9112 §9.2: they answer the oldest request that awaits a response, so the
/// pool does not send that request again (decision 124).
fn note_arrival(connection: *Connection, left: usize) void {
    if (left == 0) return;
    const slot = connection.slots.oldest_awaiting() orelse return;
    slot.response_began = true;
}

/// Records what h11's event means for the exchange it answers. Returns whether the caller is owed
/// an event, which `Connection.receive` reports before reading on.
fn record(connection: *Connection, h11_event: h11.connection.Event, now_ns: u64) bool {
    // RFC 9112 §9.2: a response answers the oldest request awaiting one, and h11 refuses one that
    // arrives with none outstanding, so an exchange awaits it.
    const slot = connection.slots.oldest_awaiting().?;
    switch (h11_event) {
        .interim => {
            // RFC 9110 §15.2: a client reads any number of interim responses before the final one.
            if (slot.stage == .sent) slot.response.interims += 1;
            return false;
        },
        .response => |head| return on_response(connection, slot, head.line.status.code, now_ns),
        .data => |octets| {
            if (slot.stage == .dropping) {
                slot.dropped_len += octets.len;
                return end_drop_past_bound(connection, slot);
            }
            if (slot.request.streamed.response) return hold(connection, slot, octets);
            response_write.append_body(slot, octets) catch |failure| return start_dropping(connection, slot, response_write.outcome_of(failure), now_ns);
            return false;
        },
        .end => return on_end(connection, slot),
        // A client reads no request, and sends no CONNECT to be tunnelled (`check_request`).
        .request, .tunnel => unreachable,
    }
}

/// The response ended. RFC 9112 §7.1.2: a chunked body's trailer section goes to the response's
/// `trailers`, apart from its headers (RFC 9110 §6.5.1, decision 152).
fn on_end(connection: *Connection, slot: *Slot) bool {
    if (slot.stage == .sent) {
        response_write.record_trailers(slot, &connection.session.h11.trailers) catch |failure| {
            slot.response.result = response_write.outcome_of(failure);
            slots_module.drop(slot, true);
        };
    }
    return finish(connection, slot);
}

/// Holds `octets`, a run of a streamed response's content, as its next piece (decision 153).
/// Returns whether the caller is owed an event.
fn hold(connection: *Connection, slot: *Slot, octets: []const u8) bool {
    if (octets.len == 0) return false;
    _ = connection_body.hold(connection, slot, octets);
    return true;
}

fn on_response(connection: *Connection, slot: *Slot, status: u16, now_ns: u64) bool {
    internal.note_alt_svc(connection, &connection.session.h11.section, 0);
    if (slot.stage == .sent) {
        if (record_final(connection, slot, status, now_ns)) return true;
    }
    // A response without a body is read whole with its head (RFC 9112 §6.3).
    if (connection.session.h11.phase == .body) {
        // Decision 153 ruling 7: a streamed response's head is an event of its own.
        if (slot.headers_owed) return true;
        return slot.stage == .dropping and end_drop_past_bound(connection, slot);
    }
    return finish(connection, slot);
}

/// Records the final head of `slot`'s response. Returns whether the connection ended, which owes
/// the caller an event.
fn record_final(connection: *Connection, slot: *Slot, status: u16, now_ns: u64) bool {
    const section = &connection.session.h11.section;
    response_write.record_head(slot, status, section, 0) catch |failure| {
        return start_dropping(connection, slot, response_write.outcome_of(failure), now_ns);
    };
    // Decision 153 ruling 7: a streamed response comes in pieces, so no length is too large.
    if (slot.request.streamed.response) {
        slot.headers_owed = true;
        return false;
    }
    // RFC 9112 §9.3.1: "Connections can be closed at any time", so a content that cannot fit
    // ends the exchange and the connection at its head, and is never read
    // (https://github.com/c4milo/colibri/issues/106).
    if (connection.session.h11.phase == .body and response_write.too_large_at_head(slot, status, section)) {
        slots_module.end(slot, .too_large);
        internal.fail(connection);
        return true;
    }
    return false;
}

/// The content did not fit the caller's memory, or its coding is corrupt: the exchange ends with
/// `outcome`, and the rest of the response is read and dropped. Returns whether the connection
/// ended instead, which owes the caller an event.
fn start_dropping(connection: *Connection, slot: *Slot, outcome: event.Result, now_ns: u64) bool {
    if (!slot.content_done()) {
        // Decision 124 ruling 2: a response dropped while the content goes out ends the connection.
        // RFC 9112 §9.5 asks this when the server closes the connection. A server may also read
        // the whole content before it ends its response, so the client does not wait for that end.
        slots_module.end(slot, outcome);
        internal.fail(connection);
        return true;
    }
    slot.response.result = outcome;
    slots_module.drop(slot, true);
    start_drop_time(connection, now_ns);
    return end_drop_past_bound(connection, slot);
}

/// Fails the connection when the drop of `slot`'s response passes a bound of decision 146, and
/// returns whether it did, which owes the caller an event.
fn end_drop_past_bound(connection: *Connection, slot: *Slot) bool {
    assert(slot.stage == .dropping);
    if (!drop_past_bound(connection, slot)) return false;
    internal.fail(connection);
    return true;
}

/// Whether the drop of `slot`'s response gains nothing, or reads more content than
/// `drop_len_max` (decision 146). Only the response being read, with content still to come, is
/// judged: a response not yet begun is judged at its head.
fn drop_past_bound(connection: *Connection, slot: *const Slot) bool {
    const session = &connection.session.h11;
    if (connection.slots.oldest_awaiting() != slot or session.phase != .body) return false;
    // RFC 9112 §9.6: the server closes the connection after a response with the "close" option,
    // or an HTTP/1.0 response, and RFC 9112 §6.3 rule 8: content that runs until the close.
    if (session.close_after or session.reader.kind == .close_delimited) return true;
    const left: u64 = if (session.reader.kind == .fixed) session.reader.remaining else 0;
    return slot.dropped_len + left > constants.limits.drop_len_max;
}

/// Starts the time of the drop whose response is the one being read, unless it runs already or
/// the connection sets no limit (decision 146).
fn start_drop_time(connection: *Connection, now_ns: u64) void {
    const limit = connection.config.drop_ns orelse return;
    const slot = connection.slots.oldest_awaiting() orelse return;
    if (slot.stage != .dropping or slot.drop_until_ns != null) return;
    slot.drop_until_ns = now_ns +| limit;
}

/// The instant the drop being read runs out, or null for none (decision 146).
pub fn deadline_ns(connection: *Connection) ?u64 {
    const slot = connection.slots.oldest_awaiting() orelse return null;
    if (slot.stage != .dropping) return null;
    return slot.drop_until_ns;
}

/// Fails the connection when the drop being read ran out at `now_ns` (decision 146).
pub fn on_instant(connection: *Connection, now_ns: u64) void {
    const until = deadline_ns(connection) orelse return;
    if (now_ns < until) return;
    internal.fail(connection);
    assert(connection.slots.idle());
}

/// The response to `slot` ended. Returns whether the caller is owed an event.
fn finish(connection: *Connection, slot: *Slot) bool {
    if (slot.stage == .dropping) {
        slots_module.settle_drop(slot);
    } else {
        // Decision 101: coded content ends with its stream, or the exchange ends malformed.
        const outcome: event.Result = if (response_write.end_body(slot)) .response else |failure| response_write.outcome_of(failure);
        slots_module.end(slot, outcome);
    }
    if (connection.session.h11.phase == .closed) {
        // RFC 9112 §9.6: after a response that closes the connection, h11 reads and writes nothing
        // more, so no exchange left awaits a response and none waiting is written.
        close(connection);
    } else if (content_left(connection)) {
        // Decision 124 ruling 2: a final response that ends before the content went out ends the
        // connection. RFC 9112 §9.5 asks this of a response that shows the server closes the
        // connection: "cease transmitting the body and close its side of the connection". The rest
        // of the content is not written, and the connection ends as `cancel` ends it.
        internal.fail(connection);
    }
    return true;
}

/// Whether h11 still writes the content of the request whose response just ended. h11 writes a
/// head only after the content before it (RFC 9112 §9.3.2), so a body still open with no exchange
/// awaiting a response is that request's.
fn content_left(connection: *Connection) bool {
    return connection.session.h11.writer.open() and connection.slots.oldest_awaiting() == null;
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
/// a response cut short leaves its exchange `closed` (RFC 9112 §8). A streamed response that h11
/// read whole, whose end a held piece kept back, ended before the close (decision 153).
pub fn transport_closed(connection: *Connection) void {
    const session = &connection.session.h11;
    if (session.end_owed and !connection.tail.pending()) {
        // RFC 9112 §6.3: the body's last octet arrived, and the caller has every octet of it, so
        // the response is whole. h11 reports its end with no octets.
        const received = session.receive(&.{}, &.{}) catch unreachable;
        assert(received.event.? == .end);
        _ = on_end(connection, connection.slots.oldest_awaiting().?);
    }
    const closed = session.transport_closed();
    const slot = connection.slots.oldest_awaiting() orelse return;
    if (closed.ended_body) _ = finish(connection, slot);
}

/// Cancels a written exchange. Its response is read and dropped, or, while its content is going
/// out, the connection ends: the server waits for what the head declared (RFC 9112 §6.2).
pub fn cancel(connection: *Connection, slot: *Slot, now_ns: u64) void {
    assert(slot.stage == .sent);
    if (slot.content_done()) {
        slots_module.drop(slot, false);
        start_drop_time(connection, now_ns);
        _ = end_drop_past_bound(connection, slot);
        return;
    }
    slots_module.release(slot);
    internal.fail(connection);
}

/// Writes exchanges in order while h11, the room and decision 88 allow: the rest of the content
/// being written, then the next head and its content.
pub fn write_requests(connection: *Connection) void {
    // Bounded: each pass finishes an exchange's request, or stops.
    for (0..constants.limits.requests_max + 1) |_| {
        const slot = connection_h11_streamed.writing(connection) orelse (connection.slots.oldest(.queued) orelse return);
        if (!write_request(connection, slot)) return;
    }
}

/// Writes what is left of `slot`'s request: its head, its content and its end. Returns whether the
/// next exchange may be written.
fn write_request(connection: *Connection, slot: *Slot) bool {
    if (slot.stage == .queued) {
        if (!write_head(connection, slot)) return false;
        // A request h11 refused ended its exchange, and the next one may go.
        if (slot.stage != .sent) return true;
    }
    connection_h11_streamed.write_content(connection, slot);
    return connection_h11_streamed.end_content(connection, slot);
}

/// Writes the head of `slot`'s request. Returns false when it must wait: for room, or for
/// decision 88 to let it follow the requests outstanding.
fn write_head(connection: *Connection, slot: *Slot) bool {
    var lines: [constants.limits.request_fields_max]Header = undefined;
    var digits: [constants.limits.content_length_digits_max]u8 = undefined;
    var offer: [coding.offer_len_max]u8 = undefined;
    const fields = request_fields(connection, slot, &lines, &digits, &offer) orelse {
        slots_module.end(slot, .invalid);
        return true;
    };
    const written = connection.session.h11.write_request(internal.room(connection), slot.request.method, slot.request.path, fields) catch |failure| {
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
/// of a user agent, the caller's, then the Content-Length or Transfer-Encoding and the
/// Accept-Encoding the client adds (RFC 9110 §8.6, RFC 9112 §6.1, decision 101). Null when they
/// pass `request_fields_max`.
fn request_fields(
    connection: *const Connection,
    slot: *Slot,
    lines: *[constants.limits.request_fields_max]Header,
    digits: *[constants.limits.content_length_digits_max]u8,
    offer: *[coding.offer_len_max]u8,
) ?[]const Header {
    const request = slot.request;
    if (request.headers.len + constants.limits.added_fields_max > lines.len) return null;
    // RFC 9112 §3.2: "A client MUST send a Host header field in all HTTP/1.1 request messages."
    lines[0] = .{ .name = "Host", .value = connection.config.authority };
    @memcpy(lines[1..][0..request.headers.len], request.headers);
    var count = 1 + request.headers.len;
    if (event_internal.content_length(request, digits)) |length| {
        lines[count] = .{ .name = "Content-Length", .value = length };
        count += 1;
    }
    // RFC 9112 §7.1: a body whose length is not known in advance goes in the chunked coding, and
    // RFC 9112 §6.1 names it in Transfer-Encoding, in place of Content-Length (decision 153).
    if (event_internal.chunked(request)) {
        lines[count] = .{ .name = "Transfer-Encoding", .value = "chunked" };
        count += 1;
    }
    if (coding.offer(connection.config.codings, .of(connection.config), slot, offer)) |value| {
        lines[count] = .{ .name = "Accept-Encoding", .value = value };
        count += 1;
    }
    return lines[0..count];
}
