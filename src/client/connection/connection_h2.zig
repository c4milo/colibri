//! The h2 half of a client connection (decision 100): exchanges written as streams through h2's
//! send path, and h2's events recorded in the response whose stream they name (RFC 9113 §8.1).
//!
//! Heads go out oldest first, so the stream identifiers follow the order `request` took the
//! exchanges (RFC 9113 §5.1.1), and each request's content follows its head as the windows allow
//! (§6.9). A response's interim heads are counted, its final head and content are written into the
//! `Response`, and its trailer section is read and dropped: RFC 9110 §6.5.1 lets no trailer field
//! into the header section the caller's wanted values come from.
const std = @import("std");
const assert = std.debug.assert;
const http = @import("http");
const h2 = @import("h2");
const constants = @import("../constants.zig");
const connection_module = @import("connection.zig");
const internal = @import("connection_internal.zig");
const connection_h2_streamed = @import("connection_h2_streamed.zig");
const connection_body = @import("connection_body.zig");
const slots_module = @import("../slots.zig");
const response_write = @import("../response_write.zig");
const coding = @import("../coding.zig");
const event = @import("../event.zig");
const event_internal = @import("../event_internal.zig");
const alt_svc = @import("../alt_svc.zig");

const Connection = connection_module.Connection;
const Slot = slots_module.Slot;

/// Reads frames from `plaintext` until an exchange ends or the connection owes the caller an
/// event, h2 needs more octets, or the replies h2 owes must be written first and `output` has no
/// room for them. Returns the octets taken.
pub fn receive(connection: *Connection, plaintext: []const u8, now_ns: u64) usize {
    const session = &connection.session.h2;
    var consumed: usize = 0;
    for (0..constants.limits.frames_per_receive_max) |_| {
        const header = note_head(connection, plaintext[consumed..]);
        const received = session.receive(plaintext[consumed..], now_ns) catch {
            // RFC 9113 §5.4.1: a connection error ends every exchange, and h2's GOAWAY goes out.
            internal.fail(connection);
            return consumed;
        };
        consumed += received.consumed;
        if (received.consumed == 0) {
            // RFC 9113 §3.4, §6.5.3: h2 reads nothing more until what it owes is written, such as
            // the acknowledgment of the server's SETTINGS.
            if (!session.has_pending() or !internal.write_owed(connection, now_ns)) return consumed;
            continue;
        }
        const h2_event = received.event orelse continue;
        if (record(connection, h2_event)) {
            // Decision 153: the frame's octets after a piece that `Response.body` holds wait for
            // the next call. h2 reads one frame a call, whose header `note_head` read.
            consumed -= held_back(connection, header.?, h2_event);
            return consumed;
        }
    }
    return consumed;
}

/// The octets of the frame just read that its event left for the next call: the tail of a DATA
/// frame's payload that did not fit `Response.body`, and the padding after it (RFC 9113 §6.1).
fn held_back(connection: *Connection, header: h2.frame.Header, h2_event: h2.Event) usize {
    const tail = &connection.tail;
    if (tail.len == 0) return 0;
    const payload_len = h2_event.data.payload.len;
    // RFC 9113 §6.1: a PADDED frame carries the Pad Length octet, the data, then the padding.
    const padded = h2.frame.has_flag(header, h2.constants.protocol.flag_padded);
    tail.skip_len = if (padded) header.length - pad_length_len - payload_len else 0;
    return tail.len + tail.skip_len;
}

/// RFC 9113 §6.1: the Pad Length field of a PADDED frame is one octet.
const pad_length_len: usize = 1;

/// Notes that a response began when `octets` start with the header of a HEADERS frame on the
/// stream of an exchange, before h2 reads the frame. A field block that fails to decode (RFC 7541
/// §6.1), or a frame that never arrives whole, still came (decision 124). Returns the frame's
/// header, or null when `octets` hold none whole.
fn note_head(connection: *Connection, octets: []const u8) ?h2.frame.Header {
    var reader = h2.core.Reader.init(octets);
    const header = h2.frame.read_header(&reader) catch return null;
    if (header.type != h2.constants.protocol.frame_type_headers) return header;
    const slot = connection.slots.of_stream(header.stream_id) orelse return header;
    slot.response_began = true;
    return header;
}

/// Records what h2's event means for the exchange it names. Returns whether the caller is owed an
/// event, which `Connection.receive` reports before reading on.
fn record(connection: *Connection, h2_event: h2.Event) bool {
    return switch (h2_event) {
        .response => |head| on_response(connection, head),
        .data => |data| on_data(connection, data),
        // RFC 9113 §8.1: a trailer section ends the stream.
        .trailers => |trailers| on_trailers(connection, trailers.stream_id),
        .stream_reset => |reset| on_reset(connection, reset),
        // RFC 9113 §5.4.2, §8.1.1: colibri reset a stream whose response broke the rules.
        .stream_refused => |refusal| end_stream(connection, refusal.stream_id, .malformed),
        .goaway => |goaway| on_goaway(connection, goaway.last_stream_id),
        .settings_acknowledged, .settings_applied, .ping_acknowledged => false,
        .alt_svc => |advertised| on_alt_svc(connection, advertised),
        // RFC 9113 §8.1: a client receives no request; h2 refuses one before it is an event.
        .request => unreachable,
    };
}

/// RFC 7838 §4: "Receiving an ALTSVC frame is semantically equivalent to receiving an Alt-Svc
/// header field" for the origin of its stream, or, on stream 0, for the origin it names. The
/// client keeps what it says as it keeps a response's Alt-Svc lines, and owes no event for it.
fn on_alt_svc(connection: *Connection, advertised: h2.connection.AltSvc) bool {
    // RFC 9114 §3.1.2: h3 cannot reach an "http" origin, which a cleartext connection serves.
    if (connection.config.tls == null) return false;
    const on_connection = advertised.stream_id == h2.constants.protocol.connection_stream_id;
    // RFC 7838 §4: "An association with an origin that the client does not consider
    // authoritative for the current connection MUST be ignored."
    if (on_connection and !alt_svc.names_origin(advertised.origin, connection.config.authority)) return false;
    const host = alt_svc.host_of(connection.config.authority);
    connection.alt_svc = alt_svc.parse(advertised.value, host) orelse return false;
    return false;
}

fn on_response(connection: *Connection, head: h2.connection.Response) bool {
    const slot = connection.slots.of_stream(head.stream_id) orelse return false;
    // RFC 9110 §15.2: a client reads any number of interim responses before the final one.
    if (head.response.status.is_interim()) {
        slot.response.interims += 1;
        return false;
    }
    const section = connection.session.h2.field_section();
    internal.note_alt_svc(connection, section, first_regular(section));
    response_write.record_head(slot, head.response.status.code, section, first_regular(section)) catch |failure| {
        return refuse(connection, slot, response_write.outcome_of(failure));
    };
    // Decision 153 ruling 7: a streamed response's head is an event of its own, and its content
    // comes in pieces, so no length is too large.
    if (slot.request.streamed.response) slot.headers_owed = true;
    if (!head.end_stream) {
        if (slot.headers_owed) return true;
        // RFC 9113 §8.1: a content that cannot fit ends its stream with CANCEL at the head
        // (https://github.com/c4milo/colibri/issues/106).
        if (response_write.too_large_at_head(slot, head.response.status.code, section)) return refuse(connection, slot, .too_large);
        return false;
    }
    return finish(connection, slot);
}

/// RFC 9110 §6.5.1: a trailer section's fields are kept apart from the header section, in the
/// response's `trailers` (decision 152). The section ends the response.
fn on_trailers(connection: *Connection, stream_id: u32) bool {
    const slot = connection.slots.of_stream(stream_id) orelse return false;
    const section = connection.session.h2.field_section();
    response_write.record_trailers(slot, section) catch |failure| return refuse(connection, slot, response_write.outcome_of(failure));
    return finish(connection, slot);
}

fn on_data(connection: *Connection, data: h2.connection.Data) bool {
    const slot = connection.slots.of_stream(data.stream_id) orelse return false;
    if (slot.request.streamed.response) return on_piece(connection, slot, data);
    response_write.append_body(slot, data.payload) catch |failure| return refuse(connection, slot, response_write.outcome_of(failure));
    if (!data.end_stream) return false;
    return finish(connection, slot);
}

/// A DATA frame of a streamed response: its payload is the next piece, and what does not fit
/// `Response.body` is the tail, after which END_STREAM ends the response (decision 153 ruling 7).
fn on_piece(connection: *Connection, slot: *Slot, data: h2.connection.Data) bool {
    if (data.payload.len == 0) return data.end_stream and finish(connection, slot);
    const tail_len = connection_body.hold(connection, slot, data.payload);
    connection.tail.ends = data.end_stream;
    // RFC 9113 §8.1: the response ends once the caller had the frame's last octet.
    if (tail_len == 0 and data.end_stream) return finish(connection, slot);
    return true;
}

fn on_reset(connection: *Connection, reset: h2.connection.StreamReset) bool {
    const slot = connection.slots.of_stream(reset.stream_id) orelse return false;
    // RFC 9113 §8.7: REFUSED_STREAM says the server processed none of the request, which may then
    // be sent again.
    if (reset.error_code == h2.constants.protocol.error_refused_stream) {
        slots_module.end(slot, .refused);
        return true;
    }
    slot.response.error_code = reset.error_code;
    slots_module.end(slot, .reset);
    return true;
}

/// RFC 9113 §6.8: the server processed no stream past `last_stream_id` and opens none, so each
/// exchange on one, and each not yet written, may go on another connection.
fn on_goaway(connection: *Connection, last_stream_id: u32) bool {
    internal.start_draining(connection);
    for (&connection.slots.slots) |*slot| {
        const unprocessed = slot.stage == .sent and slot.stream_id > last_stream_id;
        if (slot.stage == .queued or unprocessed) slots_module.end(slot, .refused);
    }
    return true;
}

/// The response ended whole. A request whose content has not all gone out needs none of the rest,
/// so CANCEL closes its stream (RFC 9113 §8.1, §6.4), which would otherwise stay open.
pub fn finish(connection: *Connection, slot: *Slot) bool {
    if (!slot.content_done()) cancel_stream(connection, slot.stream_id);
    // Decision 101: coded content ends with its stream, or the exchange ends malformed.
    const outcome: event.Result = if (response_write.end_body(slot)) .response else |failure| response_write.outcome_of(failure);
    slots_module.end(slot, outcome);
    return true;
}

fn end_stream(connection: *Connection, stream_id: u32, outcome: event.Result) bool {
    const slot = connection.slots.of_stream(stream_id) orelse return false;
    slots_module.end(slot, outcome);
    return true;
}

/// The response did not fit the caller's memory, or its coding is corrupt: the exchange ends with
/// `outcome`, and CANCEL tells the server to send no more of it (RFC 9113 §6.4).
fn refuse(connection: *Connection, slot: *Slot, outcome: event.Result) bool {
    cancel_stream(connection, slot.stream_id);
    slots_module.end(slot, outcome);
    return true;
}

/// Ends the stream of `slot` with CANCEL, and frees the slot: its caller cancelled it.
pub fn cancel(connection: *Connection, slot: *Slot) void {
    assert(slot.stage == .sent);
    cancel_stream(connection, slot.stream_id);
    slots_module.release(slot);
}

fn cancel_stream(connection: *Connection, stream_id: u64) void {
    // RFC 9113 §6.4: CANCEL says the stream is no longer needed. A stream h2 already closed needs
    // no reset.
    connection.session.h2.reset_stream(@intCast(stream_id), h2.constants.protocol.error_cancel) catch |failure| {
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

/// Writes the heads of the exchanges waiting, oldest first, and over TLS the DATA frame that fills
/// the record of the heads. `send_content` writes the rest of the content.
pub fn write_requests(connection: *Connection) void {
    // Bounded: each pass writes or ends an exchange, or stops.
    for (0..constants.limits.requests_max) |_| {
        const slot = connection.slots.oldest(.queued) orelse break;
        if (!open(connection, slot)) break;
    }
    for (&connection.slots.slots) |*slot| {
        if (slot.stage != .sent) continue;
        // Decision 153: a streamed request's pieces go out with no copy, so none fills a record.
        const fills = !slot.request.streamed.request and !slot.content_done() and !slot.trailers_next();
        if (fills) connection_h2_streamed.fill_record(connection, slot);
        if (slot.trailers_next()) write_trailers(connection, slot);
    }
}

comptime {
    // Decision 152: `check_request` refuses a trailer section past `field_section_size_max`. Each
    // line's 32 octets of that size hold its HPACK representation's own (RFC 7541 §6.2), so the
    // block fits h2's block buffer, and its frames fit an empty output.
    const section_max = h2.core.constants.limits.field_section_size_max;
    assert(h2.constants.limits.send_block_len_max >= section_max + section_max);
    assert(constants.limits.output_len >= section_max + constants.limits.frame_len_max);
}

/// Writes the trailer section of `slot`'s request after its last DATA frame, in a HEADERS frame
/// that ends the stream (RFC 9113 §8.1, decision 152).
fn write_trailers(connection: *Connection, slot: *Slot) void {
    const trailers = slot.request.trailers;
    var lines: [constants.limits.request_fields_max]h2.hpack.Field = undefined;
    // `request_fields` refused a request whose lines pass `request_fields_max`.
    assert(trailers.len <= lines.len);
    for (trailers, lines[0..trailers.len]) |field, *line| line.* = .{ .name = field.name, .value = field.value };
    const written = connection.session.h2.write_trailers(internal.room(connection), @intCast(slot.stream_id), lines[0..trailers.len]) catch |failure| {
        // `check_request` refused every line h2 refuses, and a section past
        // `field_section_size_max`, which an empty output holds whole (see the comptime block).
        // A stream the server reset or ended ended its exchange, so it is not `.sent`.
        assert(failure == error.OutputTooSmall and connection.output_len > 0);
        // The section goes out once `send` has taken what the output holds.
        return;
    };
    connection.output_len += written;
    slot.content_ended = true;
    // An empty last piece went out with the section.
    slot.piece_written();
}

/// Writes the head of `slot`'s request, which opens its stream. Returns whether the next exchange
/// may be written: false when this one waits for room or for the server's stream limit.
fn open(connection: *Connection, slot: *Slot) bool {
    const request = slot.request;
    var lines: [constants.limits.request_fields_max]h2.hpack.Field = undefined;
    var indexing: [constants.limits.request_fields_max]h2.connection.RequestIndexing = undefined;
    var digits: [constants.limits.content_length_digits_max]u8 = undefined;
    var offer: [coding.offer_len_max]u8 = undefined;
    const fields = request_fields(connection, slot, &lines, &indexing, &digits, &offer) orelse {
        slots_module.end(slot, .invalid);
        return true;
    };
    // RFC 9113 §8.3.1: `:scheme` is the target URI's, https over TLS (RFC 9110 §4.2.2).
    const scheme: []const u8 = if (connection.config.tls == null) "http" else "https";
    const head: h2.Connection.RequestHead = .{
        .method = request.method,
        .scheme = scheme,
        .path = request.path,
        .authority = connection.config.authority,
        // RFC 7541 §7.1.3: a value an intermediary must not index goes out never-indexed.
        .indexing = .{ .path = if (request.never_indexed.path) .never_indexed else .without_indexing },
        // RFC 9113 §6.9.1: a streamed response's stream credit goes back as the caller releases
        // each piece (decision 153 ruling 7).
        .hold_credit = request.streamed.response,
    };
    // RFC 9113 §8.1: a request with no content ends its stream with its HEADERS frame, as does a
    // streamed one whose only piece is an empty last one, unless a trailer section ends it.
    const ends = slot.ends_with_piece() and slot.piece.len == 0;
    const sent = connection.session.h2.write_request(internal.room(connection), head, fields, indexing[0..fields.len], ends) catch |failure| {
        return refused(connection, slot, failure);
    };
    connection.output_len += sent.written;
    slot.stream_id = sent.stream_id;
    slot.stage = .sent;
    if (ends) {
        slot.content_ended = true;
        slot.piece_written();
    }
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
            internal.start_draining(connection);
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

/// The field lines of `slot`'s request as h2 writes them, with the content-length, trailer, te and
/// accept-encoding the client adds (decisions 101 and 152), and how each is written, or null when they
/// pass `request_fields_max`.
fn request_fields(
    connection: *const Connection,
    slot: *Slot,
    lines: *[constants.limits.request_fields_max]h2.hpack.Field,
    indexing: *[constants.limits.request_fields_max]h2.connection.RequestIndexing,
    digits: *[constants.limits.content_length_digits_max]u8,
    offer: *[coding.offer_len_max]u8,
) ?[]const h2.hpack.Field {
    const request = slot.request;
    if (request.headers.len + request.trailers.len + constants.limits.added_fields_max > lines.len) return null;
    const marked = request.never_indexed.headers;
    for (request.headers, lines[0..request.headers.len], indexing[0..request.headers.len], 0..) |field, *line, *how, index| {
        line.* = .{ .name = field.name, .value = field.value };
        // RFC 7541 §7.1.3: a line the caller marked goes out never-indexed.
        const never = marked.len > 0 and marked[index];
        how.* = if (never) .never_indexed else .without_indexing;
    }
    var count = request.headers.len;
    if (event_internal.content_length(request, digits)) |length| {
        lines[count] = .{ .name = "content-length", .value = length };
        indexing[count] = .without_indexing;
        count += 1;
    }
    for (request.trailers) |field| {
        // RFC 9110 §6.6.2: a sender of trailer fields names each one in a Trailer header field.
        lines[count] = .{ .name = "trailer", .value = field.name };
        indexing[count] = .without_indexing;
        count += 1;
    }
    if (event_internal.adds_te(request, slot.response)) {
        // RFC 9110 §10.1.4: the client reads a trailer section. RFC 9113 §8.2.2: "trailers" is
        // the one TE value h2 allows.
        lines[count] = .{ .name = "te", .value = "trailers" };
        indexing[count] = .without_indexing;
        count += 1;
    }
    if (coding.offer(connection.config.codings, .of(connection.config), slot, offer)) |value| {
        lines[count] = .{ .name = "accept-encoding", .value = value };
        indexing[count] = .without_indexing;
        count += 1;
    }
    return lines[0..count];
}
