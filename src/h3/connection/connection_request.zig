//! What the peer sends on request streams (RFC 9114 §4.1, §6.1). Part of design §8 step 12.
//!
//! A message is one HEADERS frame, any number of DATA frames, and at most one more HEADERS frame
//! carrying trailers (§4.1). A client may read interim responses before the final one. Frames of
//! unknown types may come anywhere and are skipped (§9).
//!
//! A HEADERS frame is copied out of `quic` whole and taken only once QPACK decoded it (decision
//! 80). A section blocked on the dynamic table (RFC 9204 §2.2.1) stays in `quic` until the
//! decoder's insert count moves. Content goes straight from `quic` into the caller's buffer.
//!
//! A malformed message refuses its stream only (§4.1.2): colibri resets its side, asks the peer
//! to stop sending, and discards what still arrives. A frame out of order ends the connection
//! (§4.1).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const http = @import("http");
const qpack = @import("qpack");
const quic = @import("quic");
const constants = @import("../constants.zig");
const frame = @import("../frame.zig");
const message = @import("../message/message.zig");
const connection_module = @import("connection.zig");
const connection_local = @import("connection_local.zig");

const Reader = core.Reader;
const Writer = core.Writer;
const Connection = connection_module.Connection;
const Error = connection_module.Error;
const Event = connection_module.Event;
const StreamId = quic.stream.StreamId;
const QuicConnection = quic.Connection;
const stream_read = quic.connection_stream_read;

/// Where a stream's message is (RFC 9114 §4.1).
pub const Phase = enum {
    /// A HEADERS frame comes next: the request, or a response, interim or final.
    head,
    /// After the header section: DATA frames or the trailer section.
    content,
    /// After the trailer section: only the stream's end.
    trailers_read,
    /// colibri refused the stream, and discards what still arrives until the peer ends it.
    abandoned,
};

pub const RequestStream = struct {
    id: u64,
    phase: Phase = .head,
    /// Octets of the current DATA frame's payload not yet handed to the caller.
    data_left: u64 = 0,
    /// Octets of an unknown frame's payload not yet skipped (§9).
    skip_left: u64 = 0,
    /// The content-length the header section carried, and the DATA octets that arrived, which
    /// §4.1.2 requires to be equal.
    content_length: ?u64 = null,
    content_received: u64 = 0,
    /// Whether the message can carry no content, so §4.1.2's content-length rule does not apply:
    /// a response to HEAD, or a 204 or 304 (RFC 9110 §6.4.1).
    no_content: bool = false,
    /// At a client, whether the request was HEAD (RFC 9110 §9.3.2).
    head_request: bool = false,
    /// The decoder's insert count when the stream's section blocked (RFC 9204 §2.2.1), or null.
    blocked_at: ?u64 = null,
    /// A Stream Cancellation the decoder owes but had no room to queue (RFC 9204 §2.2.2.2).
    cancel_owed: bool = false,
    /// Whether colibri has taken the stream's FIN (RFC 9000 §3.2), so its end comes next.
    fin_read: bool = false,
};

/// What one pass over a stream did.
const Step = union(enum) {
    /// It produced an event.
    event: Event,
    /// It took a frame header or payload, and the next may be whole too.
    again,
    /// Nothing more can be read on the stream now.
    wait,
};

pub const Requests = struct {
    slots: [constants.request_streams_max]?RequestStream,
    /// At a server, the index of the next client-initiated bidirectional stream no slot has seen
    /// (RFC 9000 §2.1). A client opens them in order.
    next_index: u64,
    /// The slot after the one that produced the last event, so streams take turns.
    turn: u32,

    pub fn init(requests: *Requests) void {
        requests.slots = @splat(null);
        requests.next_index = 0;
        requests.turn = 0;
    }

    pub fn find(requests: *Requests, stream_id: u64) ?*RequestStream {
        for (&requests.slots) |*slot| {
            if (slot.*) |*held| {
                if (held.id == stream_id) return held;
            }
        }
        return null;
    }

    pub fn free_slot(requests: *Requests) ?*?RequestStream {
        for (&requests.slots) |*slot| {
            if (slot.* == null) return slot;
        }
        return null;
    }

    fn release(requests: *Requests, stream_id: u64) void {
        for (&requests.slots) |*slot| {
            if (slot.*) |held| {
                if (held.id == stream_id) slot.* = null;
            }
        }
    }
};

/// Gives a slot to each request stream a client opened since the last call, at a server. After
/// colibri's GOAWAY, a stream at or above the ID it named is rejected (§5.2).
pub fn accept(connection: *Connection, transport: *QuicConnection) Error!void {
    if (connection.options.role != .server) return;
    const requests = &connection.requests;
    // Bounded by the slots: a client inside colibri's limit never has more open.
    for (0..constants.request_streams_max) |_| {
        const id = StreamId.of(.client, .bidirectional, requests.next_index);
        switch (transport.streams.lookup(id)) {
            .unopened => return,
            .closed => {},
            .live => {
                const slot = requests.free_slot() orelse return;
                slot.* = .{ .id = id.value };
                // §5.2: "Requests or pushes with the indicated identifier or greater are
                // rejected", which §4.1.1 does with H3_REQUEST_REJECTED.
                const limit = connection.goaway_sent orelse std.math.maxInt(u64);
                if (id.value >= limit) refuse_stream(connection, transport, &slot.*.?, constants.error_request_rejected);
            },
        }
        requests.next_index += 1;
    }
}

/// Reads the request streams in turn, a stream QPACK can now decode first, and returns the first
/// event one produces.
pub fn step(connection: *Connection, transport: *QuicConnection, body: []u8) Error!?Event {
    const requests = &connection.requests;
    // Decision 74: a stream whose entries arrived goes first, which is also what a decoder whose
    // list of blocked streams filled asks for.
    if (connection.decoder.ready_stream()) |id| {
        if (requests.find(id)) |ready| {
            ready.blocked_at = null;
            if (try step_stream(connection, transport, ready, body)) |event| return event;
        }
    }
    const count = constants.request_streams_max;
    for (0..count) |offset| {
        const index: u32 = @intCast((requests.turn + offset) % count);
        const request = if (requests.slots[index]) |*held| held else continue;
        const event = try step_stream(connection, transport, request, body) orelse continue;
        requests.turn = @intCast((index + 1) % count);
        return event;
    }
    return null;
}

/// Reads one stream's frames until one produces an event or none is whole.
fn step_stream(connection: *Connection, transport: *QuicConnection, request: *RequestStream, body: []u8) Error!?Event {
    if (request.cancel_owed) owe_cancel(connection, request);
    // A blocked section decodes no sooner than the decoder's insert count moves.
    if (request.blocked_at) |at| {
        if (at == connection.decoder.table.insert_count()) return null;
        request.blocked_at = null;
    }
    // Bounded: each pass takes a frame header, a payload or part of one, or returns.
    for (0..constants.request_frames_per_call_max) |_| {
        switch (try advance(connection, transport, request, body)) {
            .event => |event| return event,
            .wait => return null,
            .again => {},
        }
    }
    return null;
}

fn advance(connection: *Connection, transport: *QuicConnection, request: *RequestStream, body: []u8) Error!Step {
    const id: StreamId = .{ .value = request.id };
    // The peer's code is read before the reset is reported, which forgets the stream.
    if (stream_read.reset_code(transport, id)) |code| return on_reset(connection, transport, request, code);
    if (request.phase == .abandoned) return discard(connection, transport, request);
    if (request.data_left > 0) return read_data(connection, transport, request, body);
    if (request.skip_left > 0) return skip(connection, transport, request);
    if (request.fin_read) return on_end(connection, transport, request);
    return read_frame(connection, transport, request);
}

fn read_frame(connection: *Connection, transport: *QuicConnection, request: *RequestStream) Error!Step {
    const id: StreamId = .{ .value = request.id };
    const window = connection.scratch[0..constants.frame_header_len_max];
    const peeked = stream_read.peek(transport, id, window) catch return on_closed(connection, request);
    if (peeked.len == 0) {
        if (!peeked.fin) return .wait;
        request.fin_read = (stream_read.consume(transport, id, 0) catch unreachable).fin;
        return on_end(connection, transport, request);
    }
    var reader = Reader.init(window[0..peeked.len]);
    const header = frame.read_header(&reader) catch {
        // RFC 9114 §7.1: "When a stream terminates cleanly, if the last frame on the stream was
        // truncated, this MUST be treated as a connection error of type H3_FRAME_ERROR."
        if (peeked.fin) return connection.fail(transport, constants.error_frame_error);
        return .wait;
    };
    const header_len = peeked.len - reader.remaining_len();
    try check_sequence(connection, transport, request, header.frame_type);
    return switch (header.frame_type) {
        constants.frame_headers => read_headers(connection, transport, request, header, header_len),
        constants.frame_data => start_data(connection, request, transport, header, header_len),
        else => start_skip(transport, request, header, header_len),
    };
}

/// The rules of §4.1 and §7.2 about which frame may come next on a request stream.
fn check_sequence(connection: *Connection, transport: *QuicConnection, request: *const RequestStream, frame_type: u64) Error!void {
    // §7.2.3, §7.2.4, §7.2.6, §7.2.7 and §7.2.8: a control frame, or one of HTTP/2's types, on
    // a request stream is H3_FRAME_UNEXPECTED.
    if (!frame.permitted(frame_type, .request)) return connection.fail(transport, constants.error_frame_unexpected);
    switch (frame_type) {
        constants.frame_data, constants.frame_headers => {
            // §4.1: "a DATA frame before any HEADERS frame, or a HEADERS or DATA frame after the
            // trailing HEADERS frame, is considered invalid", which is H3_FRAME_UNEXPECTED.
            if (request.phase == .trailers_read) return connection.fail(transport, constants.error_frame_unexpected);
            if (frame_type == constants.frame_data and request.phase == .head) {
                return connection.fail(transport, constants.error_frame_unexpected);
            }
        },
        constants.frame_push_promise => switch (connection.options.role) {
            // §7.2.5: "A server MUST treat the receipt of a PUSH_PROMISE frame as a connection
            // error of type H3_FRAME_UNEXPECTED."
            .server => return connection.fail(transport, constants.error_frame_unexpected),
            // §7.2.5: a push ID larger than the client advertised is H3_ID_ERROR, and colibri
            // advertised none (decision 17).
            .client => return connection.fail(transport, constants.error_id_error),
        },
        else => {},
    }
}

/// Reads a HEADERS frame whole and decodes its field section (§7.2.2, RFC 9204 §4.5).
fn read_headers(connection: *Connection, transport: *QuicConnection, request: *RequestStream, header: frame.Header, header_len: usize) Error!Step {
    const id: StreamId = .{ .value = request.id };
    // RFC 9114 §10.5.1: a peer that sends a field section past the limit colibri advertised
    // risks "having the request or response being treated as malformed".
    if (header.length > constants.frame_length_max) return refuse(connection, transport, request, constants.error_message_error);
    const total = header_len + @as(usize, @intCast(header.length));
    const window = connection.scratch[0..total];
    const peeked = stream_read.peek(transport, id, window) catch return on_closed(connection, request);
    if (peeked.len < total) {
        // §7.1: a stream that ended inside a frame is H3_FRAME_ERROR.
        if (peeked.fin) return connection.fail(transport, constants.error_frame_error);
        return .wait;
    }
    connection.section.init();
    var reader = Reader.init(window[header_len..total]);
    var strings = Writer.init(&connection.strings);
    const outcome = connection.decoder.read_section(request.id, &reader, &strings, &connection.section) catch |failure|
        return on_decode_failure(connection, transport, request, failure);
    switch (outcome) {
        .decoded => {},
        // RFC 9204 §2.2.1: the section waits in `quic` until its entries arrive (decision 80).
        .blocked => {
            request.blocked_at = connection.decoder.table.insert_count();
            return .wait;
        },
        // Decision 74: the owed instructions go out first, and the section is read again.
        .owes_instructions => {
            try connection_local.flush_decoder(connection, transport);
            return if (connection.decoder.owed_len < connection.decoder.owed.len) .again else .wait;
        },
        // Decision 74: `step` reads the streams that are ready first.
        .read_ready_first => return .wait,
    }
    request.fin_read = (stream_read.consume(transport, id, total) catch unreachable).fin;
    return on_section(connection, transport, request);
}

fn on_decode_failure(connection: *Connection, transport: *QuicConnection, request: *RequestStream, failure: qpack.decoder.Error) Error!Step {
    return switch (failure) {
        // RFC 9204 §7.4: a string longer than colibri accepts refuses the stream alone.
        error.FieldTooLong => refuse(connection, transport, request, qpack.constants.error_decompression_failed),
        // RFC 9114 §4.2.2 and §10.5.1: a section past colibri's limits may be treated as
        // malformed, which §4.1.2 makes H3_MESSAGE_ERROR.
        error.SectionTooLarge, error.TooManyLines => refuse(connection, transport, request, constants.error_message_error),
        // RFC 9204 §2.2.3 and §6: every other failure to interpret a section is a connection
        // error of QPACK_DECOMPRESSION_FAILED.
        else => connection.fail(transport, qpack.decoder.error_code(failure)),
    };
}

/// A decoded field section, read as what the stream's phase says comes next (§4.1).
fn on_section(connection: *Connection, transport: *QuicConnection, request: *RequestStream) Error!Step {
    const section = &connection.section;
    switch (request.phase) {
        .head => switch (connection.options.role) {
            .server => {
                const found = message.validate_request(section) catch |reason| return refuse(connection, transport, request, message.verdict(reason));
                request.content_length = found.content_length;
                request.phase = .content;
                return .{ .event = .{ .request = .{ .stream_id = request.id, .request = found } } };
            },
            .client => return on_response(connection, transport, request),
        },
        .content => {
            message.validate_trailers(section) catch |reason| return refuse(connection, transport, request, message.verdict(reason));
            // §4.1.2: the content is whole once the trailer section arrives.
            if (!content_length_matches(request)) return refuse(connection, transport, request, constants.error_message_error);
            request.phase = .trailers_read;
            return .{ .event = .{ .trailers = request.id } };
        },
        // `check_sequence` refused a HEADERS frame after the trailers, and an abandoned stream
        // reads no frame.
        .trailers_read, .abandoned => unreachable,
    }
}

fn on_response(connection: *Connection, transport: *QuicConnection, request: *RequestStream) Error!Step {
    const found = message.validate_response(&connection.section) catch |reason|
        return refuse(connection, transport, request, message.verdict(reason));
    // §4.1: interim responses precede the final one and carry no content, so the stream stays
    // at its head.
    if (!found.status.is_interim()) {
        request.phase = .content;
        request.content_length = found.content_length;
        const code: http.status.Code = @enumFromInt(found.status.code);
        // §4.1.2: "A response that is defined as never having content, even when a
        // Content-Length is present, can have a non-zero Content-Length header field", which
        // RFC 9110 §6.4.1 says of a response to HEAD and of 204 and 304.
        request.no_content = request.head_request or code == .no_content or code == .not_modified;
    }
    return .{ .event = .{ .response = .{ .stream_id = request.id, .response = found } } };
}

fn start_data(connection: *Connection, request: *RequestStream, transport: *QuicConnection, header: frame.Header, header_len: usize) Error!Step {
    request.fin_read = (stream_read.consume(transport, .{ .value = request.id }, header_len) catch unreachable).fin;
    request.data_left = header.length;
    request.content_received +|= header.length;
    // §4.1.2: content past the content-length is malformed, which the frame's header shows.
    if (!request.no_content) {
        if (request.content_length) |expected| {
            if (request.content_received > expected) return refuse(connection, transport, request, constants.error_message_error);
        }
    }
    // §7.1: the stream ended inside the DATA frame.
    if (request.fin_read and request.data_left > 0) return connection.fail(transport, constants.error_frame_error);
    return .again;
}

/// Hands the caller what has arrived of the current DATA frame's payload (§7.2.1).
fn read_data(connection: *Connection, transport: *QuicConnection, request: *RequestStream, body: []u8) Error!Step {
    const window = body[0..@intCast(@min(body.len, request.data_left))];
    const read = stream_read.read(transport, .{ .value = request.id }, window) catch return on_closed(connection, request);
    request.data_left -= read.len;
    request.fin_read = read.fin;
    // §7.1: a stream that ended inside a DATA frame is H3_FRAME_ERROR.
    if (read.fin and request.data_left > 0) return connection.fail(transport, constants.error_frame_error);
    if (read.len == 0) return .wait;
    return .{ .event = .{ .data = .{ .stream_id = request.id, .octets = window[0..read.len] } } };
}

fn start_skip(transport: *QuicConnection, request: *RequestStream, header: frame.Header, header_len: usize) Step {
    request.fin_read = (stream_read.consume(transport, .{ .value = request.id }, header_len) catch unreachable).fin;
    // §9: "Implementations MUST ignore unknown or unsupported values in all extensible protocol
    // elements", so an unknown frame's payload is skipped unread.
    request.skip_left = header.length;
    return .again;
}

/// Takes what has arrived of an unknown frame's payload.
fn skip(connection: *Connection, transport: *QuicConnection, request: *RequestStream) Error!Step {
    const id: StreamId = .{ .value = request.id };
    const window = connection.scratch[0..@intCast(@min(request.skip_left, connection.scratch.len))];
    const peeked = stream_read.peek(transport, id, window) catch return on_closed(connection, request);
    const taken = stream_read.consume(transport, id, peeked.len) catch unreachable;
    request.skip_left -= peeked.len;
    request.fin_read = taken.fin;
    // §7.1: a stream that ended inside a frame is H3_FRAME_ERROR.
    if (taken.fin and request.skip_left > 0) return connection.fail(transport, constants.error_frame_error);
    if (peeked.len == 0) return .wait;
    return .again;
}

/// The stream ended cleanly at a frame's end (§4.1).
fn on_end(connection: *Connection, transport: *QuicConnection, request: *RequestStream) Error!Step {
    if (request.phase == .head) {
        const code = switch (connection.options.role) {
            // §4.1: "If a client-initiated stream terminates without enough of the HTTP message
            // to provide a complete response, the server SHOULD abort its response stream with
            // the error code H3_REQUEST_INCOMPLETE."
            .server => constants.error_request_incomplete,
            // §4.1.2: a response stream that ends before its final response holds "an invalid
            // sequence of HTTP messages", so it is malformed.
            .client => constants.error_message_error,
        };
        return refuse(connection, transport, request, code);
    }
    // §4.1.2: a content-length that is not "the sum of the DATA frame lengths received".
    if (!content_length_matches(request)) return refuse(connection, transport, request, constants.error_message_error);
    const id = request.id;
    connection.requests.release(id);
    return .{ .event = .{ .end = id } };
}

fn content_length_matches(request: *const RequestStream) bool {
    if (request.no_content) return true;
    const expected = request.content_length orelse return true;
    return expected == request.content_received;
}

/// The peer reset the stream (RFC 9000 §19.4), which cancels its message (§4.1.1). RFC 9204
/// §2.2.2.2: the decoder cancels the references the stream's sections held.
fn on_reset(connection: *Connection, transport: *QuicConnection, request: *RequestStream, code: u64) Step {
    // Reading reports the reset to `quic`, which may then forget the stream.
    _ = stream_read.peek(transport, .{ .value = request.id }, connection.scratch[0..0]) catch {};
    const reported = request.phase != .abandoned;
    owe_cancel(connection, request);
    const id = request.id;
    if (!request.cancel_owed) connection.requests.release(id) else request.phase = .abandoned;
    if (!reported) return .wait;
    return .{ .event = .{ .reset = .{ .stream_id = id, .error_code = code } } };
}

/// `quic` has closed the stream, so there is nothing more to read on it.
fn on_closed(connection: *Connection, request: *RequestStream) Step {
    if (!request.cancel_owed) connection.requests.release(request.id);
    return .wait;
}

/// Takes what arrives on a refused stream until the peer ends or resets it.
fn discard(connection: *Connection, transport: *QuicConnection, request: *RequestStream) Step {
    const id: StreamId = .{ .value = request.id };
    const peeked = stream_read.peek(transport, id, &connection.scratch) catch return on_closed(connection, request);
    const taken = stream_read.consume(transport, id, peeked.len) catch unreachable;
    if (taken.fin) return on_closed(connection, request);
    return .wait;
}

/// Refuses the stream with `code`: its message is malformed or incomplete (§4.1.1, §4.1.2).
fn refuse(connection: *Connection, transport: *QuicConnection, request: *RequestStream, code: u64) Step {
    const id = request.id;
    refuse_stream(connection, transport, request, code);
    // A stream whose FIN colibri took has nothing more to discard.
    if (request.fin_read) _ = on_closed(connection, request);
    return .{ .event = .{ .refused = .{ .stream_id = id, .error_code = code } } };
}

/// Resets colibri's side of the stream and asks the peer to stop sending (§4.1.1), both with
/// `code`, and has the QPACK decoder cancel the stream's references (RFC 9204 §2.2.2.2).
fn refuse_stream(connection: *Connection, transport: *QuicConnection, request: *RequestStream, code: u64) void {
    const id: StreamId = .{ .value = request.id };
    // Either part may have finished already, which is nothing to refuse.
    quic.connection_stream_send.stop_sending(transport, id, code) catch {};
    quic.connection_stream_send.reset(transport, id, code) catch {};
    owe_cancel(connection, request);
    request.phase = .abandoned;
    request.data_left = 0;
    request.skip_left = 0;
    request.blocked_at = null;
}

fn owe_cancel(connection: *Connection, request: *RequestStream) void {
    request.cancel_owed = connection.decoder.abandon_stream(request.id) == .owes_instructions;
}

/// Cancels the message on `stream_id` at the caller's request (§4.1.1).
pub fn cancel(connection: *Connection, transport: *QuicConnection, stream_id: u64, code: u64) void {
    if (connection.requests.find(stream_id)) |request| {
        refuse_stream(connection, transport, request, code);
        if (request.fin_read) _ = on_closed(connection, request);
        return;
    }
    const id: StreamId = .{ .value = stream_id };
    quic.connection_stream_send.stop_sending(transport, id, code) catch {};
    quic.connection_stream_send.reset(transport, id, code) catch {};
}
