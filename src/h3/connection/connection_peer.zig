//! The peer's unidirectional streams (RFC 9114 §6.2): its control stream, QPACK's encoder and
//! decoder streams (RFC 9204 §4.2), and any other type, which colibri stops reading. Part of
//! design §8 step 12.
//!
//! A stream the peer opens waits in a slot until its type arrives. The three critical streams then
//! run for the connection, and closing any of them is H3_CLOSED_CRITICAL_STREAM. Every read copies
//! the octets out of `quic` and takes only what was used (decision 80), so an instruction or frame
//! cut short stays in `quic` until the rest arrives.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const qpack = @import("qpack");
const quic = @import("quic");
const constants = @import("../constants.zig");
const frame = @import("../frame.zig");
const stream = @import("../stream.zig");
const connection_module = @import("connection.zig");

const Reader = core.Reader;
const Connection = connection_module.Connection;
const Error = connection_module.Error;
const Event = connection_module.Event;
const StreamId = quic.stream.StreamId;
const QuicConnection = quic.Connection;
const stream_read = quic.connection_stream_read;

/// A peer stream whose type has not arrived, or one colibri stopped reading and discards.
const Slot = struct {
    id: u64,
    discarding: bool,
};

pub const Peer = struct {
    opened: stream.Opened,
    control_id: ?u64,
    encoder_id: ?u64,
    decoder_id: ?u64,
    slots: [constants.uni_streams_max]?Slot,
    /// The index of the next of the peer's unidirectional streams no slot has seen (RFC 9000
    /// §2.1). The peer opens them in order, so every one below it was seen.
    next_index: u64,
    /// Whether the control stream's first frame, SETTINGS, arrived (RFC 9114 §6.2.1).
    settings_received: bool,
    /// Octets of an unknown control frame's payload still to skip (§9).
    control_skip: u64,

    pub fn init(peer: *Peer) void {
        peer.opened.init();
        peer.control_id = null;
        peer.encoder_id = null;
        peer.decoder_id = null;
        peer.slots = @splat(null);
        peer.next_index = 0;
        peer.settings_received = false;
        peer.control_skip = 0;
    }
};

/// Gives a slot to each unidirectional stream the peer opened since the last call, and reads the
/// type of each that waits for one.
pub fn accept(connection: *Connection, transport: *QuicConnection) Error!void {
    const peer = &connection.peer;
    const initiator = connection.initiator().peer();
    // RFC 9114 §6.1: "Clients MUST treat receipt of a server-initiated bidirectional stream as a
    // connection error of type H3_STREAM_CREATION_ERROR". Streams open in order, so the first
    // tells.
    if (connection.options.role == .client and transport.streams.lookup(StreamId.of(.server, .bidirectional, 0)) != .unopened) {
        return connection.fail(transport, constants.error_stream_creation);
    }
    // Bounded by the slots: a peer inside colibri's limit never has more open.
    for (0..constants.uni_streams_max) |_| {
        const id = StreamId.of(initiator, .unidirectional, peer.next_index);
        switch (transport.streams.lookup(id)) {
            .unopened => break,
            // §6.2: "A receiver MUST tolerate unidirectional streams being closed or reset prior
            // to the reception of the unidirectional stream header."
            .closed => {},
            .live => {
                const slot = free_slot(peer) orelse break;
                slot.* = .{ .id = id.value, .discarding = false };
            },
        }
        peer.next_index += 1;
    }
    for (&peer.slots) |*slot| {
        if (slot.* == null) continue;
        try read_type(connection, transport, slot);
    }
}

fn free_slot(peer: *Peer) ?*?Slot {
    for (&peer.slots) |*slot| {
        if (slot.* == null) return slot;
    }
    return null;
}

/// Reads the type of the stream in `slot` (§6.2) and hands the stream to what reads it, or
/// discards what arrives on one colibri stopped reading.
fn read_type(connection: *Connection, transport: *QuicConnection, slot: *?Slot) Error!void {
    const held = slot.*.?;
    const id: StreamId = .{ .value = held.id };
    const scratch = connection.scratch[0..constants.frame_header_len_max];
    const peeked = stream_read.peek(transport, id, scratch) catch {
        // Reset or closed before its header arrived, which §6.2 tolerates.
        slot.* = null;
        return;
    };
    if (held.discarding) return discard(transport, slot, peeked);
    var reader = Reader.init(scratch[0..peeked.len]);
    const kind = stream.read_header(&reader) catch {
        // The type has not all arrived. A stream that ended first is tolerated (§6.2).
        if (peeked.fin) discard(transport, slot, peeked);
        return;
    };
    _ = stream_read.consume(transport, id, peeked.len - reader.remaining_len()) catch unreachable;
    slot.* = null;
    try take(connection, transport, id, kind);
}

/// Takes the octets the peek copied, and frees the slot once the stream has ended.
fn discard(transport: *QuicConnection, slot: *?Slot, peeked: stream_read.Read) void {
    const id: StreamId = .{ .value = slot.*.?.id };
    _ = stream_read.consume(transport, id, peeked.len) catch unreachable;
    if (peeked.fin) slot.* = null;
}

fn take(connection: *Connection, transport: *QuicConnection, id: StreamId, kind: stream.Kind) Error!void {
    const peer = &connection.peer;
    const role: stream.Role = if (connection.options.role == .client) .server else .client;
    switch (kind) {
        // RFC 9114 §4.6: "A client MUST treat receipt of a push stream as a connection error of
        // type H3_ID_ERROR when no MAX_PUSH_ID frame has been sent", and colibri sends none.
        .push => if (connection.options.role == .client) return connection.fail(transport, constants.error_id_error),
        // §6.2: "Recipients of unknown stream types MUST either abort reading of the stream or
        // discard incoming data", and "SHOULD use the H3_STREAM_CREATION_ERROR error code".
        .unknown => return stop_reading(connection, transport, id),
        .control, .qpack_encoder, .qpack_decoder => {},
    }
    // §6.2.1, §6.2.2 and RFC 9204 §4.2: a second critical stream of a kind, or a push stream
    // from a client, is H3_STREAM_CREATION_ERROR.
    peer.opened.accept(kind, role) catch |failure| return connection.fail(transport, stream.error_code(failure));
    switch (kind) {
        .control => peer.control_id = id.value,
        .qpack_encoder => peer.encoder_id = id.value,
        .qpack_decoder => peer.decoder_id = id.value,
        .push, .unknown => unreachable,
    }
}

/// Asks the peer to stop sending on `id`, and discards what arrives until it does.
fn stop_reading(connection: *Connection, transport: *QuicConnection, id: StreamId) Error!void {
    quic.connection_stream_send.stop_sending(transport, id, constants.error_stream_creation) catch {};
    // The slot the stream had was freed a moment ago, so one is free.
    const slot = free_slot(&connection.peer).?;
    slot.* = .{ .id = id.value, .discarding = true };
}

/// Reads what the peer's QPACK streams and control stream carry, and returns the first event the
/// control stream produces.
pub fn step(connection: *Connection, transport: *QuicConnection) Error!?Event {
    try read_encoder_stream(connection, transport);
    try read_decoder_stream(connection, transport);
    return read_control(connection, transport);
}

/// Copies what has arrived on a critical stream, or ends the connection when it closed: §6.2.1
/// and RFC 9204 §4.2 make "closure of either unidirectional stream type" and of the control
/// stream H3_CLOSED_CRITICAL_STREAM.
fn peek_critical(connection: *Connection, transport: *QuicConnection, id: u64, window: []u8) Error![]const u8 {
    const peeked = stream_read.peek(transport, .{ .value = id }, window) catch
        return connection.fail(transport, constants.error_closed_critical_stream);
    if (peeked.fin) return connection.fail(transport, constants.error_closed_critical_stream);
    return window[0..peeked.len];
}

/// Applies every whole encoder instruction that arrived (RFC 9204 §4.3).
fn read_encoder_stream(connection: *Connection, transport: *QuicConnection) Error!void {
    const id = connection.peer.encoder_id orelse return;
    // The window holds the longest instruction the decoder accepts, so one longer is refused
    // rather than waited for (RFC 9204 §7.4, decision 74).
    const octets = try peek_critical(connection, transport, id, connection.scratch[0..qpack.constants.encoder_instruction_len_max]);
    var reader = Reader.init(octets);
    connection.decoder.read_encoder_stream(&reader) catch |failure|
        return connection.fail(transport, qpack.decoder.error_code(failure));
    _ = stream_read.consume(transport, .{ .value = id }, octets.len - reader.remaining_len()) catch unreachable;
}

/// Applies every whole decoder instruction that arrived (RFC 9204 §4.4).
fn read_decoder_stream(connection: *Connection, transport: *QuicConnection) Error!void {
    const id = connection.peer.decoder_id orelse return;
    const octets = try peek_critical(connection, transport, id, &connection.scratch);
    var reader = Reader.init(octets);
    // RFC 9204 §6: an instruction the encoder cannot interpret is QPACK_DECODER_STREAM_ERROR.
    connection.encoder.read_decoder_stream(&reader) catch
        return connection.fail(transport, qpack.constants.error_decoder_stream);
    _ = stream_read.consume(transport, .{ .value = id }, octets.len - reader.remaining_len()) catch unreachable;
}

/// What one pass over the control stream did.
const Step = union(enum) {
    event: Event,
    /// It took a frame or part of an unknown one's payload, and more may be whole.
    again,
    /// Nothing more can be read now.
    wait,
};

/// Reads the control stream's frames until one produces an event or none is whole (§6.2.1).
fn read_control(connection: *Connection, transport: *QuicConnection) Error!?Event {
    const id = connection.peer.control_id orelse return null;
    // Bounded: each pass takes a whole frame, or part of an unknown one's payload, or returns.
    for (0..constants.control_frames_per_call_max) |_| {
        switch (try control_step(connection, transport, id)) {
            .event => |event| return event,
            .wait => return null,
            .again => {},
        }
    }
    return null;
}

fn control_step(connection: *Connection, transport: *QuicConnection, id: u64) Error!Step {
    const peer = &connection.peer;
    if (peer.control_skip > 0) return skip_control(connection, transport, id);
    const octets = try peek_critical(connection, transport, id, &connection.scratch);
    var reader = Reader.init(octets);
    const header = frame.read_header(&reader) catch return .wait;
    const header_len = octets.len - reader.remaining_len();
    try check_control_frame(connection, transport, header);
    if (!is_known_control(header.frame_type)) {
        _ = stream_read.consume(transport, .{ .value = id }, header_len) catch unreachable;
        // §9: "Implementations MUST ignore unknown or unsupported values in all extensible
        // protocol elements", so the payload is skipped unread.
        peer.control_skip = header.length;
        return .again;
    }
    // A frame colibri reads whole and cannot hold is suspicious; §10.5 permits H3_EXCESSIVE_LOAD.
    if (header.length > connection.scratch.len - header_len) return connection.fail(transport, constants.error_excessive_load);
    const payload = reader.take(@intCast(header.length)) catch return .wait;
    _ = stream_read.consume(transport, .{ .value = id }, header_len + payload.len) catch unreachable;
    const found = frame.read_payload(header.frame_type, payload) catch |failure|
        return connection.fail(transport, frame.error_code(failure));
    const event = try on_control_frame(connection, transport, found) orelse return .again;
    return .{ .event = event };
}

/// Takes what has arrived of an unknown control frame's payload.
fn skip_control(connection: *Connection, transport: *QuicConnection, id: u64) Error!Step {
    const peer = &connection.peer;
    const window = connection.scratch[0..@intCast(@min(peer.control_skip, connection.scratch.len))];
    const octets = try peek_critical(connection, transport, id, window);
    _ = stream_read.consume(transport, .{ .value = id }, octets.len) catch unreachable;
    peer.control_skip -= octets.len;
    if (octets.len == 0) return .wait;
    return .again;
}

/// The frame rules of the control stream that its header alone decides.
fn check_control_frame(connection: *Connection, transport: *QuicConnection, header: frame.Header) Error!void {
    const peer = &connection.peer;
    // §6.2.1: "If the first frame of the control stream is any other frame type, this MUST be
    // treated as a connection error of type H3_MISSING_SETTINGS."
    if (!peer.settings_received and header.frame_type != constants.frame_settings) {
        return connection.fail(transport, constants.error_missing_settings);
    }
    // §7.2.1, §7.2.2, §7.2.5 and §7.2.8: DATA, HEADERS, PUSH_PROMISE and the HTTP/2 types are
    // not permitted on the control stream, which is H3_FRAME_UNEXPECTED.
    if (!frame.permitted(header.frame_type, .control)) return connection.fail(transport, constants.error_frame_unexpected);
    // §7.2.4: "If an endpoint receives a second SETTINGS frame on the control stream, the
    // endpoint MUST respond with a connection error of type H3_FRAME_UNEXPECTED."
    if (peer.settings_received and header.frame_type == constants.frame_settings) {
        return connection.fail(transport, constants.error_frame_unexpected);
    }
    // §7.2.7: "A client MUST treat the receipt of a MAX_PUSH_ID frame as a connection error of
    // type H3_FRAME_UNEXPECTED."
    if (connection.options.role == .client and header.frame_type == constants.frame_max_push_id) {
        return connection.fail(transport, constants.error_frame_unexpected);
    }
}

fn is_known_control(frame_type: u64) bool {
    return switch (frame_type) {
        constants.frame_settings, constants.frame_goaway, constants.frame_max_push_id, constants.frame_cancel_push => true,
        else => false,
    };
}

fn on_control_frame(connection: *Connection, transport: *QuicConnection, found: frame.Payload) Error!?Event {
    switch (found) {
        .settings => |settings| return on_settings(connection, transport, settings),
        .goaway => |value| return try on_goaway(connection, transport, value),
        .max_push_id => |value| {
            // §7.2.7: "receipt of a MAX_PUSH_ID frame that contains a smaller value than
            // previously received MUST be treated as a connection error of type H3_ID_ERROR".
            if (connection.max_push_id) |previous| {
                if (value < previous) return connection.fail(transport, constants.error_id_error);
            }
            connection.max_push_id = value;
            return null;
        },
        // §7.2.3: at a server, a push ID no PUSH_PROMISE mentioned, and colibri sends none; at a
        // client, one "greater than currently allowed", and colibri allows none. Both are
        // H3_ID_ERROR.
        .cancel_push => return connection.fail(transport, constants.error_id_error),
        .push_promise, .unknown => unreachable,
    }
}

fn on_settings(connection: *Connection, transport: *QuicConnection, settings: frame.Settings) Error!?Event {
    _ = transport;
    connection.peer.settings_received = true;
    connection.peer_settings = settings;
    // RFC 9204 §5: the peer's decoder settings are what colibri's encoder may use.
    connection.encoder.on_settings(.{
        .max_table_capacity = settings.qpack_max_table_capacity orelse 0,
        .blocked_streams = settings.qpack_blocked_streams orelse 0,
    });
    return .settings;
}

fn on_goaway(connection: *Connection, transport: *QuicConnection, value: u64) Error!?Event {
    // §7.2.6: "A client MUST treat receipt of a GOAWAY frame containing a stream ID of any other
    // type as a connection error of type H3_ID_ERROR", the type being a client-initiated
    // bidirectional stream.
    if (connection.options.role == .client) {
        const id: StreamId = .{ .value = value };
        if (id.initiator() != .client or id.directionality() != .bidirectional) {
            return connection.fail(transport, constants.error_id_error);
        }
    }
    // §5.2: "Receiving a GOAWAY containing a larger identifier than previously received MUST be
    // treated as a connection error of type H3_ID_ERROR."
    if (connection.goaway_received) |previous| {
        if (value > previous) return connection.fail(transport, constants.error_id_error);
    }
    connection.goaway_received = value;
    return .{ .goaway = value };
}
