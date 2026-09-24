//! colibri's own three streams: the control stream (RFC 9114 §6.2.1) and QPACK's encoder and
//! decoder streams (RFC 9204 §4.2). Part of design §8 step 12.
//!
//! h3 writes these streams and keeps their octets until the peer acknowledges them (decision
//! 79), each in a `SendBuffer`. Before a write that may not fit, it drops what `quic` reports
//! acknowledged (decision 78). Asking scans `quic`'s sent records, so it is asked only then.
//!
//! None of the three may close (§6.2.1, RFC 9204 §4.2). A peer that asks colibri to stop sending
//! on one has closed it all the same, which is H3_CLOSED_CRITICAL_STREAM.
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const qpack = @import("qpack");
const quic = @import("quic");
const constants = @import("../constants.zig");
const frame = @import("../frame.zig");
const frame_write = @import("../frame_write.zig");
const stream = @import("../stream.zig");
const send_buffer = @import("../send_buffer.zig");
const connection_module = @import("connection.zig");

const Writer = core.Writer;
const Connection = connection_module.Connection;
const Error = connection_module.Error;
const StreamId = quic.stream.StreamId;
const StreamProvider = quic.stream.StreamProvider;
const QuicConnection = quic.Connection;

/// The octets one QPACK insert takes at most (decision 76), which is the room the encoder
/// stream's buffer is cleared for before a section is encoded.
const insert_len_max: usize = qpack.constants.dynamic_table_capacity_max / qpack.constants.insert_size_divisor;

pub const Local = struct {
    /// The three streams, once `start` opened them.
    control_id: ?u64,
    encoder_id: ?u64,
    decoder_id: ?u64,
    control: send_buffer.SendBuffer(constants.control_buffer_len),
    encoder: send_buffer.SendBuffer(constants.encoder_buffer_len),
    decoder: send_buffer.SendBuffer(constants.decoder_buffer_len),

    pub fn init(local: *Local) void {
        local.control_id = null;
        local.encoder_id = null;
        local.decoder_id = null;
        local.control.init();
        local.encoder.init();
        local.decoder.init();
    }

    /// Whether `start` has opened the streams.
    pub fn started(local: *const Local) bool {
        return local.control_id != null;
    }
};

/// Opens the three streams, writes each one's type (RFC 9114 §6.2, RFC 9204 §4.2) and the
/// SETTINGS frame (§7.2.4), and tells `quic` how far each reaches.
pub fn start(connection: *Connection, transport: *QuicConnection) Error!void {
    const local = &connection.local;
    assert(!local.started());
    // The peer's transport parameters say how many streams colibri may open (RFC 9000 §4.6).
    assert(transport.peer_parameters != null);
    local.control_id = try open(connection, transport);
    local.encoder_id = try open(connection, transport);
    local.decoder_id = try open(connection, transport);
    // Each buffer is empty and far longer than a stream header and a SETTINGS frame.
    write_header(&local.control, .control);
    write_header(&local.encoder, .qpack_encoder);
    write_header(&local.decoder, .qpack_decoder);
    var writer = local.control.free();
    frame_write.write_settings(&writer, settings_of(connection)) catch unreachable;
    local.control.commit(writer.written());
    try supply(connection, transport, local.control_id.?, local.control.end_offset());
    try supply(connection, transport, local.encoder_id.?, local.encoder.end_offset());
    try supply(connection, transport, local.decoder_id.?, local.decoder.end_offset());
}

fn open(connection: *Connection, transport: *QuicConnection) Error!u64 {
    const id = quic.connection_stream_send.open(transport, .unidirectional) catch
        // RFC 9114 §6.2: "the transport parameters sent by both clients and servers MUST allow
        // the peer to create at least three unidirectional streams".
        return connection.fail(transport, constants.error_general_protocol);
    return id.value;
}

fn write_header(buffer: anytype, kind: stream.Kind) void {
    var writer = buffer.free();
    stream.write_header(&writer, kind) catch unreachable;
    buffer.commit(writer.written());
}

/// The SETTINGS colibri sends (RFC 9114 §7.2.4.1, RFC 9204 §5): the field section size it
/// accepts, its decoder's two QPACK settings where they are not the default, and one reserved
/// setting drawn from the caller's grease value.
fn settings_of(connection: *const Connection) frame.Settings {
    const qpack_settings = connection.options.qpack;
    const n = connection.options.grease % constants.grease_range;
    return .{
        .max_field_section_size = core.constants.field_section_size_max,
        .qpack_max_table_capacity = if (qpack_settings.max_table_capacity == 0) null else qpack_settings.max_table_capacity,
        .qpack_blocked_streams = if (qpack_settings.blocked_streams == 0) null else qpack_settings.blocked_streams,
        // §7.2.4.1: "Endpoints SHOULD include at least one such setting", and its value "can be
        // any value the implementation selects".
        .reserved = .{ .n = n, .value = n },
    };
}

/// Tells `quic` that stream `id` now reaches `end`, which never ends it: none of the three may
/// close (RFC 9114 §6.2.1, RFC 9204 §4.2).
fn supply(connection: *Connection, transport: *QuicConnection, id: u64, end: u64) Error!void {
    quic.connection_stream_send.supply(transport, .{ .value = id }, end, false) catch |failure| switch (failure) {
        // The peer's STOP_SENDING reset it, though §6.2.1 says "the receiver MUST NOT request
        // that the sender close the control stream", and RFC 9204 §4.2 says the same of QPACK's.
        error.NotWritable => return connection.fail(transport, constants.error_closed_critical_stream),
        // A buffer never holds more than 2^62 octets over a connection's life.
        error.OffsetTooLarge, error.NotReadable => unreachable,
    };
}

/// Drops the octets the peer has acknowledged from `buffer` when fewer than `wanted` octets are
/// free (decision 78).
fn make_room(connection: *Connection, transport: *QuicConnection, buffer: anytype, id: u64, wanted: usize) Error!void {
    if (buffer.free().remaining_len() >= wanted) return;
    // Null means `quic` reads none of the stream again: it was reset, which only a peer's
    // STOP_SENDING does to these three, and §6.2.1 and RFC 9204 §4.2 forbid it.
    const end = quic.connection_stream_acknowledged.acknowledged_end(transport, .{ .value = id }) orelse
        return connection.fail(transport, constants.error_closed_critical_stream);
    buffer.drop_acknowledged(end);
}

/// Writes every decoder instruction the QPACK decoder owes that fits (RFC 9204 §4.4).
pub fn flush_decoder(connection: *Connection, transport: *QuicConnection) Error!void {
    const local = &connection.local;
    const id = local.decoder_id orelse return;
    if (!connection.decoder.owes()) return;
    const wanted = (connection.decoder.owed_len + 1) * constants.decoder_instruction_len_max;
    try make_room(connection, transport, &local.decoder, id, wanted);
    var writer = local.decoder.free();
    connection.decoder.write_decoder_stream(&writer);
    local.decoder.commit(writer.written());
    if (writer.written().len == 0) return;
    try supply(connection, transport, id, local.decoder.end_offset());
}

/// The encoder stream's free room, cleared for one insert at its largest. What the QPACK encoder
/// writes into it goes to `commit_encoder`.
pub fn encoder_room(connection: *Connection, transport: *QuicConnection) Error!Writer {
    const local = &connection.local;
    // Before `start`, the encoder uses the static table alone and writes no instruction.
    const id = local.encoder_id orelse return Writer.init(&.{});
    try make_room(connection, transport, &local.encoder, id, insert_len_max);
    return local.encoder.free();
}

/// Counts what the QPACK encoder wrote into `encoder_room`'s writer and tells `quic`.
pub fn commit_encoder(connection: *Connection, transport: *QuicConnection, written: []const u8) Error!void {
    if (written.len == 0) return;
    const local = &connection.local;
    local.encoder.commit(written);
    try supply(connection, transport, local.encoder_id.?, local.encoder.end_offset());
}

/// Writes a GOAWAY frame (RFC 9114 §5.2, §7.2.6).
pub fn write_goaway(connection: *Connection, transport: *QuicConnection) connection_module.SendError!void {
    const local = &connection.local;
    // RFC 9114 §7.2.6: "The GOAWAY frame is always sent on the control stream", which `start`
    // opens.
    const id = local.control_id orelse return error.NotStarted;
    const named = switch (connection.options.role) {
        // §5.2: "The server sends a client-initiated bidirectional stream ID", the first one it
        // has not taken, and refuses every later one.
        .server => StreamId.of(.client, .bidirectional, connection.requests.next_index).value,
        // §5.2: "the client sends a push ID". colibri allowed none (decision 17), so none is
        // processed.
        .client => 0,
    };
    // §5.2: an identifier "MUST NOT be greater than the identifier in any previous frame".
    const value = if (connection.goaway_sent) |previous| @min(previous, named) else named;
    try make_room(connection, transport, &local.control, id, constants.frame_header_len_max);
    var writer = local.control.free();
    try frame_write.write_single(&writer, constants.frame_goaway, value);
    local.control.commit(writer.written());
    connection.goaway_sent = value;
    try supply(connection, transport, id, local.control.end_offset());
}

/// The provider `quic`'s send path reads through (decision 79).
pub fn provider(connection: *Connection) StreamProvider {
    return .{ .context = connection, .vtable = &vtable };
}

const vtable: quic.stream.stream_provider.VTable = .{ .read = read };

fn read(context: *anyopaque, stream_id: u64, offset: u64, output: []u8) usize {
    const connection: *Connection = @ptrCast(@alignCast(context));
    const local = &connection.local;
    if (is(local.control_id, stream_id)) return local.control.read(offset, output);
    if (is(local.encoder_id, stream_id)) return local.encoder.read(offset, output);
    if (is(local.decoder_id, stream_id)) return local.decoder.read(offset, output);
    const caller = connection.caller_provider;
    return caller.vtable.read(caller.context, stream_id, offset, output);
}

fn is(held: ?u64, stream_id: u64) bool {
    const id = held orelse return false;
    return id == stream_id;
}
