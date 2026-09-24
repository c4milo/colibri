//! The frames colibri writes on request streams (RFC 9114 §4.1, §7.2.1, §7.2.2). Part of design
//! §8 step 12.
//!
//! Each call writes a whole frame into the caller's buffer, which the caller keeps with the
//! stream's content until the stream reaches "Data Recvd" (decision 79). A field section is
//! encoded with QPACK into the connection's scratch, and the frame's header and the section then
//! go into the caller's buffer, because §7.1's Length comes before the section.
//!
//! **Room is checked before the encoder runs.** The encoder records each section it writes that
//! references the dynamic table, and waits for the peer to acknowledge it (RFC 9204 §2.1.1). A
//! section encoded and then not sent would hold its entries forever. So a call first checks that
//! the caller's buffer holds the largest frame the section can make, and writes nothing if not.
//! Encoder instructions it writes are owed whether or not the section fits (decision 76).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const http = @import("http");
const qpack = @import("qpack");
const quic = @import("quic");
const constants = @import("../constants.zig");
const frame_write = @import("../frame_write.zig");
const message = @import("../message/message.zig");
const connection_module = @import("connection.zig");
const connection_local = @import("connection_local.zig");

const Writer = core.Writer;
const FieldSection = http.FieldSection;
const Connection = connection_module.Connection;
const StreamId = quic.stream.StreamId;
const QuicConnection = quic.Connection;
const Indexing = qpack.encoder.Indexing;

pub const Error = core.writer.Error || connection_module.Error || error{
    /// `start` has not opened colibri's control stream.
    NotStarted,
    /// The peer sent a GOAWAY, after which "Endpoints MUST NOT initiate new requests" (RFC 9114
    /// §5.2).
    GoawayReceived,
    /// The section is not a message of the kind asked for (RFC 9114 §4.1.2), so colibri does not
    /// send it.
    MessageInvalid,
    /// The section is larger than the peer's SETTINGS_MAX_FIELD_SECTION_SIZE, which RFC 9114
    /// §4.2.2 says an implementation "SHOULD NOT send".
    FieldSectionTooLarge,
    /// No request stream can be opened now: the peer's limit is reached (RFC 9000 §4.6), or every
    /// slot colibri keeps is in use.
    StreamsExhausted,
};

/// Opens a request stream and writes its HEADERS frame (RFC 9114 §4.1, §6.1).
pub fn write_request(
    connection: *Connection,
    transport: *QuicConnection,
    section: *const FieldSection,
    indexing: []const Indexing,
    output: *Writer,
) Error!u64 {
    assert(connection.options.role == .client);
    // RFC 9114 §5.2: "Endpoints MUST NOT initiate new requests or promise new pushes on the
    // connection after receipt of a GOAWAY frame from the peer."
    if (connection.goaway_received != null) return error.GoawayReceived;
    // RFC 9114 §4.1.2: colibri sends no malformed request.
    const found = message.validate_request(section) catch return error.MessageInvalid;
    // RFC 9114 §6.1: a request stream needs a slot to read its response on.
    const slot = connection.requests.free_slot() orelse return error.StreamsExhausted;
    const streams = &transport.streams;
    const which = @intFromEnum(quic.stream.Directionality.bidirectional);
    // RFC 9000 §4.6: "Endpoints MUST NOT exceed the limit set by their peer."
    if (streams.local_limit[which].is_blocked()) return error.StreamsExhausted;
    // The encoder records the section against its stream, so the ID comes before the stream
    // opens, and the stream opens only once its frame is written.
    const id = StreamId.of(.client, .bidirectional, streams.next_index[which]);
    try write_headers(connection, transport, id.value, section, indexing, output);
    // RFC 9000 §4.6: the limit was checked above, so only colibri's table can refuse the stream.
    const opened = quic.connection_stream_send.open(transport, .bidirectional) catch return error.StreamsExhausted;
    assert(opened.value == id.value);
    // RFC 9110 §9.3.2: a response to HEAD carries no content, whatever its content-length.
    slot.* = .{ .id = id.value, .head_request = std.mem.eql(u8, found.method, "HEAD") };
    return id.value;
}

/// Writes a HEADERS frame carrying a response on `stream_id` (RFC 9114 §4.1).
pub fn write_response(
    connection: *Connection,
    transport: *QuicConnection,
    stream_id: u64,
    section: *const FieldSection,
    indexing: []const Indexing,
    output: *Writer,
) Error!void {
    assert(connection.options.role == .server);
    // RFC 9114 §4.1.2: colibri sends no malformed response.
    _ = message.validate_response(section) catch return error.MessageInvalid;
    return write_headers(connection, transport, stream_id, section, indexing, output);
}

/// Writes a HEADERS frame carrying a trailer section on `stream_id` (RFC 9114 §4.1). A trailer
/// line is not inserted into the dynamic table: it is sent once.
pub fn write_trailers(
    connection: *Connection,
    transport: *QuicConnection,
    stream_id: u64,
    section: *const FieldSection,
    output: *Writer,
) Error!void {
    // RFC 9114 §4.1.2: colibri sends no malformed trailer section.
    message.validate_trailers(section) catch return error.MessageInvalid;
    var no_insert: [core.constants.field_count_max]Indexing = @splat(.no_insert);
    return write_headers(connection, transport, stream_id, section, no_insert[0..section.len()], output);
}

/// Writes a DATA frame's header (RFC 9114 §7.2.1). The caller writes `len` octets of content
/// after it.
pub fn write_data_header(len: u64, output: *Writer) Error!void {
    try frame_write.write_header(output, constants.frame_data, len);
}

fn write_headers(
    connection: *Connection,
    transport: *QuicConnection,
    stream_id: u64,
    section: *const FieldSection,
    indexing: []const Indexing,
    output: *Writer,
) Error!void {
    // RFC 9114 §4.2.2: "An implementation that has received this parameter SHOULD NOT send an
    // HTTP message header that exceeds the indicated size", the size counted as §4.2.2 counts it.
    if (connection.peer_settings) |settings| {
        if (settings.max_field_section_size) |limit| {
            // RFC 9114 §4.2.2: SETTINGS_MAX_FIELD_SECTION_SIZE.
            if (section.size > limit) return error.FieldSectionTooLarge;
        }
    }
    if (output.remaining_len() < frame_len_max(section)) return error.NoSpaceLeft;
    var encoder_stream = try connection_local.encoder_room(connection, transport);
    var encoded = Writer.init(&connection.scratch);
    const result = connection.encoder.write_section(stream_id, &encoded, &encoder_stream, section, indexing);
    // Decision 76: what the encoder stream gained is owed either way.
    try connection_local.commit_encoder(connection, transport, encoder_stream.written());
    // The scratch holds the longest section `frame_len_max` admits.
    result catch unreachable;
    var cursor = output.*;
    frame_write.write_header(&cursor, constants.frame_headers, encoded.written().len) catch unreachable;
    cursor.write_bytes(encoded.written()) catch unreachable;
    output.* = cursor;
}

/// The longest HEADERS frame `section` can make. §4.2.2's size counts 32 octets for each line
/// beyond its name and value, more than the representation of a line ever adds, so it bounds the
/// lines; the prefix and the frame header are added to it.
fn frame_len_max(section: *const FieldSection) usize {
    return constants.frame_header_len_max + constants.section_prefix_len_max + section.size;
}

comptime {
    // A line's representation adds its pattern octet and two length prefixes to its name and
    // value (RFC 9204 §4.5.6), which `field_line_overhead` covers.
    assert(core.constants.field_line_overhead >= constants.line_representation_len_max);
    // The longest section `frame_len_max` admits fits the scratch it is encoded into.
    assert(constants.section_prefix_len_max + core.constants.field_section_size_max <= constants.scratch_len);
}
