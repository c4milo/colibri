//! The octets of each request stream of a QUIC client connection (decision 79), split from
//! `quic_connection_h3.zig` in design §8 step 39. A request stream carries the HEADERS frame, which
//! the connection keeps, then a DATA frame for each piece of the request's content: its header,
//! which the connection keeps too, and the piece from the caller's memory (decision 153). QUIC
//! reads them by offset, and may read them again until the peer acknowledges them or the stream
//! closes (RFC 9000 §3.1, §13.3), so an ended exchange holds its octets until then.
const std = @import("std");
const assert = std.debug.assert;
const quic = @import("quic");
const h3 = @import("h3");
const constants = @import("../constants.zig");
const slots_module = @import("../slots.zig");
const quic_connection = @import("quic_connection.zig");

const QuicConnection = quic_connection.QuicConnection;
const Slot = slots_module.Slot;
const StreamProvider = quic.stream.StreamProvider;

/// The frames of one request stream the connection keeps (decision 79).
pub const RequestStream = struct {
    /// The HEADERS frame.
    prefix: [constants.limits.request_prefix_len_max]u8,
    prefix_len: usize,
    /// The header of the DATA frame that carries the slot's piece, empty for an empty piece, and
    /// the stream offset it starts at.
    data_header: [h3.constants.protocol.frame_header_len_max]u8,
    data_header_len: usize,
    piece_base: u64,
    /// The stream's octets QUIC was told of (RFC 9000 §4.5): the end of the piece's frame.
    supplied_end: u64,
};

/// Supplies QUIC the DATA frame of `slot`'s piece, after the octets supplied before it, with FIN
/// when the piece is the last (RFC 9114 §4.1, RFC 9000 §2.2). `BodyStopped` says the stream's
/// sending part takes no more: the server asked the client to stop sending (RFC 9114 §4.1), or
/// the stream was reset.
pub fn supply_piece(connection: *QuicConnection, slot: *Slot, now_ns: u64) error{BodyStopped}!void {
    assert(slot.stage == .sent and slot.holds_octets);
    const stream = &connection.streams[connection.slots.index_of(slot)];
    stream.piece_base = stream.supplied_end;
    stream.data_header_len = 0;
    if (slot.piece.len > 0) {
        var writer = quic.core.Writer.init(&stream.data_header);
        // RFC 9114 §4.1: the content goes in DATA frames after the header section, here one for
        // each piece. Its header fits `frame_header_len_max`.
        connection.h3.write_data_header(slot.stream_id, slot.piece.len, &writer, now_ns) catch unreachable;
        stream.data_header_len = writer.written().len;
    }
    const end = stream.piece_base + stream.data_header_len + slot.piece.len;
    // RFC 9000 §2.2: the stream ends with the last octet of the content, which carries FIN.
    quic.connection_stream_send.supply(&connection.transport, .{ .value = slot.stream_id }, end, slot.piece_end) catch {
        slot.content_stopped = true;
        // RFC 9114 §4.1: the server asked the client to stop sending, and QUIC reset the stream's
        // sending part in answer (RFC 9000 §3.5).
        return error.BodyStopped;
    };
    stream.supplied_end = end;
    slot.piece_sent = slot.piece.len;
    slot.response.body_sent += slot.piece.len;
    slot.content_ended = slot.piece_end;
}

/// Supplies the piece each written exchange was handed since its last one, at `now_ns`. A stream
/// whose sending part takes no more reads none of it, so the piece is taken at once.
pub fn supply_pieces(connection: *QuicConnection, now_ns: u64) void {
    for (&connection.slots.slots) |*slot| {
        if (slot.stage != .sent or !slot.content_ready()) continue;
        supply_piece(connection, slot, now_ns) catch {
            slot.piece_sent = slot.piece.len;
            slot.piece_written();
        };
    }
}

/// Whether the sending part of `slot`'s stream takes no more of the request. RFC 9114 §4.1: a
/// server that needs no more of it asks the client to stop sending, and QUIC answers with a reset
/// of the sending part (RFC 9000 §3.5), whose octets it then reads no more.
pub fn sending_stopped(connection: *QuicConnection, slot: *const Slot) bool {
    if (slot.stage != .sent or !slot.holds_octets) return false;
    return quic.connection_stream_acknowledged.acknowledged_end(&connection.transport, .{ .value = slot.stream_id }) == null;
}

/// Reports each held piece the peer acknowledged to its last octet, or that the stream sends no
/// more, as taken. RFC 9000 §13.3: QUIC sends a lost octet again by its offset, so the piece is
/// the caller's again only then. The stream may still read the octets after the piece's.
pub fn note_taken(connection: *QuicConnection) void {
    for (&connection.slots.slots) |*slot| {
        if (!slot.piece_held or !slot.holds_octets) continue;
        const stream = &connection.streams[connection.slots.index_of(slot)];
        const acknowledged = quic.connection_stream_acknowledged.acknowledged_end(&connection.transport, .{ .value = slot.stream_id });
        // Null when QUIC reads none of the stream's octets again: it closed, or it was reset.
        if (acknowledged) |end| {
            if (end < stream.supplied_end) continue;
        }
        slot.piece_written();
    }
}

/// The provider QUIC reads the request streams from: h3 serves its own streams, and the rest come
/// from the requests (decision 79).
pub fn provider(connection: *QuicConnection) StreamProvider {
    return connection.h3.provider(.{ .context = connection, .vtable = &vtable });
}

const vtable: quic.stream.stream_provider.VTable = .{ .read = read_request };

/// A request stream's octets from `offset`: its HEADERS frame, then the DATA frame's header and
/// the piece. Every call at one offset answers the same octets, which RFC 9000 §2.2 asks of a
/// retransmission. QUIC reads no octet between the two: the pieces before the current one were
/// acknowledged before it was handed (`note_taken`).
fn read_request(context: *anyopaque, stream_id: u64, offset: u64, output: []u8) usize {
    const connection: *QuicConnection = @ptrCast(@alignCast(context));
    const slot = holding(connection, stream_id) orelse return 0;
    const stream = &connection.streams[connection.slots.index_of(slot)];
    var written: usize = 0;
    if (offset < stream.prefix_len) {
        written = copy_part(stream.prefix[0..stream.prefix_len], offset, output);
        // The output filled before the HEADERS frame ended, or the peer acknowledged what follows
        // it.
        if (written == output.len or stream.piece_base > stream.prefix_len) return written;
    }
    const from = offset + written;
    if (from >= stream.supplied_end) return written;
    // RFC 9000 §13.3: only octets not acknowledged are sent again.
    assert(from >= stream.piece_base);
    const header = stream.data_header[0..stream.data_header_len];
    written += copy_part(header, from - stream.piece_base, output[written..]);
    // The piece follows the header in the same call, as far as `output` holds.
    const piece_from = offset + written - stream.piece_base;
    if (piece_from < header.len) return written;
    written += copy_part(slot.piece, piece_from - header.len, output[written..]);
    return written;
}

/// Copies the octets of `part` from `from` into `output`, as far as `output` holds, and returns
/// the octets copied.
fn copy_part(part: []const u8, from: u64, output: []u8) usize {
    if (from >= part.len) return 0;
    const start: usize = @intCast(from);
    const len = @min(output.len, part.len - start);
    @memcpy(output[0..len], part[start..][0..len]);
    return len;
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
