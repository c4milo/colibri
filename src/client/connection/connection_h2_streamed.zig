//! The request content of the h2 half of a client connection (decision 100), split from
//! `connection_h2.zig` in design §8 step 39. Each request's content goes out in DATA frames as the
//! windows allow (RFC 9113 §6.9). Over TLS, a small content fills the record of the heads in the
//! connection's output. The rest goes from the caller's memory into the caller's output, each
//! frame's data after the header h2 wrote, sealed over TLS (decisions 138 and 139). A streamed
//! request's pieces go out the same way, each in DATA frames of its own (decision 153).
const std = @import("std");
const assert = std.debug.assert;
const h2 = @import("h2");
const tls_provider = @import("tls_provider");
const connection_module = @import("connection.zig");
const internal = @import("connection_internal.zig");
const connection_tls = @import("connection_tls.zig");
const slots_module = @import("../slots.zig");

const Connection = connection_module.Connection;
const Slot = slots_module.Slot;

/// Copies into the output the DATA frame of `slot`'s content that fills the record of what the
/// output holds over TLS, as the windows allow, so a small content goes out with its head.
pub fn fill_record(connection: *Connection, slot: *Slot) void {
    const fill = internal.record_fill(connection);
    if (fill <= h2.constants.protocol.frame_header_len) return;
    const room = internal.room(connection);
    const content = slot.piece[slot.piece_sent..];
    const sent = connection.session.h2.write_data(room[0..@min(room.len, fill)], @intCast(slot.stream_id), content, slot.ends_with_piece()) catch {
        // RFC 9113 §5.1: the stream is no longer one the client may send on.
        slot.content_stopped = true;
        return;
    };
    connection.output_len += sent.written;
    count_sent(slot, sent.consumed);
}

/// Counts `consumed` octets of `slot`'s piece written. RFC 9113 §6.1: the frame that carried the
/// last octet of the last piece carried END_STREAM, which ends the content, unless a trailer
/// section ends it (RFC 9113 §8.1).
fn count_sent(slot: *Slot, consumed: usize) void {
    slot.piece_sent += consumed;
    slot.response.body_sent += consumed;
    assert(slot.piece_sent <= slot.piece.len);
    if (slot.piece_sent < slot.piece.len) return;
    slot.content_ended = slot.ends_with_piece();
    slot.piece_written();
}

/// Writes the content of each request going out into `output`, sealed over TLS, as the windows and
/// the room allow, once the connection's own output is empty. h2 writes each DATA frame's header,
/// and the data follows it from the caller's memory (decisions 138 and 139). Returns the octets
/// written.
pub fn send_content(connection: *Connection, output: []u8, now_ns: u64) usize {
    assert(connection.output_len == 0);
    var written: usize = 0;
    for (&connection.slots.slots) |*slot| {
        // A record that failed ended every exchange the connection held.
        if (connection.stopped) break;
        // Decision 152: `write_requests` writes a trailer section into the connection's output.
        const frames = slot.stage == .sent and slot.content_ready() and !slot.trailers_next();
        if (frames) written += send_frames(connection, slot, output[written..], now_ns);
    }
    assert(written <= output.len);
    return written;
}

/// Writes DATA frames of `slot`'s content into `output`, each one's data from the caller's memory
/// after the header h2 wrote. Returns the octets written.
fn send_frames(connection: *Connection, slot: *Slot, output: []u8, now_ns: u64) usize {
    var written: usize = 0;
    // Bounded: each pass writes a frame that carries an octet of the piece or ends it, or stops.
    for (0..slot.piece.len + 1) |_| {
        if (!slot.content_ready() or slot.trailers_next()) return written;
        const left = slot.piece[slot.piece_sent..];
        var header: [h2.constants.protocol.frame_header_len]u8 = undefined;
        const room_len = frame_room(connection, output.len - written);
        // RFC 9113 §6.1: END_STREAM goes on the frame that carries the last octet of the last
        // piece, and on no frame of a piece before it (decision 153), nor before a trailer
        // section (RFC 9113 §8.1).
        const sent = connection.session.h2.write_data_header(&header, room_len, @intCast(slot.stream_id), left.len, slot.ends_with_piece()) catch {
            // RFC 9113 §5.1: the stream is no longer one the client may send on.
            slot.content_stopped = true;
            return written;
        };
        // RFC 9113 §6.9: no window, or no room for a frame.
        if (sent.written == 0) return written;
        // Decision 138: the frame's data follows its header, before any other octet.
        written += put_frame(connection, &header, left[0..sent.consumed], output[written..], now_ns);
        if (connection.stopped) return written;
        count_sent(slot, sent.consumed);
    }
    return written;
}

/// The octets one DATA frame may take of `output_len`: all of them in cleartext, and over TLS the
/// plaintext that one seal writes into them, at most one record's. A frame of 16,384 octets of
/// data and its header would pass one record by 9 octets (RFC 9113 §4.2, RFC 9846 §5.1), and
/// would cost a second record of 9 octets.
fn frame_room(connection: *const Connection, output_len: usize) usize {
    if (connection.config.tls == null) return output_len;
    const writable = h2.connection_tls.writable_len(&connection.session.h2, output_len);
    return @min(writable, tls_provider.constants.protocol.record_plaintext_len_max);
}

/// Writes a DATA frame's `header` and then its `data` into `output`, sealed over TLS, and returns
/// the octets written.
fn put_frame(connection: *Connection, header: []const u8, data: []const u8, output: []u8, now_ns: u64) usize {
    if (connection.config.tls != null) return connection_tls.seal_frame(connection, header, data, output, now_ns);
    @memcpy(output[0..header.len], header);
    @memcpy(output[header.len..][0..data.len], data);
    return header.len + data.len;
}
