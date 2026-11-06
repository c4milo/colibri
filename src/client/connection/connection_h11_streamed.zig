//! The request content of the h11 half of a client connection (decision 100), split from
//! `connection_h11.zig` in design §8 step 39. Over TLS, the part of a whole body that fills the
//! record of the head goes into the connection's output. The rest goes from the caller's memory
//! into the caller's output, sealed over TLS, with no copy into the connection's output
//! (https://github.com/c4milo/colibri/issues/105, decision 139).
//!
//! A streamed request's pieces go out with no copy at all (decision 153). In a chunked body, each
//! piece is one chunk: its head goes into the connection's output, and its data follows from the
//! caller's memory (RFC 9112 §7.1).
const std = @import("std");
const assert = std.debug.assert;
const core = @import("core");
const tls_provider = @import("tls_provider");
const constants = @import("../constants.zig");
const connection_module = @import("connection.zig");
const internal = @import("connection_internal.zig");
const connection_tls = @import("connection_tls.zig");
const slots_module = @import("../slots.zig");
const event_internal = @import("../event_internal.zig");

const Connection = connection_module.Connection;
const Slot = slots_module.Slot;

comptime {
    // Decision 152: `check_request` refuses a trailer section past `field_section_size_max`. Each
    // line's 32 octets of that size hold its ": " and CRLF, and the first line's hold the CRLF
    // owed, the last chunk and the empty line (RFC 9112 §7.1), so an empty output holds the end.
    assert(constants.limits.output_len >= core.constants.limits.field_section_size_max);
}

/// The written exchange whose content is still going out, or null. h11 writes the next head only
/// after it, so there is one at most (RFC 9112 §9.3.2).
pub fn writing(connection: *Connection) ?*Slot {
    for (&connection.slots.slots) |*slot| {
        if (slot.stage == .sent and !slot.content_done()) return slot;
    }
    return null;
}

/// Ends the body of `slot` once its last piece went out. Returns whether the content is done, so
/// the next head may follow.
pub fn end_content(connection: *Connection, slot: *Slot) bool {
    if (slot.content_done()) return true;
    if (!slot.piece_end or slot.piece_sent < slot.piece.len) return false;
    const session = &connection.session.h11;
    // RFC 9112 §6.2: a body of a declared length ends with its last octet, and RFC 9112 §7.1: a
    // chunked body ends with the last chunk. The next head may follow.
    // RFC 9112 §7.1.2: the last chunk carries the request's trailer section (decision 152).
    if (session.writer.open()) connection.output_len += session.write_end(internal.room(connection), slot.request.trailers) catch {
        // `check_request` refused every trailer h11 refuses, and a section past
        // `field_section_size_max`, which an empty output holds whole (see the comptime block).
        assert(connection.output_len > 0);
        // The end goes out once `send` has taken what the output holds.
        return false;
    };
    slot.content_ended = true;
    // An empty last piece went out with the end.
    slot.piece_written();
    return true;
}

/// Writes into the output what of `slot`'s content goes there: over TLS, the part of a whole body
/// that fills the record of the head before it, and for a chunked piece, the head of its chunk.
/// `send_content` writes the rest from the caller's memory, with no copy into the output
/// (https://github.com/c4milo/colibri/issues/105).
pub fn write_content(connection: *Connection, slot: *Slot) void {
    // Decision 153: a streamed piece goes out with no copy. Decision 152: a whole body before a
    // trailer section goes as one chunk, with no copy too (RFC 9112 §7.1.2).
    if (slot.request.streamed.request or event_internal.chunked(slot.request)) return open_chunk(connection, slot);
    const left = slot.piece.len - slot.piece_sent;
    const take = @min(left, internal.room(connection).len, internal.record_fill(connection));
    if (take == 0) return;
    const written = connection.session.h11.write_body(internal.room(connection), slot.piece[slot.piece_sent..][0..take]) catch {
        // RFC 9112 §9.6: the connection closed, and no more of the body goes out.
        slot.content_stopped = true;
        return;
    };
    connection.output_len += written;
    slot.piece_sent += take;
    slot.response.body_sent += take;
    assert(slot.piece_sent <= slot.piece.len);
}

/// Writes the head of a chunk that holds the rest of `slot`'s piece, once the chunk before it
/// went out (RFC 9112 §7.1). A body of a stated length has no chunks.
fn open_chunk(connection: *Connection, slot: *Slot) void {
    const session = &connection.session.h11;
    if (session.writer.kind != .chunked or session.writer.remaining > 0) return;
    const left = slot.piece.len - slot.piece_sent;
    // RFC 9112 §7.1: a chunk-size of 0 is the last chunk, which `end_content` writes.
    if (left == 0) return;
    const written = session.write_chunk_head(internal.room(connection), left) catch |failure| switch (failure) {
        // The head goes out once `send` has taken what the output holds.
        error.OutputTooSmall => return,
        // The writer is chunked, its last chunk went out whole, and the piece is not empty.
        else => unreachable,
    };
    connection.output_len += written;
}

/// Writes the content of the request going out from the caller's memory into `output`, sealed
/// over TLS, once the connection's own output is empty, and ends its body after its last octet.
/// Returns the octets written into `output` (https://github.com/c4milo/colibri/issues/105).
pub fn send_content(connection: *Connection, output: []u8, now_ns: u64) usize {
    assert(connection.output_len == 0);
    assert(connection.session == .h11);
    if (connection.stopped) return 0;
    const slot = writing(connection) orelse return 0;
    const content = slot.piece[slot.piece_sent..][0..sendable_len(connection, slot)];
    if (content.len == 0) return 0;
    const sent: tls_provider.provider.Sealed = if (connection.config.tls == null)
        copy_content(content, output)
    else
        connection_tls.seal_content(connection, content, output, now_ns);
    // A record that failed ended the connection and every exchange it held.
    if (sent.consumed == 0) return sent.written;
    // The head declared the body's length, or the chunk head the chunk's, and the octets sent stay
    // within it (decision 95).
    connection.session.h11.count_body(sent.consumed) catch unreachable;
    slot.piece_sent += sent.consumed;
    slot.response.body_sent += sent.consumed;
    assert(slot.piece_sent <= slot.piece.len);
    if (slot.piece_sent == slot.piece.len) {
        slot.piece_written();
        _ = end_content(connection, slot);
    }
    return sent.written;
}

/// The octets of `slot`'s piece that may go out now: in a chunked body, the data of the chunk
/// whose head went out, and none before its head (RFC 9112 §7.1).
fn sendable_len(connection: *const Connection, slot: *const Slot) usize {
    const left = slot.piece.len - slot.piece_sent;
    const writer = &connection.session.h11.writer;
    if (writer.kind != .chunked) return left;
    return @intCast(@min(left, writer.remaining));
}

/// Copies as much of `content` as `output` holds, in cleartext.
fn copy_content(content: []const u8, output: []u8) tls_provider.provider.Sealed {
    const take = @min(content.len, output.len);
    @memcpy(output[0..take], content[0..take]);
    return .{ .consumed = take, .written = take };
}
